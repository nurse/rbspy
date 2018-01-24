pub use self::os_impl::*;
use libc::pid_t;

/*
 * Operating-system specific code for getting
 * a) the address of the current thread, and
 * b) the address of the Ruby version of a PID
 *
 * from a running Ruby process. Involves a lot of reading memory maps and symbols.
 */

#[derive(Fail, Debug)]
pub enum AddressFinderError {
    #[fail(display = "No process with PID: {}", _0)] NoSuchProcess(pid_t),
    #[fail(display = "Permission denied when reading from process {}. Try again with sudo?", _0)]
    PermissionDenied(pid_t),
    #[fail(display = "Error reading /proc/{}/maps", _0)] ProcMapsError(pid_t),
}

#[cfg(target_os = "macos")]
mod os_impl {
    use failure::Error;
    use goblin::mach;
    use proc_maps::*;
    use libc::pid_t;
    use regex::Regex;
    use std::fs::File;
    use std::io::Read;
    use std::thread;
    use std::time;
    use std::process::{Command, Stdio};
    use read_process_memory::*;

    // struct to hold everything we know about the program
    pub struct ProgramInfo {
        pub pid: pid_t,
        pub ruby_path: String,
        pub ruby_offset: usize,
    }

    pub fn current_thread_address(
        pid: pid_t,
        version: &str,
        is_maybe_thread: Box<Fn(usize, &ProcessHandle, &MapRange, &Vec<MapRange>) -> bool>,
    ) -> Result<usize, Error> {
        if version >= "2.5.0" {
            // TODO: make this more robust
            let addr = get_symbol_addr2(pid, "_ruby_current_execution_context_ptr");
            debug!("current_thread_address:_ruby_current_execution_context_ptr: {:?}", addr);
            addr
        } else {
            let addr = get_symbol_addr2(pid, "_ruby_current_thread");
            debug!("current_thread_address:_ruby_current_thread: {:?}", addr);
            addr
        }
    }

    fn parse_vmmap(pid: pid_t) -> ProgramInfo {
        let vmmap_command = Command::new("vmmap")
            .arg(format!("{}", pid))
            .stdout(Stdio::piped())
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .expect("failed to execute process");
        if !vmmap_command.status.success() {
            panic!(
                "failed to execute process: {}",
                String::from_utf8(vmmap_command.stderr).unwrap()
            )
        }

        let output = String::from_utf8(vmmap_command.stdout).unwrap();

        let path_line = output.lines().find(|line| line.starts_with("Path:")).unwrap();
        // get ruby binary's path
        let ruby_path = path_line.split_whitespace().last().unwrap();

        let lines: Vec<&str> = output
            .split("\n")
            .filter(|line| line.contains("bin/ruby") && line.contains("__TEXT"))
            .collect();
        let line = lines
            .first()
            .expect("No `__TEXT` line found for `bin/ruby` in vmmap output");

        let re = Regex::new(r"([0-9a-f]+)").unwrap();
        let cap = re.captures(&line).unwrap();
        let address_str = &cap[1];
        // get address where ruby binary is mapped
        let addr = usize::from_str_radix(address_str, 16).unwrap();
        debug!("parse_vmmap: {:x}", addr);

        ProgramInfo{
            pid: pid,
            ruby_path: ruby_path.to_string(),
            ruby_offset: addr,
        }
    }

    pub fn get_ruby_version_address(pid: pid_t) -> Result<usize, Error> {
        let symbol_name = "_ruby_version";
        get_symbol_addr(pid, symbol_name)
    }

    fn get_symbol_addr(pid: pid_t, symbol_name: &str) -> Result<usize, Error> {
        let proginfo = parse_vmmap(pid);
        let mut fd = File::open(&proginfo.ruby_path)?;
        let mut buffer = Vec::new();
        fd.read_to_end(&mut buffer)?;
        match mach::MachO::parse(&buffer, 0) {
            Ok(macho) => {
                for sym in macho.exports()? {
                    if sym.name == symbol_name {
                        debug!("sym: {} {:x}+{:x}", sym.name, sym.offset, proginfo.ruby_offset);
                        let addr = sym.offset as usize;
                        return Ok(proginfo.ruby_offset + addr);
                    }
                }
                Err(format_err!("{} is not found", symbol_name))
            },
            Err(err) => {
                Err(format_err!("{}", err))
            }
        }
    }

    fn get_symbol_addr2(pid: pid_t, symbol_name: &str) -> Result<usize, Error> {
        let proginfo = parse_vmmap(pid);
        let mut fd = File::open(&proginfo.ruby_path)?;
        let mut buffer = Vec::new();
        fd.read_to_end(&mut buffer)?;
        match mach::MachO::parse(&buffer, 0) {
            Ok(macho) => {
                let (s, n) = macho.symbols()
                    .filter(|x| x.is_ok() )
                    .map(|x| x.unwrap() )
                    .find(|&(sym,_)| sym == symbol_name )
                    .expect("No executable LOAD header found in ELF file. Please report this!");
                debug!("sym: {} {} {:x}+{:x} {}", s,n.n_strx, n.n_value, proginfo.ruby_offset, n.type_str());
                let base_address = 0x100000000;
                Ok(proginfo.ruby_offset + (n.n_value as usize) - base_address)
            },
            Err(err) => {
                Err(format_err!("{}", err))
            }
        }
    }
}

#[cfg(target_os = "linux")]
mod os_impl {
    use copy::*;
    use elf;
    use proc_maps::*;
    use failure::Error;
    use libc::pid_t;
    use std;
    use address_finder::AddressFinderError;
    use read_process_memory::*;

    pub fn current_thread_address(
        pid: pid_t,
        version: &str,
        is_maybe_thread: Box<Fn(usize, &ProcessHandle, &MapRange, &Vec<MapRange>) -> bool>,
    ) -> Result<usize, Error> {
        let proginfo = &get_program_info(pid)?;
        match current_thread_address_symbol_table(proginfo, version) {
            Some(addr) => Ok(addr),
            None => {
                debug!("Trying to find address location another way");
                Ok(current_thread_address_search_bss(
                    proginfo,
                    is_maybe_thread,
                )?)
            }
        }
    }

    pub fn get_ruby_version_address(pid: pid_t) -> Result<usize, Error> {
        let proginfo = &get_program_info(pid)?;
        let ruby_version_symbol = "ruby_version";
        let symbol_addr =
            get_symbol_addr(&proginfo.ruby_map, &proginfo.ruby_elf, ruby_version_symbol);
        match symbol_addr {
            Some(addr) => Ok(addr),
            _ => {
                get_symbol_addr(
                    // if we have a ruby map but `ruby_version` isn't in it, we expect there to be
                    // a libruby map. If that's not true, that's a bug.
                    (*proginfo.libruby_map)
                        .as_ref()
                        .expect("Missing libruby map. Please report this!"),
                    proginfo
                        .libruby_elf
                        .as_ref()
                        .expect("Missing libruby ELF. Please report this!"),
                    ruby_version_symbol,
                ).ok_or(format_err!("Couldn't find ruby version."))
            }
        }
    }

    fn elf_symbol_value(elf_file: &elf::File, symbol_name: &str) -> Option<usize> {
        // TODO: maybe move this to goblin so that it works on OS X & BSD, not just linux
        let sections = &elf_file.sections;
        for s in sections {
            for sym in elf_file
                .get_symbols(&s)
                .expect("Failed to get symbols from section")
            {
                if sym.name == symbol_name {
                    debug!("symbol: {}", sym);
                    return Some(sym.value as usize);
                }
            }
        }
        None
    }

    fn get_bss_section(elf_file: &elf::File) -> Option<elf::types::SectionHeader> {
        for s in &elf_file.sections {
            match s.shdr.name.as_ref() {
                ".bss" => {
                    return Some(s.shdr.clone());
                }
                _ => {}
            }
        }
        None
    }

    fn current_thread_address_search_bss(
        proginfo: &ProgramInfo,
        is_maybe_thread: Box<Fn(usize, &ProcessHandle, &MapRange, &Vec<MapRange>) -> bool>,
    ) -> Result<usize, Error> {
        // Used when there's no symbol table. Looks through the .bss and uses a search_bss (found in
        // `is_maybe_thread`) to find the address of the current thread.
        let map = (*proginfo.libruby_map).as_ref().expect(
            "No libruby map: symbols are stripped so we expected to have one. Please report this!",
        );
        let libruby_elf = proginfo.libruby_elf.as_ref().expect(
            "No libruby elf: symbols are stripped so we expected to have one. Please report this!",
        );
        let bss_section = get_bss_section(libruby_elf).expect(
            "No BSS section (every Ruby ELF file should have a BSS section?). Please report this!",
        );
        let load_header = elf_load_header(libruby_elf);
        debug!("bss_section header: {:?}", bss_section);
        let read_addr = map.range_start + bss_section.addr as usize - load_header.vaddr as usize;

        debug!("read_addr: {:x}", read_addr);
        let source = &proginfo.pid.try_into_process_handle().unwrap();
        let mut data = copy_address_raw(read_addr as usize, bss_section.size as usize, source)?;
        debug!("successfully read data");
        let slice: &[usize] = unsafe {
            std::slice::from_raw_parts(
                data.as_mut_ptr() as *mut usize,
                data.capacity() as usize / std::mem::size_of::<usize>() as usize,
            )
        };

        let i = slice
            .iter()
            .position({ |&x| is_maybe_thread(x, source, &proginfo.heap_map, &proginfo.all_maps) })
            .ok_or(format_err!(
                "Current thread address not found in process {}",
                &proginfo.pid
            ))?;
        Ok((i as usize) * (std::mem::size_of::<usize>() as usize) + read_addr)
    }

    fn current_thread_address_symbol_table(
        // Uses the symbol table to get the address of the current thread
        proginfo: &ProgramInfo,
        version: &str,
    ) -> Option<usize> {
        // TODO: comment this somewhere
        if version >= "2.5.0" {
            // TODO: make this more robust
            get_symbol_addr(
                &proginfo.ruby_map,
                &proginfo.ruby_elf,
                "ruby_current_execution_context_ptr",
            )
        } else {
            get_symbol_addr(
                &proginfo.ruby_map,
                &proginfo.ruby_elf,
                "ruby_current_thread",
            )
        }
    }

    fn get_symbol_addr(map: &MapRange, elf_file: &elf::File, symbol_name: &str) -> Option<usize> {
        elf_symbol_value(elf_file, symbol_name).map(|addr| {
            let load_header = elf_load_header(elf_file);
            debug!("load header: {}", load_header);
            map.range_start + addr - load_header.vaddr as usize
        })
    }

    fn elf_load_header(elf_file: &elf::File) -> elf::types::ProgramHeader {
        elf_file
            .phdrs
            .iter()
            .find(|ref ph| {
                ph.progtype == elf::types::PT_LOAD && (ph.flags.0 & elf::types::PF_X.0) != 0
            })
            .expect("No executable LOAD header found in ELF file. Please report this!")
            .clone()
    }

    // struct to hold everything we know about the program
    pub struct ProgramInfo {
        pub pid: pid_t,
        pub all_maps: Vec<MapRange>,
        pub ruby_map: Box<MapRange>,
        pub heap_map: Box<MapRange>,
        pub libruby_map: Box<Option<MapRange>>,
        pub ruby_elf: elf::File,
        pub libruby_elf: Option<elf::File>,
    }

    pub fn get_program_info(pid: pid_t) -> Result<ProgramInfo, Error> {
        let all_maps = get_proc_maps(pid).map_err(|x| match x.kind() {
            std::io::ErrorKind::NotFound => AddressFinderError::NoSuchProcess(pid),
            std::io::ErrorKind::PermissionDenied => AddressFinderError::PermissionDenied(pid),
            _ => AddressFinderError::ProcMapsError(pid),
        })?;
        let ruby_map = Box::new(get_map(&all_maps, "bin/ruby", "r-xp")
            .ok_or(format_err!("Ruby map not found for PID: {}", pid))?);
        let heap_map = Box::new(get_map(&all_maps, "[heap]", "rw-p")
            .ok_or(format_err!("Heap map not found for PID: {}", pid))?);
        let ruby_path = &ruby_map
            .pathname
            .clone()
            .expect("ruby map's pathname shouldn't be None");
        let ruby_elf = elf::File::open_path(ruby_path)
            .map_err(|_| format_err!("Couldn't open ELF file: {}", ruby_path))?;
        let libruby_map = Box::new(get_map(&all_maps, "libruby", "r-xp"));
        let libruby_elf = match *libruby_map {
            Some(ref map) => {
                let path = &map.pathname
                    .clone()
                    .expect("libruby map's pathname shouldn't be None");
                Some(elf::File::open_path(path)
                    .map_err(|_| format_err!("Couldn't open ELF file: {}", path))?)
            }
            _ => None,
        };
        Ok(ProgramInfo {
            pid: pid,
            all_maps: all_maps,
            ruby_map: ruby_map,
            heap_map: heap_map,
            libruby_map: libruby_map,
            ruby_elf: ruby_elf,
            libruby_elf: libruby_elf,
        })
    }

    fn get_map(maps: &Vec<MapRange>, contains: &str, flags: &str) -> Option<MapRange> {
        maps.iter()
            .find(|ref m| {
                if let Some(ref pathname) = m.pathname {
                    pathname.contains(contains) && &m.flags == flags
                } else {
                    false
                }
            })
            .map(|x| x.clone())
    }
}
