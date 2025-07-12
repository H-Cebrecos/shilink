use elf::endian::AnyEndian;
use elf::note::Note;
use elf::section::SectionHeader;
use elf::ElfBytes;

pub fn hi(file_path: &str) {
    let path = std::path::PathBuf::from(file_path);
    let file_data = std::fs::read(path).expect("Could not read file.");
    let slice = file_data.as_slice();
    let raw = slice;
    let file = ElfBytes::<AnyEndian>::minimal_parse(slice).expect("Error parsing header.");

    println!();
    println!();
    read_elf(&file, raw);
    println!();
    println!();
    // Get the ELF file's build-id
    let abi_shdr: SectionHeader = file
        .section_header_by_name(".note.gnu.build-id")
        .expect("section table should be parseable")
        .expect("file should have a .note.ABI-tag section");

    let notes: Vec<Note> = file
        .section_data_as_notes(&abi_shdr)
        .expect("Should be able to get note section data")
        .collect();

    // Find lazy-parsing types for the common ELF sections (we want .dynsym, .dynstr, .hash)
    let common = file.find_common_data().expect("shdrs should parse");
    let (dynsyms, strtab) = (common.dynsyms.unwrap(), common.dynsyms_strs.unwrap());
    let hash_table = common.sysv_hash.unwrap();

    // Use the hash table to find a given symbol in it.
    let name = b"memset";
    let (sym_idx, sym) = hash_table
        .find(name, &dynsyms, &strtab)
        .expect("hash table and symbols should parse")
        .unwrap();

    // Verify that we got the same symbol from the hash table we expected
    assert_eq!(sym_idx, 2);
    assert_eq!(strtab.get(sym.st_name as usize).unwrap(), "memset");
    assert_eq!(sym, dynsyms.get(sym_idx).unwrap());
}

pub fn read_elf(file: &ElfBytes<'_, AnyEndian>, raw: &[u8]) {
    let header = file.ehdr;

    println!("\nELF Header:");
    print!("  Magic:   ");
    for byte in raw.iter().take(16) {
        print!("{:02x} ", byte);
    }
    println!(); // Add a newline

    println!("  {:<34} {:?}", "Class:", header.class);
    print!("  {:<34} ", "Data:");
    match header.endianness {
        AnyEndian::Big => println!("2' complement, big endian"),
        AnyEndian::Little => println!("2's comlement, little endian"),
    }

    print!("  {:<34} {}", "Version:", header.version);
    if header.version == 1 {
        println!(" (current)");
    } else {
        println!(" (unknown)");
    }
    print!("  {:<34} ", "OS/ABI:");
    match header.osabi {
        0 => println!("No extensions (System V) or unspecified"),
        1 => println!("Hewlett-Packard HP-UX"),
        2 => println!("NetBSD"),
        3 => println!("Linux"),
        6 => println!("Sun Solaris"),
        7 => println!("AIX"),
        8 => println!("IRIX"),
        9 => println!("FreeBSD"),
        10 => println!("Compaq TRU64 UNIX"),
        11 => println!("Novell Modesto"),
        12 => println!("OpenBSD"),
        13 => println!("Open VMS"),
        14 => println!("Hewlett-Packard Non-Stop Kernel"),
        64..=255 => println!("Architecture-specific value range"),
        _ => println!("Unknown"),
    }

    println!("  {:<34} {}", "ABI Version:", header.abiversion);
    print!("  {:<34} ", "Type:");
    match header.e_type {
        0 => println!("No file type"),
        1 => println!("Relocatable"),
        2 => println!("Executable"),
        3 => println!("Shared object"),
        4 => println!("Core"),
        _ => panic!("Unrecognized file type."),
    }

    print!("  {:<34} ", "Machine:");
    match header.e_machine {
        243 => println!("RISC-V"),
        _ => println!("Unsupported Machine {}.", header.e_machine),
    }

    //TODO: actually use the real value instead of the same value.
    println!(
        "  {:<34} 0x{:x} (object code version) must be equal to ELF version",
        "Version:", header.version
    );

    if header.e_entry == 0 {
        println!("  {:<34} No entry point specified.", "Entry point address:");
    } else {
        println!("  {:<34} 0x{:08x}", "Entry point address:", header.e_entry);
    }

    println!(
        "  {:<34} {} (bytes into file)",
        "Start of program headers:", header.e_phoff
    );
    println!(
        "  {:<34} {} (bytes into file)",
        "Start of section headers:", header.e_shoff
    );

    println!("  {:<34} 0x{:x}", "Flags:", header.e_flags);
    let eflags = header.e_flags;
    let rvc = eflags & 0x0001;
    println!("      {:<30} {}", "RVC:", rvc);

    // Bits 1-2: Float ABI (mask = 0x0006) --> shift right by 1 bit
    let float_abi = (eflags & 0x0006) >> 1;
    match float_abi {
        0 => println!("      {:<30} {}", "Float ABI:", "Soft"),
        1 => println!("      {:<30} {}", "Float ABI:", "Single"),
        2 => println!("      {:<30} {}", "Float ABI:", "Double"),
        3 => println!("      {:<30} {}", "Float ABI:", "Quad"),
        _ => println!("      {:<30} {}", "Float ABI:", "Unknown Float ABI"),
    }

    // Bit 3: RVE (mask = 0x0008)
    let rve = (eflags & 0x0008) >> 3;
    println!("      {:<30} {}", "RVE:", rve);

    // Bit 4: TSO (mask = 0x0010)
    let tso = (eflags & 0x0010) >> 4;
    println!("      {:<30} {}", "TSO:", tso);

    // Bits 5-23: Reserved
    let reserved = (eflags & 0x00FFE0) >> 5;
    if reserved != 0 {
        println!(
            "      {:<30} {}",
            "Error, unsuported use of reserved bits:", reserved
        );
    }

    // Bits 24-31: Non-standard extensions (mask = 0xFF000000)
    let non_standard = (eflags & 0xFF000000) >> 24;
    println!(
        "      {:<30} {:#x}",
        "Non-standard extensions:", non_standard
    );

    println!(
        "  {:<34} {} (bytes)",
        "Size of this header:", header.e_ehsize
    );
    println!(
        "  {:<34} {} (bytes)",
        "Size of program headers:", header.e_phentsize
    );
    println!(
        "  {:<34} {} (bytes)",
        "Size of section headers:", header.e_shentsize
    );

    println!("  {:<34} {}", "Number of program headers:", header.e_phnum);
    println!("  {:<34} {}", "Number of section headers:", header.e_shnum);

    println!(
        "  {:<34} {}",
        "Section header string table index:", header.e_shstrndx
    );

    println!();

    /* /////////////////////////////////////////////////////////////////// */

    println!("Section Headers:");

    let sections = file
        .section_headers()
        .expect("section headers should not be empty");
    let shstrtab = sections.get(header.e_shstrndx as usize).unwrap();
    let (section_names, _) = file.section_data(&shstrtab).unwrap();

    //TODO: do the format string for this one so it works in 32 or 64 bit mode.
    println!("  [Nr] Name              Type             Addr     Off    Size   ES Flg Lk Inf Al");

    //the assembler/compiler optimizes the section header string table and .text is part of .rela.text !!
    for (i, section) in sections.iter().enumerate() {
        let slice = section_names[section.sh_name as usize..]
            .split(|&byte| byte == 0)
            .next()
            .unwrap();
        let stype = match section.sh_type {
            0 => "NULL",
            1 => "PROGBITS",
            2 => "SYMTAB",
            3 => "STRTAB",
            4 => "RELA",
            5 => "HASH",
            6 => "DYNAMIC",
            7 => "NOTE",
            8 => "NOBITS",
            9 => "REL",
            10 => "SHLIB",
            11 => "DYNSYM",
            0x70000003 => "RISCV_ATTRIBUTES",
            _ => todo!(),
        };
        let mut sflags: String = "".to_owned();
        if section.sh_flags & 0b1 != 0 {
            sflags = sflags + "W"; //writable data.
        }
        if section.sh_flags & 0b10 != 0 {
            sflags = sflags + "A"; //allocated in memory image.
        }
        if section.sh_flags & 0b100 != 0 {
            sflags = sflags + "X"; //executable instructions.
        }
        if section.sh_flags & 0b1000 != 0 {
            //unused bit.
        }
        if section.sh_flags & 0b10000 != 0 {
            sflags = sflags + "M"; //might be merged.
        }
        if section.sh_flags & 0b100000 != 0 {
            sflags = sflags + "S"; //contains null terminated strings.
        }
        if section.sh_flags & 0b1000000 != 0 {
            sflags = sflags + "I"; //sh_info contains SHT index.
        }
        if section.sh_flags & 0b10000000 != 0 {
            sflags = sflags + "L"; //preserve order after combining.
        }
        if section.sh_flags & 0b100000000 != 0 {
            sflags = sflags + "O"; //non-standard os handling required.
        }

        //... fill from here https://gist.github.com/x0nu11byt3/bcb35c3de461e5fb66173071a2379779

        match header.class {
            elf::file::Class::ELF32 => {
                print!(
                    "  [{:2}] {:<17} {:<17}{:08x} {:06x} {:06x} {:02x} {:2} {:3} {:3} {:2}",
                    i,
                    std::str::from_utf8(slice).unwrap(),
                    stype,
                    section.sh_addr,
                    section.sh_offset,
                    section.sh_size,
                    section.sh_entsize,
                    sflags,
                    section.sh_link,
                    section.sh_info,
                    section.sh_addralign
                );
                //TODO: think how to do this cleanly for link field to
                //link field:
                /*
                if dynamic it is the string table used by the entries in the table.
                uf hask it is the symbolt table to wich the hash table applies
                if rel or rela it is the symbol table refereced by relocations
                if symtab or dymsym it is the string table used by entries in the section.
                 */
                //todo: instead of just printing the index print the name of the section.
                if section.sh_type == 4 || section.sh_type == 9 {
                    print!(" Inf: index of section to relocate");
                } else if section.sh_type == 2 || section.sh_type == 11 {
                    print!(" Inf: Index of first non-local symbol")
                } else if section.sh_info != 0 {
                    print!(" Inf: Usupported information field")
                }
                println!()
            }
            elf::file::Class::ELF64 => {
                println!(
                    "  [{:2}] {:<17} {:<17}{:#016x} {:00x}   Size   ES Flg Lk Inf Al",
                    i,
                    std::str::from_utf8(slice).unwrap(),
                    stype,
                    section.sh_addr,
                    section.sh_offset
                );
            }
        }

        match section.sh_type {
            4 | 9 => {} //rel or rela
            _ => {}
        }
    }
    /* /////////////////////////////////////////////////////////////////// */

    // section groups
    /* /////////////////////////////////////////////////////////////////// */

    // program headers
    /* /////////////////////////////////////////////////////////////////// */

    // dynamic sections
    /* /////////////////////////////////////////////////////////////////// */

    // relocation sections.
}
