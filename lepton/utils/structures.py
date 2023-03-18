ELF64HEADER = {
    "e_ident": bytearray(16),
    "e_type": bytearray(2),
    "e_machine": bytearray(2),
    "e_version": bytearray(4),
    "e_entry": bytearray(8),
    "e_phoff": bytearray(8),
    "e_shoff": bytearray(8),
    "e_flags": bytearray(4),
    "e_ehsize": bytearray(2),
    "e_phentsize": bytearray(2),
    "e_phnum": bytearray(2),
    "e_shentsize": bytearray(2),
    "e_shnum": bytearray(2),
    "e_shstrndx": bytearray(2)
}

ELF64PROGRAMHEADER = {
    "p_type": bytearray(4),
    "p_offset": bytearray(4),
    "p_vaddr": bytearray(8),
    "p_paddr": bytearray(8),
    "p_filesz": bytearray(8),
    "p_memsz": bytearray(8),
    "p_flags": bytearray(8),
    "p_align": bytearray(8)
}

ELF32HEADER = {
    "e_ident": bytearray(16),
    "e_type": bytearray(2),
    "e_machine": bytearray(2),
    "e_version": bytearray(4),
    "e_entry": bytearray(4),
    "e_phoff": bytearray(4),
    "e_shoff": bytearray(4),
    "e_flags": bytearray(4),
    "e_ehsize": bytearray(2),
    "e_phentsize": bytearray(2),
    "e_phnum": bytearray(2),
    "e_shentsize": bytearray(2),
    "e_shnum": bytearray(2),
    "e_shstrndx": bytearray(2)
}

ELF32PROGRAMHEADER = {
    "p_type": bytearray(4),
    "p_offset": bytearray(4),
    "p_vaddr": bytearray(4),
    "p_paddr": bytearray(4),
    "p_filesz": bytearray(4),
    "p_memsz": bytearray(4),
    "p_flags": bytearray(4),
    "p_align": bytearray(4)
}

ELF32SECTIONHEADER = {
    "sh_name": bytearray(4),
    "sh_type": bytearray(4),
    "sh_flags": bytearray(4),
    "sh_addr": bytearray(4),
    "sh_offset": bytearray(4),
    "sh_size": bytearray(4),
    "sh_link": bytearray(4),
    "sh_info": bytearray(4),
    "sh_addralign": bytearray(4),
    "sh_entsize": bytearray(4)
}

ELF64SECTIONHEADER = {
    "sh_name": bytearray(4),
    "sh_type": bytearray(4),
    "sh_flags": bytearray(8),
    "sh_addr": bytearray(8),
    "sh_offset": bytearray(8),
    "sh_size": bytearray(8),
    "sh_link": bytearray(4),
    "sh_info": bytearray(4),
    "sh_addralign": bytearray(8),
    "sh_entsize": bytearray(8)
}
