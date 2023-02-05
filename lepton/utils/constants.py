ELFMAGIC = b"\x7fELF"
MAGIC_SLICE = (0, 4)
E_MACHINE = (0x12, 0x14)


class ELF32HEADEROFFSETS:
    MAGIC_SLICE = (0, 4)
    EI_CLASS = (4, 5)
    EI_DATA = (5, 6)
    EI_VERSION = (6, 7)
    EI_OSABI = (7, 8)
    EI_ABIVERSION = (8, 9)
    EI_PAD = (9, 0x10)
    E_TYPE = (0x10, 0x12)
    E_MACHINE = (0x12, 0x14)
    E_VERSION = (0x14, 0x18)
    E_ENTRY = (0x18, 0x1C)
    E_PHOFF = (0x1C, 0x20)
    E_SHOFF = (0x20, 0x24)
    E_FLAGS = (0x24, 0x28)
    E_EHSIZE = (0x28, 0x2A)
    E_PHENTSIZE = (0x2A, 0x2C)
    E_PHNUM = (0x2C, 0x2E)
    E_SHENTSIZE = (0x2E, 0x30)
    E_SHNUM = (0x30, 0x32)
    E_SHSTRNDX = (0x32, 0x34)


class ELF64HEADEROFFSETS:
    MAGIC_SLICE = (0, 4)
    EI_CLASS = (4, 5)
    EI_DATA = (5, 6)
    EI_VERSION = (6, 7)
    EI_OSABI = (7, 8)
    EI_ABIVERSION = (8, 9)
    EI_PAD = (9, 0x10)
    E_TYPE = (0x10, 0x12)
    E_MACHINE = (0x12, 0x14)
    E_VERSION = (0x14, 0x18)
    E_ENTRY = (0x18, 0x20)
    E_PHOFF = (0x20, 0x28)
    E_SHOFF = (0x28, 0x30)
    E_FLAGS = (0x30, 0x34)
    E_EHSIZE = (0x34, 0x36)
    E_PHENTSIZE = (0x36, 0x38)
    E_PHNUM = (0x38, 0x3A)
    E_SHENTSIZE = (0x3A, 0x3C)
    E_SHNUM = (0x3C, 0x3E)
    E_SHSTRNDX = (0x3E, 0x40)


class ELF32PROGRAMHEADEROFFSETS:
    P_TYPE = (0, 4)
    P_OFFSET = (4, 8)
    P_VADDR = (8, 12)
    P_PADDR = (12, 16)
    P_FILESZ = (16, 20)
    P_MEMSZ = (20, 24)
    P_FLAGS = (24, 28)
    P_ALIGN = (28, 32)


class ELF64PROGRAMHEADEROFFSETS:
    P_TYPE = (0, 4)
    P_FLAGS = (4, 8)
    P_OFFSET = (8, 16)
    P_VADDR = (16, 24)
    P_PADDR = (24, 32)
    P_FILESZ = (32, 40)
    P_MEMSZ = (40, 48)
    P_ALIGN = (48, 56)


class ELF32SECTIONHEADEROFFSETS:
    SH_NAME = (0, 4)
    SH_TYPE = (4, 8)
    SH_FLAGS = (8, 12)
    SH_ADDR = (12, 16)
    SH_OFFSET = (16, 20)
    SH_SIZE = (20, 24)
    SH_LINK = (24, 28)
    SH_INFO = (28, 32)
    SH_ADDRALIGN = (32, 36)
    SH_ENTSIZE = (36, 40)


class ELF64SECTIONHEADEROFFSETS:
    SH_NAME = (0, 4)
    SH_TYPE = (4, 8)
    SH_FLAGS = (8, 16)
    SH_ADDR = (16, 24)
    SH_OFFSET = (24, 32)
    SH_SIZE = (32, 40)
    SH_LINK = (40, 44)
    SH_INFO = (44, 48)
    SH_ADDRALIGN = (48, 56)
    SH_ENTSIZE = (56, 64)
