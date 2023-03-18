import os
import logging
from copy import deepcopy
from struct import pack, unpack

import lepton.utils.constants as constants
import lepton.utils.exceptions as exceptions
import lepton.utils.structures as structures

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


class ELFProgramHeaderTable:
    def __init__(self, data, elfheader, little_endian):
        """
        :param data: Input file contents
        :type data: <class 'bytes'>
        :param elfheader: Lepton-constructed ELF header contents
        :type elfheader: dict
        :param little_endian: Flag to indicate whether the ELF file is little endian
        :type little_endian: bool
        """
        self.endian = "<" if little_endian else ">"
        self.entries = self.build_program_header_table(data, elfheader)

    def _update_elf32_values(self, data, pheader_struct, phdr_num):
        """
        Update ELF32 program header table entry fields with values.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param pheader_struct: ELF32 program header table entry definition.
        :type pheader_struct: dict
        :param phdr_num: Program header table entry number. 0-indexed.
        :type phdr_num: int
        :return: Constructed ELF32 program header table entry
        :rtype: dict
        """
        # Calculate offset of p_hdr
        # p_hdr_offset = e_phoff
        e_phoff = unpack(f"{self.endian}I", data[constants.ELF32HEADEROFFSETS.E_PHOFF[0]:
                                                 constants.ELF32HEADEROFFSETS.E_PHOFF[1]])[0]
        e_phentsize = unpack(f"{self.endian}H", data[constants.ELF32HEADEROFFSETS.E_PHENTSIZE[0]:
                                                     constants.ELF32HEADEROFFSETS.E_PHENTSIZE[1]])[0]
        phdr = deepcopy(pheader_struct)
        phdr_entry_offset = e_phoff + e_phentsize * phdr_num

        # The program header fields must be accurate in the binary since these are needed
        # by the ELF loader.
        phdr["p_type"] = pack(f"{self.endian}I",
                              unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_TYPE[0]:
                                                             phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_TYPE[1]])[0])
        phdr["p_offset"] = pack(f"{self.endian}I",
                                unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_OFFSET[0]:
                                                               phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_OFFSET[1]])[0])
        phdr["p_vaddr"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_VADDR[0]:
                                                              phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_VADDR[1]])[0])
        phdr["p_paddr"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_PADDR[0]:
                                                              phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_PADDR[1]])[0])
        phdr["p_filesz"] = pack(f"{self.endian}I",
                                unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_FILESZ[0]:
                                                               phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_FILESZ[1]])[0])
        phdr["p_memsz"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_MEMSZ[0]:
                                                              phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_MEMSZ[1]])[0])
        phdr["p_flags"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_FLAGS[0]:
                                                              phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_FLAGS[1]])[0])
        phdr["p_align"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_ALIGN[0]:
                                                              phdr_entry_offset + constants.ELF32PROGRAMHEADEROFFSETS.P_ALIGN[1]])[0])

        return phdr

    def _update_elf64_values(self, data, pheader_struct, phdr_num):
        """
        Update ELF64 program header table entry fields with values.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param pheader_struct: ELF64 program header table entry definition.
        :type pheader_struct: dict
        :param phdr_num: Program header table entry number. 0-indexed.
        :type phdr_num: int
        :return: Constructed ELF64 program header table entry
        :rtype: dict
        """
        # Calculate offset of p_hdr
        e_phoff = unpack(f"{self.endian}Q", data[constants.ELF64HEADEROFFSETS.E_PHOFF[0]:
                                                 constants.ELF64HEADEROFFSETS.E_PHOFF[1]])[0]
        e_phentsize = unpack(f"{self.endian}H", data[constants.ELF64HEADEROFFSETS.E_PHENTSIZE[0]:
                                                     constants.ELF64HEADEROFFSETS.E_PHENTSIZE[1]])[0]
        # p_hdr_i_offset = e_phoff + e_phentsize * phdr_num
        phdr_entry_offset = e_phoff + e_phentsize * phdr_num

        phdr = deepcopy(pheader_struct)

        # The program header fields must be accurate in the binary since these are needed
        # by the ELF loader.
        phdr["p_type"] = pack(f"{self.endian}I",
                              unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_TYPE[0]:
                                                             phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_TYPE[1]])[0])
        phdr["p_offset"] = pack(f"{self.endian}Q",
                                unpack(f"{self.endian}Q", data[phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_OFFSET[0]:
                                                               phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_OFFSET[1]])[0])
        phdr["p_vaddr"] = pack(f"{self.endian}Q",
                               unpack(f"{self.endian}Q", data[phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_VADDR[0]:
                                                              phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_VADDR[1]])[0])
        phdr["p_paddr"] = pack(f"{self.endian}Q",
                               unpack(f"{self.endian}Q", data[phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_PADDR[0]:
                                                              phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_PADDR[1]])[0])
        phdr["p_filesz"] = pack(f"{self.endian}Q",
                                unpack(f"{self.endian}Q", data[phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_FILESZ[0]:
                                                               phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_FILESZ[1]])[0])
        phdr["p_memsz"] = pack(f"{self.endian}Q",
                               unpack(f"{self.endian}Q", data[phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_MEMSZ[0]:
                                                              phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_MEMSZ[1]])[0])
        phdr["p_flags"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_FLAGS[0]:
                                                              phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_FLAGS[1]])[0])
        phdr["p_align"] = pack(f"{self.endian}Q",
                               unpack(f"{self.endian}Q", data[phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_ALIGN[0]:
                                                              phdr_entry_offset + constants.ELF64PROGRAMHEADEROFFSETS.P_ALIGN[1]])[0])

        return phdr

    def _build_phdr(self, data, pheader_struct, phdr_num):
        """
        Router function. Calls relevant functions to build program header table
        for an ELF32/ELF64 file.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param pheader_struct: ELF32/64 program header table entry definition.
        :type pheader_struct: dict
        :param phdr_num: Program header table entry number. 0-indexed.
        :type phdr_num: int
        :return: Constructed ELF program header table
        :rtype: list of dict
        """
        if pheader_struct == structures.ELF32PROGRAMHEADER:
            return self._update_elf32_values(data, pheader_struct, phdr_num)
        elif pheader_struct == structures.ELF64PROGRAMHEADER:
            return self._update_elf64_values(data, pheader_struct, phdr_num)
        else:
            raise exceptions.ELFProgramHeaderTableError("Invalid Program"
                                                        "Header Structure.")

    def build_program_header_table(self, data, elfheader):
        """
        Builds the program header table of the input ELF file.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param elfheader: Lepton-constructed ELF header contents
        :type elfheader: dict
        :return: Constructed ELF program header table
        :rtype: list of dict
        """
        phdr_table = []
        phnum = unpack(f"{self.endian}H", elfheader["e_phnum"])[0]
        ei_class = elfheader["e_ident"][4]

        for phdr_num in range(phnum):
            if ei_class == 1:
                phdr = self._build_phdr(data, structures.ELF32PROGRAMHEADER,
                                        phdr_num)
            else:
                phdr = self._build_phdr(data, structures.ELF64PROGRAMHEADER,
                                        phdr_num)

            phdr_table.append(phdr)

        return phdr_table

    def to_bytes(self):
        """
        Returns ELF program header contents in the form of a sequence of bytes
        :return: ELF program header contents
        :rtype: <class 'bytes'>
        """
        phdr_table_bytes = bytes()
        if len(self.entries[0]["p_vaddr"]) == 8:
            # ELF64
            for phdr in self.entries:
                header_bytes = phdr["p_type"] + phdr["p_flags"] + \
                               phdr["p_offset"] + phdr["p_vaddr"] + \
                               phdr["p_paddr"] + phdr["p_filesz"] + \
                               phdr["p_memsz"] + phdr["p_align"]
                phdr_table_bytes += header_bytes
        else:
            for phdr in self.entries:
                header_bytes = phdr["p_type"] + phdr["p_offset"] + \
                               phdr["p_vaddr"] + phdr["p_paddr"] + \
                               phdr["p_filesz"] + phdr["p_memsz"] + \
                               phdr["p_flags"] + phdr["p_align"]
                phdr_table_bytes += header_bytes
        return phdr_table_bytes
