import os
import logging
from copy import deepcopy
from struct import unpack, pack, error

import lepton.utils.constants as constants
import lepton.utils.exceptions as exceptions
import lepton.utils.structures as structures

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


class ELFSectionHeaderTable:
    def __init__(self, data, elfheader, little_endian, new_header):
        """
        :param data: Input file contents
        :type data: <class 'bytes'>
        :param elfheader: Lepton-constructed ELF header contents
        :type elfheader: dict
        :param little_endian: Flag to indicate whether the ELF file is little endian
        :type little_endian: bool
        :param new_header: Flag to indicate reconstruction of ELF section header
        :type new_header: bool
        """
        self.endian = "<" if little_endian else ">"
        self.entries = self.build_section_header_table(data, elfheader, new_header)

    def _update_elf32_values(self, data, sheader_struct, sh_off, shdr_num, e_shentsize):
        """
        Update ELF32 section header table entry fields with values.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param sheader_struct: ELF32 section header table entry definition.
        :type sheader_struct: dict
        :param sh_off: Section header table offset
        :type sh_off: int
        :param shdr_num: Section header table entry number. 0-indexed.
        :type shdr_num: int
        :param e_shentsize: Size of each section header table entry
        :type e_shentsize: int
        :return: Constructed ELF32 section header table entry
        :rtype: dict
        """
        shdr_entry_offset = sh_off + e_shentsize * shdr_num

        shdr = deepcopy(sheader_struct)

        # The section header fields may be inaccurate.
        shdr["sh_name"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_NAME[0]:
                                                              shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_NAME[1]])[0])
        shdr["sh_type"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[0]:
                                                              shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[1]])[0])
        shdr["sh_flags"] = pack(f"{self.endian}I",
                                unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_FLAGS[0]:
                                                               shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_FLAGS[1]])[0])
        shdr["sh_addr"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_ADDR[0]:
                                                              shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_ADDR[1]])[0])
        shdr["sh_offset"] = pack(f"{self.endian}I",
                                 unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_OFFSET[0]:
                                                                shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_OFFSET[1]])[0])
        shdr["sh_size"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_SIZE[0]:
                                                              shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_SIZE[1]])[0])
        shdr["sh_link"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_LINK[0]:
                                                              shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_LINK[1]])[0])
        shdr["sh_info"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_INFO[0]:
                                                              shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_INFO[1]])[0])
        shdr["sh_addralign"] = pack(f"{self.endian}I",
                                    unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_ADDRALIGN[0]:
                                                                   shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_ADDRALIGN[1]])[0])
        shdr["sh_entsize"] = pack(f"{self.endian}I",
                                  unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_ENTSIZE[0]:
                                                                 shdr_entry_offset + constants.ELF32SECTIONHEADEROFFSETS.SH_ENTSIZE[1]])[0])

        return shdr

    def _update_elf64_values(self, data, sheader_struct, sh_off, shdr_num, e_shentsize):
        """
        Update ELF64 section header table entry fields with values.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param sheader_struct: ELF64 section header table entry definition.
        :type sheader_struct: dict
        :param sh_off: Section header table offset
        :type sh_off: int
        :param shdr_num: Section header table entry number. 0-indexed.
        :type shdr_num: int
        :param e_shentsize: Size of section header table entry
        :type e_shentsize: int
        :return: Constructed ELF32 section header table entry
        :rtype: dict
        """
        # s_hdr_i_offset = e_shoff + e_shentsize * shdr_num
        shdr_entry_offset = sh_off + e_shentsize * shdr_num

        shdr = deepcopy(sheader_struct)

        # The section header fields may be inaccurate.
        shdr["sh_name"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_NAME[0]:
                                                              shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_NAME[1]])[0])
        shdr["sh_type"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[0]:
                                                              shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[1]])[0])
        shdr["sh_flags"] = pack(f"{self.endian}Q",
                                unpack(f"{self.endian}Q", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_FLAGS[0]:
                                                               shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_FLAGS[1]])[0])
        shdr["sh_addr"] = pack(f"{self.endian}Q",
                               unpack(f"{self.endian}Q", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_ADDR[0]:
                                                              shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_ADDR[1]])[0])
        shdr["sh_offset"] = pack(f"{self.endian}Q",
                                 unpack(f"{self.endian}Q", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_OFFSET[0]:
                                                                shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_OFFSET[1]])[0])
        shdr["sh_size"] = pack(f"{self.endian}Q",
                               unpack(f"{self.endian}Q", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_SIZE[0]:
                                                              shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_SIZE[1]])[0])
        shdr["sh_link"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_LINK[0]:
                                                              shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_LINK[1]])[0])
        shdr["sh_info"] = pack(f"{self.endian}I",
                               unpack(f"{self.endian}I", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_INFO[0]:
                                                              shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_INFO[1]])[0])
        shdr["sh_addralign"] = pack(f"{self.endian}Q",
                                    unpack(f"{self.endian}Q", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_ADDRALIGN[0]:
                                                                   shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_ADDRALIGN[1]])[0])
        shdr["sh_entsize"] = pack(f"{self.endian}Q",
                                  unpack(f"{self.endian}Q", data[shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_ENTSIZE[0]:
                                                                 shdr_entry_offset + constants.ELF64SECTIONHEADEROFFSETS.SH_ENTSIZE[1]])[0])

        return shdr

    def _build_shdr(self, data, sheader_struct, sh_off, shdr_num, shentsize):
        """
        Router function. Calls relevant functions to build section header table
        for an ELF32/ELF64 file.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param sheader_struct: ELF32/64 section header table entry definition.
        :type sheader_struct: dict
        :param sh_off: Section header table offset
        :type sh_off: int
        :param shdr_num: Section header table entry number. 0-indexed.
        :type shdr_num: int
        :param shentsize: Size of each section header table entry.
        :type shentsize: int
        :return: Constructed ELF section header table
        :rtype: list of dict
        """
        if sheader_struct == structures.ELF32SECTIONHEADER:
            return self._update_elf32_values(data, sheader_struct, sh_off, shdr_num, shentsize)
        elif sheader_struct == structures.ELF64SECTIONHEADER:
            return self._update_elf64_values(data, sheader_struct, sh_off, shdr_num, shentsize)
        else:
            raise exceptions.ELFSectionHeaderTableError("Invalid Section"
                                                        "Header Structure.")

    def _verify_section_header_table(self, data, shoff_, shentsize, ei_class):
        """
        Using various heuristics, verify if a section header table exists at
        shoff_ offset.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param shoff_: Suspected section headers table offset
        :type shoff_: int
        :param shentsize: Size of each entry in the section header table
        :data shentsize: int
        :param ei_class: Leptop-constructed EI_CLASS field in ELF header
        :type ei_class: int
        """
        # Get a few entries from the section header table.
        # sh_flags field value must be as expected for sh_type == PROGBITS.
        # I'm checking multiple entries (instead of one) to make for a better
        # heuristic.
        match = 0
        check = 5
        current_entry = shoff_
        while check:
            current_entry = current_entry + shentsize
            if ei_class == 1:
                sh_type_start = current_entry + (constants.ELF32SECTIONHEADEROFFSETS.SH_NAME[1] -
                                                 constants.ELF32SECTIONHEADEROFFSETS.SH_NAME[0])
                sh_type_len = constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[1] -\
                              constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[0]

                current_entry_sh_type = unpack(f"{self.endian}I", data[sh_type_start: sh_type_start + sh_type_len])[0]
                if current_entry_sh_type != 0x1:
                    # Not sh_type == PROGBITS
                    check -= 1
                    continue
                sh_flags_start = sh_type_start + (constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[1] -
                                                  constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[0])
                sh_flags_len = constants.ELF32SECTIONHEADEROFFSETS.SH_FLAGS[1] -\
                               constants.ELF32SECTIONHEADEROFFSETS.SH_FLAGS[0]

                current_entry_sh_flags = unpack(f"{self.endian}I", data[sh_flags_start: sh_flags_start + sh_flags_len])[0]
            elif ei_class == 2:
                sh_type_start = current_entry + (constants.ELF64SECTIONHEADEROFFSETS.SH_NAME[1] -
                                                 constants.ELF64SECTIONHEADEROFFSETS.SH_NAME[0])
                sh_type_len = constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[1] - \
                              constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[0]
                current_entry_sh_type = unpack(f"{self.endian}I", data[sh_type_start: sh_type_start + sh_type_len])[0]
                if current_entry_sh_type != 0x1:
                    # Not sh_type == PROGBITS
                    check -= 1
                    continue
                sh_flags_start = sh_type_start + (constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[1] -
                                                  constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[0])
                sh_flags_len = constants.ELF64SECTIONHEADEROFFSETS.SH_FLAGS[1] - \
                               constants.ELF64SECTIONHEADEROFFSETS.SH_FLAGS[0]

                current_entry_sh_flags = unpack(f"{self.endian}Q", data[sh_flags_start: sh_flags_start + sh_flags_len])[0]
            else:
                raise exceptions.ELFSectionHeaderTableError("Invalid EI_CLASS")
            # When SHF_WRITE and/or SHF_ALLOC and/or SHF_EXECINSTR and/or SHF_MASKPROC
            # are set, they result in some set values: (>0 <=7) or (>=0xF0000000 <=0xF0000007)
            if 0x7 < current_entry_sh_flags < 0xf0000000 or current_entry_sh_flags > 0xf0000007:
                return False
            match += 1
            check -= 1

        return match > 0

    @staticmethod
    def _find_shnum(data, shoff, shentsize):
        """
        Find the number of section header table entries using heuristics.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param shoff: Section headers table offset determined previously
        :type shoff: int
        :param shentsize: Size of each entry in the section header table
        :data shentsize: int
        """
        null_bytes_section = shentsize * b"\x00"

        # One way I know to determine number of section header
        # table entries is if the section header table extends all
        # the way to end of file. In this case, the size of the section
        # header table must be divisible by the size of each section
        # header table entry.
        filesize = len(data)
        if (filesize - shoff) % shentsize == 0:
            return (filesize - shoff) // shentsize
        # If the section header table does not lie at the end of the
        # file, then it gets murky. With the below algorithm, the hope
        # is that there is null-bytes padding after the section header
        # table atleast of the size of one section header table entry.
        # This assumption does not come from the ELF specification.
        else:
            # In data, find the first occurrence of null_bytes_section
            # after shoff such that (next_null_bytes_section-shoff) %
            # shentsize == 0. Ensure there's no infinite loop.
            current_index = shoff
            while current_index < filesize:
                # Can't do a data.find(null_bytes_section) because
                # the index it finds may be inaccurate. I need to
                # ensure that the next occurrence of null_bytes_section
                # is not in the middle of a section header table entry.
                current_index += shentsize
                if data[current_index: current_index + shentsize] == null_bytes_section:
                    if (current_index - shoff) % shentsize == 0:
                        return (current_index - shoff) // shentsize

        return 0

    def find_section_header_table(self, data, shentsize, ei_class):
        """
        In stripped ELF files, section header information is removed from the
        ELF header making debugging difficult. This function attempts to find
        the ELF section header in the file contents. Of course, it may not
        always be correct.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param shentsize: Size of each entry in the section header table
        :data shentsize: int
        :param ei_class: Leptop-constructed EI_CLASS field in ELF header
        :type ei_class: int
        """
        shnum = 0
        shoff = 0

        # The initial entry in the section header table is full of null bytes.
        # This is not true in all cases. From the ELF specification:
        # "The initial entry is used in ELF extensions for e_phnum, e_shnum, and
        # e_shstrndx; in other cases, each field in the initial entry is set
        # to zero."
        null_bytes_section = shentsize * b"\x00"

        # Usually, the section header table exists at the end of the file.
        # Again, this may not always be true. Assuming it is true, start
        # search for null_bytes_section from end of file and process from
        # the first found index
        occurrences = []
        current_index = len(data)
        while current_index >= 0:
            current_index = data.rfind(null_bytes_section, 0, current_index)
            if current_index >= 0:
                occurrences.append(current_index)
                current_index -= 1

        for i in occurrences:
            try:
                flag = self._verify_section_header_table(data, i, shentsize, ei_class)
            except error:
                continue

            if flag:
                shoff = i
                shnum = self._find_shnum(data, shoff, shentsize)
                break

        return shnum, shoff

    def find_section_name_string_table(self, data, sh_num, sh_off,
                                       shentsize, ei_class):
        """
        Determines the index of the section name string table in the sections
        headers table.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param sh_num: Lepton-determined number of entries in section headers
                       table
        :type sh_num: int
        :param sh_off: Lepton-determined section headers table offset
        :type sh_off: int
        :param shentsize: Size of each section headers table entry
        :type shentsize: int
        :param ei_class: Leptop-constructed EI_CLASS field in ELF header
        :type ei_class: int
        """
        for num in range(sh_num):
            current_entry = sh_off + num * shentsize
            if ei_class == 1:
                # ELF32
                sh_type_start = current_entry + (constants.ELF32SECTIONHEADEROFFSETS.SH_NAME[1] -
                                                 constants.ELF32SECTIONHEADEROFFSETS.SH_NAME[0])
                sh_type_len = constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[1] - \
                              constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[0]
            elif ei_class == 2:
                sh_type_start = current_entry + (constants.ELF64SECTIONHEADEROFFSETS.SH_NAME[1] -
                                                 constants.ELF64SECTIONHEADEROFFSETS.SH_NAME[0])
                sh_type_len = constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[1] - \
                              constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[0]
            else:
                raise exceptions.ELFSectionHeaderTableError(f"Invalid EI_CLASS: {ei_class}")

            current_entry_sh_type = unpack(f"{self.endian}I", data[sh_type_start: sh_type_start + sh_type_len])[0]
            if current_entry_sh_type != 3:
                # sh_type != SHT_STRTAB
                continue

            if ei_class == 1:
                # ELF32
                sh_offset_start = current_entry + (constants.ELF32SECTIONHEADEROFFSETS.SH_NAME[1] -
                                                   constants.ELF32SECTIONHEADEROFFSETS.SH_NAME[0]) \
                                                + (constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[1] -
                                                   constants.ELF32SECTIONHEADEROFFSETS.SH_TYPE[0]) \
                                                + (constants.ELF32SECTIONHEADEROFFSETS.SH_FLAGS[1] -
                                                   constants.ELF32SECTIONHEADEROFFSETS.SH_FLAGS[0]) \
                                                + (constants.ELF32SECTIONHEADEROFFSETS.SH_ADDR[1] -
                                                   constants.ELF32SECTIONHEADEROFFSETS.SH_ADDR[0])
                sh_offset_len = constants.ELF32SECTIONHEADEROFFSETS.SH_OFFSET[1] - \
                                constants.ELF32SECTIONHEADEROFFSETS.SH_OFFSET[0]

                sh_offset = unpack(f"{self.endian}I", data[sh_offset_start: sh_offset_start + sh_offset_len])[0]
                sh_size_start = sh_offset_start + sh_offset_len
                sh_size_len = constants.ELF32SECTIONHEADEROFFSETS.SH_SIZE[1] - \
                              constants.ELF32SECTIONHEADEROFFSETS.SH_SIZE[0]
                sh_size = unpack(f"{self.endian}I", data[sh_size_start: sh_size_start + sh_size_len])[0]
            elif ei_class == 2:
                sh_offset_start = current_entry + (constants.ELF64SECTIONHEADEROFFSETS.SH_NAME[1] -
                                                   constants.ELF64SECTIONHEADEROFFSETS.SH_NAME[0]) \
                                  + (constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[1] -
                                     constants.ELF64SECTIONHEADEROFFSETS.SH_TYPE[0]) \
                                  + (constants.ELF64SECTIONHEADEROFFSETS.SH_FLAGS[1] -
                                     constants.ELF64SECTIONHEADEROFFSETS.SH_FLAGS[0]) \
                                  + (constants.ELF64SECTIONHEADEROFFSETS.SH_ADDR[1] -
                                     constants.ELF64SECTIONHEADEROFFSETS.SH_ADDR[0])
                sh_offset_len = constants.ELF64SECTIONHEADEROFFSETS.SH_OFFSET[1] - \
                                constants.ELF64SECTIONHEADEROFFSETS.SH_OFFSET[0]
                sh_offset = unpack(f"{self.endian}Q", data[sh_offset_start: sh_offset_start + sh_offset_len])[0]

                sh_size_start = sh_offset_start + sh_offset_len
                sh_size_len = constants.ELF64SECTIONHEADEROFFSETS.SH_SIZE[1] - \
                              constants.ELF64SECTIONHEADEROFFSETS.SH_SIZE[0]
                sh_size = unpack(f"{self.endian}Q", data[sh_size_start: sh_size_start + sh_size_len])[0]
            else:
                raise exceptions.ELFSectionHeaderTableError(f"Invalid EI_CLASS: {ei_class}")

            section_data = data[sh_offset: sh_offset + sh_size]
            if b".shstrtab" in section_data:
                return num

        return 0

    def build_section_header_table(self, data, elfheader, new_header):
        """
        Builds the section header table of the input ELF file. When building a
        new section header this function relies on Lepton-constructed e_shnum,
        ei_ident fields. It finds a possible e_shoff and e_shnum and constructs
        a section header table based off of that. Values of the section header
        table are read directly from the ELF file based on calculated offsets.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :param elfheader: Lepton-constructed ELF header contents
        :type elfheader: dict
        :param new_header: Flag to indicate reconstruction of ELF section header
        :type new_header: bool
        :return: Constructed ELF section header table
        :rtype: list of dict
        """
        shdr_table = []
        sh_num = unpack(f"{self.endian}H", elfheader["e_shnum"])[0]
        shstrndx = unpack(f"{self.endian}H", elfheader["e_shstrndx"])[0]
        ei_class = elfheader["e_ident"][4]

        if ei_class == 1:
            sh_off = unpack(f"{self.endian}I", elfheader["e_shoff"])[0]
            shentsize = unpack(f"{self.endian}H", data[constants.ELF32HEADEROFFSETS.E_SHENTSIZE[0]:
                                                       constants.ELF32HEADEROFFSETS.E_SHENTSIZE[1]])[0]
        elif ei_class == 2:
            sh_off = unpack(f"{self.endian}Q", elfheader["e_shoff"])[0]
            shentsize = unpack(f"{self.endian}H", data[constants.ELF64HEADEROFFSETS.E_SHENTSIZE[0]:
                                                       constants.ELF64HEADEROFFSETS.E_SHENTSIZE[1]])[0]
        else:
            raise exceptions.ELFSectionHeaderTableError(f"Invalid EI_CLASS: {ei_class}")

        # To reconstruct the ELF section header, all that's needed is to
        # determine sh_off and sh_num fields and update the ELF header
        # entry
        if new_header:
            shentsize = unpack(f"{self.endian}H", elfheader["e_shentsize"])[0]
            sh_num, sh_off = self.find_section_header_table(data, shentsize,
                                                            ei_class)
            shstrndx = self.find_section_name_string_table(data, sh_num, sh_off,
                                                           shentsize, ei_class)

        if ei_class == 1:
            elfheader["e_shnum"], elfheader["e_shoff"], elfheader["e_shstrndx"] = \
                pack(f"{self.endian}H", sh_num), pack(f"{self.endian}I", sh_off), pack(f"{self.endian}H", shstrndx)
        else:
            elfheader["e_shnum"], elfheader["e_shoff"], elfheader["e_shstrndx"] = \
                pack(f"{self.endian}H", sh_num), pack(f"{self.endian}Q", sh_off), pack(f"{self.endian}H", shstrndx)

        for shdr_num in range(sh_num):
            if ei_class == 1:
                try:
                    shdr = self._build_shdr(data, structures.ELF32SECTIONHEADER,
                                            sh_off, shdr_num, shentsize)
                except error:
                    continue
            else:
                try:
                    shdr = self._build_shdr(data, structures.ELF64SECTIONHEADER,
                                            sh_off, shdr_num, shentsize)
                except error:
                    continue

            shdr_table.append(shdr)

        return shdr_table

    def to_bytes(self):
        """
        Returns ELF section header contents in the form of a sequence of bytes
        :return: ELF section header contents
        :rtype: <class 'bytes'>
        """
        shdr_table_bytes = bytes()
        for shdr in self.entries:
            header_bytes = shdr["sh_name"] + shdr["sh_type"] + \
                           shdr["sh_flags"] + shdr["sh_addr"] + \
                           shdr["sh_offset"] + shdr["sh_size"] + \
                           shdr["sh_link"] + shdr["sh_info"] + \
                           shdr["sh_addralign"] + shdr["sh_entsize"]
            shdr_table_bytes += header_bytes

        return shdr_table_bytes
