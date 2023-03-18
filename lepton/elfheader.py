import os
import logging
from copy import deepcopy
from struct import pack, unpack

import lepton.utils.constants as constants
import lepton.utils.exceptions as exceptions
import lepton.utils.structures as structures
import lepton.arch.mappings as arch_mappings

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


class ELFHeader:
    def __init__(self, data, new_header):
        """
        :param data: Input file contents
        :type data: <class 'bytes'>
        :param new_header: Flag to decide whether to build a new header with
                           standard values or clone the header of the input file.
        :type new_header: bool
        """
        self.e_machine = None

        if data[constants.MAGIC_SLICE[0]:constants.MAGIC_SLICE[1]] != constants.ELFMAGIC:
            raise exceptions.ELFMagicError("Not an ELF: " +
                                           hex(unpack("<I", data[constants.MAGIC_SLICE[0]:
                                                                 constants.MAGIC_SLICE[1]])[0]))

        self.little_endian = self.is_little_endian(data)
        self.endian = "<" if self.little_endian else ">"
        self.bits32 = self.is_32_bit(data)
        self.arch_metadata = self.get_target_arch(data).get_arch_field_values(little_endian=self.little_endian,
                                                                              bits32=self.bits32)
        if new_header:
            self.fields = self.build_new_header(data)
        else:
            self.fields = self.build_raw_header(data)

    @staticmethod
    def is_little_endian(data):
        """
        This function determines the endianness of the sample based on heuristics.

        1. I assume that ELF samples have e_version == 1. This assumption is
        purely based on observation. While e_version can be == 0, I haven't
        seen it being used. Note that a sample can still execute correctly
        if e_version is set to 0, but this function will not work correctly.

        2. I don't trust the value of EI_DATA in the ELF header.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :return: True if little endian, False if big endian
        """
        # Assumes the value of e_version is 1 in the sample.
        expected_e_version = 1
        ei_data = unpack("<B", data[constants.EI_DATA[0]: constants.EI_DATA[1]])[0]

        if ei_data == constants.ELFDATA2LSB:
            e_version = unpack("<I", data[constants.E_VERSION[0]: constants.E_VERSION[1]])[0]
            # If the sample is truly little-endian, then e_version should be
            # equal to 1. If it's not, then ei_data is corrupted and the sample
            # is actually big-endian.
            return True if e_version == expected_e_version else False
        elif ei_data == constants.ELFDATA2MSB:
            e_version = unpack(">I", data[constants.E_VERSION[0]: constants.E_VERSION[1]])[0]
            # If the sample is truly big-endian, then e_version should be
            # equal to 1. If it's not, then ei_data is corrupted and the sample
            # is actually little-endian.
            return False if e_version == expected_e_version else True

        return None

    def is_32_bit(self, data):
        """
        This function determines the bitness of the sample based on heuristics.
        For some e_machine values like 386, AMD64 it is straightforward to
        determine bitness. But for others like MIPS, it is not so. For the same
        e_machine == MIPS, a file can be 32-bit or 64-bit.

        I don't trust the value of EI_CLASS in the ELF header.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :return: True if little endian, False if big endian
        """
        # Defines the value of e_phentsize for 32-bit and 64-bit based on ELF
        # specification. AFAIK, these are always true and should be accurate
        # for a functioning ELF file.
        expected_32bit_e_phentsize = 32
        expected_64bit_e_phentsize = 56

        e_phentsize_32_bit = unpack(f"{self.endian}H", data[constants.ELF32HEADEROFFSETS.E_PHENTSIZE[0]:
                                                            constants.ELF32HEADEROFFSETS.E_PHENTSIZE[1]])[0]
        e_phentsize_64_bit = unpack(f"{self.endian}H", data[constants.ELF64HEADEROFFSETS.E_PHENTSIZE[0]:
                                                            constants.ELF64HEADEROFFSETS.E_PHENTSIZE[1]])[0]

        if e_phentsize_32_bit == expected_32bit_e_phentsize:
            return True
        elif e_phentsize_64_bit == expected_64bit_e_phentsize:
            return False

        # Unknown bitness
        return None

    def get_target_arch(self, data):
        """
        Determine target architecture based on the e_machine field in the ELF
        header. e_machine is the only reliable field.

        :param data: Input file contents
        :type data: <class 'bytes'>
        """
        try:
            self.e_machine = pack(f"{self.endian}H",
                                  unpack(f"{self.endian}H",
                                         data[constants.E_MACHINE[0]: constants.E_MACHINE[1]])[0])
            return arch_mappings.ArchMappings().get_arch_obj(self.e_machine)
        except KeyError as e:
            LOG.error("Unsupported architecture: " + hex(unpack(f"{self.endian}H",
                                                         data[constants.E_MACHINE[0]:
                                                              constants.E_MACHINE[1]])[0]))
            raise exceptions.ELFHeaderError("Error in ELF Header:"
                                            "Unsupported architecture")

    @staticmethod
    def _build_hdr(field_values, header_struct):
        """
        Populate header fields.

        :param field_values: Header field and values mapping
        :type field_values: dict
        :param header_struct: The ELF header structure definition (ELF32/ELF64)
        :type header_struct: dict
        :return: Final update of header field and values mapping
        :rtype: dict
        """
        hdr = deepcopy(header_struct)

        hdr.update({
            "e_ident": field_values["ei_mag"] + field_values["ei_class"] +
                       field_values["ei_data"] + field_values["ei_version"] +
                       field_values["ei_osabi"] + field_values["ei_abiversion"] +
                       field_values["ei_pad"],
            "e_type": field_values["e_type"],
            "e_machine": field_values["e_machine"],
            "e_version": field_values["e_version"],
            "e_entry": field_values["e_entry"],
            "e_phoff": field_values["e_phoff"],
            "e_shoff": field_values["e_shoff"],
            "e_flags": field_values["e_flags"],
            "e_ehsize": field_values["e_ehsize"],
            "e_phentsize": field_values["e_phentsize"],
            "e_phnum": field_values["e_phnum"],
            "e_shentsize": field_values["e_shentsize"],
            "e_shnum": field_values["e_shnum"],
            "e_shstrndx": field_values["e_shstrndx"],
        })

        return hdr

    def handle_overlap(self, field_values, data):
        """
        :param field_values: ELF32 header field and values mapping
        :type field_values: dict
        :param data: Input file content
        :type data: <class 'bytes'>
        :return: Updated ELF32 header field and values mapping
        :rtype: dict
        """
        pass

    def _update_elf64_values(self, field_values, data):
        """
        Update ELF64 header field and values

        :param field_values: ELF64 header field and values mapping
        :type field_values: dict
        :param data: Input file content
        :type data: <class 'bytes'>
        :return: Updated ELF64 header field and values mapping
        :rtype: dict
        """
        e_phoff = unpack(f"{self.endian}Q", data[constants.ELF64HEADEROFFSETS.E_PHOFF[0]:
                                                 constants.ELF64HEADEROFFSETS.E_PHOFF[1]])[0]

        if e_phoff < self.arch_metadata["e_phoff"]:
            LOG.info("There is likely an ELF header and program header overlap. "
                     "Lepton is not equipped to handle this scenario.")
            return None

        field_values.update({
            "e_type": pack(f"{self.endian}H",
                           unpack(f"{self.endian}H", data[constants.ELF64HEADEROFFSETS.E_TYPE[0]:
                                                          constants.ELF64HEADEROFFSETS.E_TYPE[1]])[0]),
            "e_entry": pack(f"{self.endian}Q",
                            unpack(f"{self.endian}Q", data[constants.ELF64HEADEROFFSETS.E_ENTRY[0]:
                                                           constants.ELF64HEADEROFFSETS.E_ENTRY[1]])[0]),
            "e_phoff": pack(f"{self.endian}Q", self.arch_metadata["e_phoff"]),
            "e_shoff": pack(f"{self.endian}Q",
                            unpack(f"{self.endian}Q", data[constants.ELF64HEADEROFFSETS.E_SHOFF[0]:
                                                           constants.ELF64HEADEROFFSETS.E_SHOFF[1]])[0]),
            "e_flags": pack(f"{self.endian}I",
                            unpack(f"{self.endian}I", data[constants.ELF64HEADEROFFSETS.E_FLAGS[0]:
                                                           constants.ELF64HEADEROFFSETS.E_FLAGS[1]])[0]),
            "e_ehsize": pack(f"{self.endian}H", self.arch_metadata["e_ehsize"]),
            "e_phentsize": pack(f"{self.endian}H", self.arch_metadata["e_phentsize"]),
            "e_phnum": pack(f"{self.endian}H",
                            unpack(f"{self.endian}H", data[constants.ELF64HEADEROFFSETS.E_PHNUM[0]:
                                                           constants.ELF64HEADEROFFSETS.E_PHNUM[1]])[0]),
            "e_shentsize": pack(f"{self.endian}H", self.arch_metadata["e_shentsize"]),
            "e_shnum": pack(f"{self.endian}H",
                            unpack(f"{self.endian}H", data[constants.ELF64HEADEROFFSETS.E_SHNUM[0]:
                                                           constants.ELF64HEADEROFFSETS.E_SHNUM[1]])[0]),
            "e_shstrndx": pack(f"{self.endian}H",
                               unpack(f"{self.endian}H", data[constants.ELF64HEADEROFFSETS.E_SHSTRNDX[0]:
                                                              constants.ELF64HEADEROFFSETS.E_SHSTRNDX[1]])[0])
        })

        return field_values

    def _update_elf32_values(self, field_values, data):
        """
        Update ELF32 header field and values

        :param field_values: ELF32 header field and values mapping
        :type field_values: dict
        :param data: Input file content
        :type data: <class 'bytes'>
        :return: Updated ELF32 header field and values mapping
        :rtype: dict
        """
        e_phoff = unpack(f"{self.endian}I", data[constants.ELF32HEADEROFFSETS.E_PHOFF[0]:
                                                 constants.ELF32HEADEROFFSETS.E_PHOFF[1]])[0]

        if e_phoff < self.arch_metadata["e_phoff"]:
            LOG.info("There is likely an ELF header and program header overlap. "
                     "Lepton is not equipped to handle this scenario.")
            return None

        field_values.update({
            "e_type": pack(f"{self.endian}H",
                           unpack(f"{self.endian}H", data[constants.ELF32HEADEROFFSETS.E_TYPE[0]:
                                                          constants.ELF32HEADEROFFSETS.E_TYPE[1]])[0]),
            "e_entry": pack(f"{self.endian}I",
                            unpack(f"{self.endian}I", data[constants.ELF32HEADEROFFSETS.E_ENTRY[0]:
                                                           constants.ELF32HEADEROFFSETS.E_ENTRY[1]])[0]),
            "e_phoff": pack(f"{self.endian}I", self.arch_metadata["e_phoff"]),
            "e_shoff": pack(f"{self.endian}I",
                            unpack(f"{self.endian}I", data[constants.ELF32HEADEROFFSETS.E_SHOFF[0]:
                                                           constants.ELF32HEADEROFFSETS.E_SHOFF[1]])[0]),
            "e_flags": pack(f"{self.endian}I",
                            unpack(f"{self.endian}I", data[constants.ELF32HEADEROFFSETS.E_FLAGS[0]:
                                                           constants.ELF32HEADEROFFSETS.E_FLAGS[1]])[0]),
            "e_ehsize": pack(f"{self.endian}H", self.arch_metadata["e_ehsize"]),
            "e_phentsize": pack(f"{self.endian}H", self.arch_metadata["e_phentsize"]),
            "e_phnum": pack(f"{self.endian}H",
                            unpack(f"{self.endian}H", data[constants.ELF32HEADEROFFSETS.E_PHNUM[0]:
                                                           constants.ELF32HEADEROFFSETS.E_PHNUM[1]])[0]),
            "e_shentsize": pack(f"{self.endian}H", self.arch_metadata["e_shentsize"]),
            "e_shnum": pack(f"{self.endian}H",
                            unpack(f"{self.endian}H", data[constants.ELF32HEADEROFFSETS.E_SHNUM[0]:
                                                           constants.ELF32HEADEROFFSETS.E_SHNUM[1]])[0]),
            "e_shstrndx": pack(f"{self.endian}H",
                               unpack(f"{self.endian}H", data[constants.ELF32HEADEROFFSETS.E_SHSTRNDX[0]:
                                                              constants.ELF32HEADEROFFSETS.E_SHSTRNDX[1]])[0])
        })

        return field_values

    def build_new_header(self, data):
        """
        Create a new ELF header structure and populate expected values into the
        header fields. In case of ELF header corruption, these new values should
        allow tools like pyelftools to load the input ELF file.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :return: New ELF header contents
        :rtype: dict
        """
        field_values = {
            "ei_mag": constants.ELFMAGIC,
            "ei_class": pack(f"{self.endian}B", self.arch_metadata["ei_class"]),
            "ei_data": pack(f"{self.endian}B", self.arch_metadata["ei_data"]),
            "ei_version": pack(f"{self.endian}B", self.arch_metadata["ei_version"]),
            "ei_osabi": pack(f"{self.endian}B", self.arch_metadata["ei_osabi"]),
            "ei_abiversion": pack(f"{self.endian}B", self.arch_metadata["ei_abiversion"]),
            "ei_pad": self.arch_metadata["padding"],
            "e_machine": self.e_machine,
            "e_version": pack(f"{self.endian}I", self.arch_metadata["e_version"]),
        }

        if self.arch_metadata["ei_class"] == 1:
            field_values = self._update_elf32_values(field_values, data)
            if field_values is None:
                return
            return self._build_hdr(field_values, deepcopy(structures.ELF32HEADER))
        else:
            field_values = self._update_elf64_values(field_values, data)
            if field_values is None:
                return
            return self._build_hdr(field_values, deepcopy(structures.ELF64HEADER))

    def build_raw_header(self, data):
        """
        Create a header structure from the input file itself. Essentially, cloning
        it.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :return: Cloned ELF header contents
        :rtype: dict
        """
        if self.arch_metadata["ei_class"] == 1:
            field_values = {
                "ei_mag": constants.ELFMAGIC,
                "ei_class": data[constants.ELF32HEADEROFFSETS.EI_CLASS[0]:
                                 constants.ELF32HEADEROFFSETS.EI_CLASS[1]],
                "ei_data": data[constants.ELF32HEADEROFFSETS.EI_DATA[0]:
                                constants.ELF32HEADEROFFSETS.EI_DATA[1]],
                "ei_version": data[constants.ELF32HEADEROFFSETS.EI_VERSION[0]:
                                   constants.ELF32HEADEROFFSETS.EI_VERSION[1]],
                "ei_osabi": data[constants.ELF32HEADEROFFSETS.EI_OSABI[0]:
                                 constants.ELF32HEADEROFFSETS.EI_OSABI[1]],
                "ei_abiversion": data[constants.ELF32HEADEROFFSETS.EI_ABIVERSION[0]:
                                      constants.ELF32HEADEROFFSETS.EI_ABIVERSION[1]],
                "ei_pad": data[constants.ELF32HEADEROFFSETS.EI_PAD[0]:
                               constants.ELF32HEADEROFFSETS.EI_PAD[1]],
                "e_type": data[constants.ELF32HEADEROFFSETS.E_TYPE[0]:
                               constants.ELF32HEADEROFFSETS.E_TYPE[1]],
                "e_machine": data[constants.ELF32HEADEROFFSETS.E_MACHINE[0]:
                                  constants.ELF32HEADEROFFSETS.E_MACHINE[1]],
                "e_version": data[constants.ELF32HEADEROFFSETS.E_VERSION[0]:
                                  constants.ELF32HEADEROFFSETS.E_VERSION[1]],
                "e_entry": data[constants.ELF32HEADEROFFSETS.E_ENTRY[0]:
                                constants.ELF32HEADEROFFSETS.E_ENTRY[1]],
                "e_phoff": data[constants.ELF32HEADEROFFSETS.E_PHOFF[0]:
                                constants.ELF32HEADEROFFSETS.E_PHOFF[1]],
                "e_shoff": data[constants.ELF32HEADEROFFSETS.E_SHOFF[0]:
                                constants.ELF32HEADEROFFSETS.E_SHOFF[1]],
                "e_flags": data[constants.ELF32HEADEROFFSETS.E_FLAGS[0]:
                                constants.ELF32HEADEROFFSETS.E_FLAGS[1]],
                "e_ehsize": data[constants.ELF32HEADEROFFSETS.E_EHSIZE[0]:
                                 constants.ELF32HEADEROFFSETS.E_EHSIZE[1]],
                "e_phentsize": data[constants.ELF32HEADEROFFSETS.E_PHENTSIZE[0]:
                                    constants.ELF32HEADEROFFSETS.E_PHENTSIZE[1]],
                "e_phnum": data[constants.ELF32HEADEROFFSETS.E_PHNUM[0]:
                                constants.ELF32HEADEROFFSETS.E_PHNUM[1]],
                "e_shentsize": data[constants.ELF32HEADEROFFSETS.E_SHENTSIZE[0]:
                                    constants.ELF32HEADEROFFSETS.E_SHENTSIZE[1]],
                "e_shnum": data[constants.ELF32HEADEROFFSETS.E_SHNUM[0]:
                                constants.ELF32HEADEROFFSETS.E_SHNUM[1]],
                "e_shstrndx": data[constants.ELF32HEADEROFFSETS.E_SHSTRNDX[0]:
                                   constants.ELF32HEADEROFFSETS.E_SHSTRNDX[1]],
            }
            return self._build_hdr(field_values, deepcopy(structures.ELF32HEADER))
        else:
            field_values = {
                "ei_mag": constants.ELFMAGIC,
                "ei_class": data[constants.ELF64HEADEROFFSETS.EI_CLASS[0]:
                                 constants.ELF64HEADEROFFSETS.EI_CLASS[1]],
                "ei_data": data[constants.ELF64HEADEROFFSETS.EI_DATA[0]:
                                constants.ELF64HEADEROFFSETS.EI_DATA[1]],
                "ei_version": data[constants.ELF64HEADEROFFSETS.EI_VERSION[0]:
                                   constants.ELF64HEADEROFFSETS.EI_VERSION[1]],
                "ei_osabi": data[constants.ELF64HEADEROFFSETS.EI_OSABI[0]:
                                 constants.ELF64HEADEROFFSETS.EI_OSABI[1]],
                "ei_abiversion": data[constants.ELF64HEADEROFFSETS.EI_ABIVERSION[0]:
                                      constants.ELF64HEADEROFFSETS.EI_ABIVERSION[1]],
                "ei_pad": data[constants.ELF64HEADEROFFSETS.EI_PAD[0]:
                               constants.ELF64HEADEROFFSETS.EI_PAD[1]],
                "e_type": data[constants.ELF64HEADEROFFSETS.E_TYPE[0]:
                               constants.ELF64HEADEROFFSETS.E_TYPE[1]],
                "e_machine": data[constants.ELF64HEADEROFFSETS.E_MACHINE[0]:
                                  constants.ELF64HEADEROFFSETS.E_MACHINE[1]],
                "e_version": data[constants.ELF64HEADEROFFSETS.E_VERSION[0]:
                                  constants.ELF64HEADEROFFSETS.E_VERSION[1]],
                "e_entry": data[constants.ELF64HEADEROFFSETS.E_ENTRY[0]:
                                constants.ELF64HEADEROFFSETS.E_ENTRY[1]],
                "e_phoff": data[constants.ELF64HEADEROFFSETS.E_PHOFF[0]:
                                constants.ELF64HEADEROFFSETS.E_PHOFF[1]],
                "e_shoff": data[constants.ELF64HEADEROFFSETS.E_SHOFF[0]:
                                constants.ELF64HEADEROFFSETS.E_SHOFF[1]],
                "e_flags": data[constants.ELF64HEADEROFFSETS.E_FLAGS[0]:
                                constants.ELF64HEADEROFFSETS.E_FLAGS[1]],
                "e_ehsize": data[constants.ELF64HEADEROFFSETS.E_EHSIZE[0]:
                                 constants.ELF64HEADEROFFSETS.E_EHSIZE[1]],
                "e_phentsize": data[constants.ELF64HEADEROFFSETS.E_PHENTSIZE[0]:
                                    constants.ELF64HEADEROFFSETS.E_PHENTSIZE[1]],
                "e_phnum": data[constants.ELF64HEADEROFFSETS.E_PHNUM[0]:
                                constants.ELF64HEADEROFFSETS.E_PHNUM[1]],
                "e_shentsize": data[constants.ELF64HEADEROFFSETS.E_SHENTSIZE[0]:
                                    constants.ELF64HEADEROFFSETS.E_SHENTSIZE[1]],
                "e_shnum": data[constants.ELF64HEADEROFFSETS.E_SHNUM[0]:
                                constants.ELF64HEADEROFFSETS.E_SHNUM[1]],
                "e_shstrndx": data[constants.ELF64HEADEROFFSETS.E_SHSTRNDX[0]:
                                   constants.ELF64HEADEROFFSETS.E_SHSTRNDX[1]],
            }
            return self._build_hdr(field_values, deepcopy(structures.ELF64HEADER))

    def to_bytes(self):
        """
        Returns ELF header contents in the form of a sequence of bytes
        :return: ELF header contents
        :rtype: <class 'bytes'>
        """
        return self.fields["e_ident"] + self.fields["e_type"] + \
               self.fields["e_machine"] + self.fields["e_version"] + \
               self.fields["e_entry"] + self.fields["e_phoff"] + \
               self.fields["e_shoff"] + self.fields["e_flags"] + \
               self.fields["e_ehsize"] + self.fields["e_phentsize"] + \
               self.fields["e_phnum"] + self.fields["e_shentsize"] + \
               self.fields["e_shnum"] + self.fields["e_shstrndx"]
