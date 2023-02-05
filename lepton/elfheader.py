import os
import logging
from copy import deepcopy
from struct import pack, unpack

import lepton.utils.constants as constants
import lepton.utils.exceptions as exceptions
import lepton.utils.structures as structures

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
        self.arch_metadata = None

        if data[constants.MAGIC_SLICE[0]:constants.MAGIC_SLICE[1]] != constants.ELFMAGIC:
            raise exceptions.ELFMagicError("ELFMagicError: Not an ELF: " +
                                           hex(unpack("<I", data[constants.MAGIC_SLICE[0]:
                                                                 constants.MAGIC_SLICE[1]])[0]))

        self.get_target_arch(data)

        if new_header:
            self.fields = self.build_new_header(data)
        else:
            self.fields = self.build_raw_header(data)

    def get_target_arch(self, data):
        """
        Determine target architecture based on the e_machine field in the ELF
        header. e_machine is the only reliable field.

        :param data: Input file contents
        :type data: <class 'bytes'>
        :return: None
        :rtype: None
        """
        try:
            self.e_machine = data[constants.E_MACHINE[0]:
                                  constants.E_MACHINE[1]]
            self.arch_metadata = structures.ARCH[self.e_machine]
        except KeyError as e:
            LOG.error("Unsupported architecture: " + hex(unpack('<H',
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
        e_phoff = unpack("<Q", data[constants.ELF64HEADEROFFSETS.E_PHOFF[0]:
                                    constants.ELF64HEADEROFFSETS.E_PHOFF[1]])[0]
        if e_phoff < self.arch_metadata["e_phoff"]:
            LOG.info("There is likely an ELF header and program header overlap. "
                     "Lepton is not equipped to handle this scenario.")
            return None

        field_values.update({
            "e_type": data[constants.ELF64HEADEROFFSETS.E_TYPE[0]:
                           constants.ELF64HEADEROFFSETS.E_TYPE[1]],
            "e_entry": data[constants.ELF64HEADEROFFSETS.E_ENTRY[0]:
                            constants.ELF64HEADEROFFSETS.E_ENTRY[1]],
            "e_phoff": pack("<Q", self.arch_metadata["e_phoff"]),
            "e_shoff": data[constants.ELF64HEADEROFFSETS.E_SHOFF[0]:
                            constants.ELF64HEADEROFFSETS.E_SHOFF[1]],
            "e_ehsize": pack("<H", self.arch_metadata["e_ehsize"]),
            "e_phentsize": pack("<H", self.arch_metadata["e_phentsize"]),
            "e_phnum": data[constants.ELF64HEADEROFFSETS.E_PHNUM[0]:
                            constants.ELF64HEADEROFFSETS.E_PHNUM[1]],
            "e_shentsize": pack("<H", self.arch_metadata["e_shentsize"]),
            "e_shnum": data[constants.ELF64HEADEROFFSETS.E_SHNUM[0]:
                            constants.ELF64HEADEROFFSETS.E_SHNUM[1]],
            "e_shstrndx": data[constants.ELF64HEADEROFFSETS.E_SHSTRNDX[0]:
                               constants.ELF64HEADEROFFSETS.E_SHSTRNDX[1]]
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
        e_phoff = unpack("<I", data[constants.ELF32HEADEROFFSETS.E_PHOFF[0]:
                                    constants.ELF32HEADEROFFSETS.E_PHOFF[1]])[0]
        if e_phoff < self.arch_metadata["e_phoff"]:
            LOG.info("There is likely an ELF header and program header overlap. "
                     "Lepton is not equipped to handle this scenario.")
            return None

        field_values.update({
            "e_type": data[constants.ELF32HEADEROFFSETS.E_TYPE[0]:
                           constants.ELF32HEADEROFFSETS.E_TYPE[1]],
            "e_entry": data[constants.ELF32HEADEROFFSETS.E_ENTRY[0]:
                            constants.ELF32HEADEROFFSETS.E_ENTRY[1]],
            "e_phoff": pack("<I", self.arch_metadata["e_phoff"]),
            "e_shoff": data[constants.ELF32HEADEROFFSETS.E_SHOFF[0]:
                            constants.ELF32HEADEROFFSETS.E_SHOFF[1]],
            "e_ehsize": pack("<H", self.arch_metadata["e_ehsize"]),
            "e_phentsize": pack("<H", self.arch_metadata["e_phentsize"]),
            "e_phnum": data[constants.ELF32HEADEROFFSETS.E_PHNUM[0]:
                            constants.ELF32HEADEROFFSETS.E_PHNUM[1]],
            "e_shentsize": pack("<H", self.arch_metadata["e_shentsize"]),
            "e_shnum": data[constants.ELF32HEADEROFFSETS.E_SHNUM[0]:
                            constants.ELF32HEADEROFFSETS.E_SHNUM[1]],
            "e_shstrndx": data[constants.ELF32HEADEROFFSETS.E_SHSTRNDX[0]:
                               constants.ELF32HEADEROFFSETS.E_SHSTRNDX[1]]
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
            "ei_class": pack("B", self.arch_metadata["ei_class"]),
            "ei_data": pack("B", self.arch_metadata["ei_data"]),
            "ei_version": pack("B", self.arch_metadata["ei_version"]),
            "ei_osabi": pack("B", self.arch_metadata["ei_osabi"]),
            "ei_abiversion": pack("B", self.arch_metadata["ei_abiversion"]),
            "ei_pad": self.arch_metadata["padding"],
            "e_machine": self.e_machine,
            "e_version": pack("<I", self.arch_metadata["e_version"]),
            "e_flags": pack("<I", 0)
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
