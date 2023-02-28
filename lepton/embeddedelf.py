import re
import os
import struct
import logging

from lepton.utils.constants import ELFMAGIC, ELF32HEADEROFFSETS, E_MACHINE

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


def find_elf_magic_offsets(content):
    """
    Given the input file content, this functions finds all offsets where the
    ELF magic is found.

    :param content: The input file content
    :type content: <class 'bytes'>
    :return: Offsets where the ELF magic is found
    :rtype: set
    """
    start_offsets = set()

    for m in re.finditer(ELFMAGIC, content):
        offset = m.start()
        # Exclude offset 0 since that is the input file itself
        if offset:
            start_offsets.add(offset)

    return start_offsets


def apply_heuristics(content, e_machine, magic_offsets):
    """
    Given the input file content and the offsets where the ELF magic is found,
    this function applies heuristics to filter out false positives.

    :param content: The input file content
    :type content: <class 'bytes'>
    :param e_machine: The parent ELF e_machine field value
    :type e_machine: <class 'bytes'>
    :param magic_offsets: The offsets where the ELF magic is found
    :type magic_offsets: set
    :return: Verified offsets where the embedded ELF magic is found
    :rtype: list
    """
    def _verify_ei_pad(offset):
        """
        This function verifies the EI_PAD bytes in the ELF header.
        """
        # EI_PAD is at the same offset for ELF64 as well
        ei_pad_indices = ELF32HEADEROFFSETS.EI_PAD
        ei_pad = content[offset + ei_pad_indices[0]: offset + ei_pad_indices[1]]
        if ei_pad != b"\x00" * len(ei_pad):
            return False
        return True

    def _verify_e_machine(offset):
        """
        This function verifies if the suspected embedded ELF e_machine field
        value is the same as the parent. Presumably, this embedded ELF file
        should also be able to run on the same architecture as the parent.
        """
        # E_MACHINE is at the same offset for ELF64 as well
        e_machine_indices = E_MACHINE
        embedded_e_machine = content[offset + e_machine_indices[0]:
                                     offset + e_machine_indices[1]]
        if embedded_e_machine != e_machine:
            return False
        return True

    start_offsets = []
    for s in magic_offsets:
        if not _verify_ei_pad(s):
            LOG.debug(f"Could not verify EI_PAD value at offset {s}")
            continue

        if not _verify_e_machine(s):
            LOG.debug(f"Could not verify e_machine value at offset {s}")
            continue

        start_offsets.append(s)

    return start_offsets


def extract_embedded_elf(content, magic_offsets):
    """
    Given the input file content and the offsets where the ELF magic is found,
    this function extracts the embedded ELF files. However, it is not possible
    to reliably determine the embedded ELF file's size. So, this function
    extracts everything from the start of embedded ELF magic to the end of the
    input file or the next embedded ELF magic, whichever comes first.

    :param content: The input file content
    :type content: <class 'bytes'>
    :param magic_offsets: The offset where the ELF magic is found
    :type magic_offsets: list
    :return: Embedded ELF files
    :rtype: list of tuples. Each tuple contains the embedded ELF file content
            and the offset where it was found in the parent ELF binary.
    """
    embedded_elf = []

    for i in range(len(magic_offsets)):
        start_offset = magic_offsets[i]
        if i == len(magic_offsets) - 1:
            end_offset = len(content)
        else:
            end_offset = magic_offsets[i + 1]
        embedded_elf.append((content[start_offset:end_offset], start_offset))

    return embedded_elf
