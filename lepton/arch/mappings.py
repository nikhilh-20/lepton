from lepton.arch.mips import MIPS
from lepton.arch.i386 import I386
from lepton.arch.amd64 import AMD64
from lepton.arch.arm import ARM
from lepton.arch.ppc import PPC

import lepton.utils.exceptions as exceptions


# Architecture-specific information is tied to the CPU. ELF files of specified
# architectures are expected to contain these values.
class ArchMappings:
    def __init__(self):
        """
        """
        self.arch_mappings = {
            b"\x03\x00": I386,  # little-endian
            b"\x3E\x00": AMD64,  # little-endian
            b"\x00\x08": MIPS,  # big-endian
            b"\x08\x00": MIPS,  # little-endian
            b"\x28\x00": ARM,  # little-endian
            b"\x00\x14": PPC,  # big-endian
        }

    def get_arch_obj(self, e_machine):
        """
        :param e_machine: Value of e_machine field of ELF header.
        :type e_machine: bytes
        """
        try:
            return self.arch_mappings[e_machine]()
        except KeyError:
            raise exceptions.UnsupportedArchError(f"Architecture: {e_machine} not supported.")
