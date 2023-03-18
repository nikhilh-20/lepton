from lepton.utils.exceptions import *
from lepton.elfheader import ELFHeader
from lepton.elfprogramheader import ELFProgramHeaderTable
from lepton.elfsectionheader import ELFSectionHeaderTable
from lepton.embeddedelf import *

logging.basicConfig(level=os.environ.get("LOGLEVEL", "INFO"))
LOG = logging.getLogger(__name__)


class ELFFile:
    def __init__(self, file_handle, new_header=False):
        """
        :param file_handle: File handle to file
        :type file_handle: <class '_io.BufferedReader'>
        :param new_header: Flag to decide whether to build a new header with
                           standard values or clone the header of the input file.
        :type new_header: bool
        """
        self.new_header = new_header

        try:
            self.data = file_handle.read()
        except PermissionError as err:
            LOG.error(f"Permission error: {err}")
            return

        try:
            self.elfheader = ELFHeader(self.data, new_header)
        except ELFHeaderError as err:
            LOG.error(f"ELF header error: {err}")
            return

        if self.elfheader.fields is None:
            LOG.error("ELF header was not constructed. Exiting.")
            return

        try:
            self.elfprogheader = ELFProgramHeaderTable(
                                     self.data,
                                     self.elfheader.fields,
                                     self.elfheader.little_endian
                                 )
        except ELFProgramHeaderTableError as err:
            LOG.error(f"Program header table error: {err}")
            return

        try:
            self.elfsectionheader = ELFSectionHeaderTable(
                                        self.data,
                                        self.elfheader.fields,
                                        self.elfheader.little_endian,
                                        new_header
                                    )
        except ELFSectionHeaderTableError as err:
            LOG.error(f"Section header table error: {err}")
            return

    def reconstruct_file(self):
        """
        This function reconstructs the ELF file with Lepton-constructed headers
        and non-header content directly from the input file.
        """
        # Initial new file with ELF header contents
        new_data = self.elfheader.to_bytes()

        # Add any bytes between ELF header and program headers table
        e_phoff = self.elfheader.fields["e_phoff"]
        if self.elfheader.little_endian:
            gap = int.from_bytes(e_phoff, byteorder="little") - len(new_data)
        else:
            gap = int.from_bytes(e_phoff, byteorder="big") - len(new_data)
        if gap:
            new_data += self.data[len(new_data): len(new_data) + gap]

        # Add program headers table to new file
        new_data += self.elfprogheader.to_bytes()

        # Add any bytes between bytes add so far and section headers table
        e_shoff = self.elfheader.fields["e_shoff"]
        gap = int.from_bytes(e_shoff, byteorder="little") - len(new_data)
        if gap:
            new_data += self.data[len(new_data): len(new_data) + gap]

        # Add section headers table to new file
        new_data += self.elfsectionheader.to_bytes()

        # Add rest of the data
        gap = len(self.data) - len(new_data)
        if gap:
            new_data += self.data[len(new_data): len(new_data) + gap]

        return new_data

    def get_embedded_elf(self):
        """
        This function dumps all ELF files embedded in the input file. These
        extractions are not high fidelity because it's difficult to reliably
        determine the size of an embedded ELF file. So, content exclusively in
        the parent file may also be included in the extracted ELF files.
        """
        start_offsets = find_elf_magic_offsets(self.data)
        start_offsets = apply_heuristics(self.data, self.elfheader.e_machine,
                                         start_offsets)
        return extract_embedded_elf(self.data, start_offsets)
