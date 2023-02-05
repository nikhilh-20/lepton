# TODO: Everything

class Error(Exception):
    """Base class for exceptions in this module"""
    pass


class ELFMagicError(Error):
    """Exception raised if the EI_MAG0 - EI_MAG3 are not 7f 45 4c 46"""

    def __init__(self, message):
        self.message = message


class ELFHeaderError(Error):
    """Exception raised if there is a problem with the ELF header"""

    def __init__(self, message):
        self.message = message


class ELFProgramHeaderTableError(Error):
    """Exception raised if there is a problem with reading or composing the
    program header table"""

    def __init__(self, message):
        self.message = message


class ELFSectionHeaderTableError(Error):
    """Exception raised if there is a problem with reading or composing the
    section header table"""

    def __init__(self, message):
        self.message = message
