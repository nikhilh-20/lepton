class MIPS:
    def __init__(self):
        pass

    def get_arch_field_values(self, **kwargs):
        little_endian = kwargs.get("little_endian", None)
        bits32 = kwargs.get("bits32", None)
        if bits32:
            if little_endian:
                return {
                    "e_machine": "MIPS",
                    "ei_class": 1,
                    "ei_data": 1,
                    "ei_version": 1,
                    "ei_osabi": 0,
                    "ei_abiversion": 0,
                    "padding": b"\x00\x00\x00\x00\x00\x00\x00",
                    "e_version": 1,
                    "e_phoff": 0x34,
                    "e_ehsize": 0x34,
                    "e_phentsize": 0x20,
                    "e_shentsize": 0x28
                }
            else:
                return {
                    "e_machine": "MIPS",
                    "ei_class": 1,
                    "ei_data": 2,
                    "ei_version": 1,
                    "ei_osabi": 0,
                    "ei_abiversion": 0,
                    "padding": b"\x00\x00\x00\x00\x00\x00\x00",
                    "e_version": 1,
                    "e_phoff": 0x34,
                    "e_ehsize": 0x34,
                    "e_phentsize": 0x20,
                    "e_shentsize": 0x28
                }
        else:
            if little_endian:
                return {
                    "e_machine": "MIPS",
                    "ei_class": 2,
                    "ei_data": 1,
                    "ei_version": 1,
                    "ei_osabi": 0,
                    "ei_abiversion": 0,
                    "padding": b"\x00\x00\x00\x00\x00\x00\x00",
                    "e_version": 1,
                    "e_phoff": 0x40,
                    "e_ehsize": 0x40,
                    "e_phentsize": 0x38,
                    "e_shentsize": 0x40
                }
            else:
                return {
                    "e_machine": "MIPS",
                    "ei_class": 2,
                    "ei_data": 2,
                    "ei_version": 1,
                    "ei_osabi": 0,
                    "ei_abiversion": 0,
                    "padding": b"\x00\x00\x00\x00\x00\x00\x00",
                    "e_version": 1,
                    "e_phoff": 0x40,
                    "e_ehsize": 0x40,
                    "e_phentsize": 0x38,
                    "e_shentsize": 0x40
                }
