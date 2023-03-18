class AMD64:
    def __init__(self):
        pass

    def get_arch_field_values(self, **kwargs):
        return {
            "e_machine": "AMD64",
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
            "e_shentsize": 0x40,
        }
