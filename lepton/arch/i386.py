class I386:
    def __init__(self):
        pass

    def get_arch_field_values(self, **kwargs):
        return {
            "e_machine": "386",
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
            "e_shentsize": 0x28,
        }
