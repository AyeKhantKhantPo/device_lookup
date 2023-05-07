from netaddr import EUI, valid_mac


class MACAddressStr(str):
    """Data model for MAC Address."""

    def __new__(cls, v):
        if not valid_mac(str(v)):
            raise ValueError("invalid MAC address format")
        m = EUI(v)
        mac = super(MACAddressStr, cls).__new__(cls, str(m))
        # setattr(mac,"vendor", m.info.OUI.org)
        return mac

    def __str__(self) -> str:
        return super().__str__()

    def __repr__(self) -> str:
        return "MACAddressStr(%s)" % self
