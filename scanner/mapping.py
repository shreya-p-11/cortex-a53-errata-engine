import re


MAPPING_SYMBOL = re.compile(r"^\$(?P<kind>x|d)(?:\..*)?$")


def mapping_symbol_kind(name):
    match = MAPPING_SYMBOL.fullmatch(name)
    if not match:
        return None
    return "code" if match.group("kind") == "x" else "data"


def address_region(section, address):
    """Return the mapping region at address, or code when mappings are absent."""
    symbols = sorted(section.get("mapping_symbols", []), key=lambda symbol: symbol["value"])
    if not symbols:
        return "code"

    section_end = section["addr"] + section.get("size", len(section["data"]))
    for index, symbol in enumerate(symbols):
        start = symbol["value"]
        end = symbols[index + 1]["value"] if index + 1 < len(symbols) else section_end
        if start <= address < end:
            return symbol["kind"]
    return None


def is_code_address(section, address):
    return address_region(section, address) == "code"