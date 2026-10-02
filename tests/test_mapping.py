import struct

from scanner.detector import detect_843419
from scanner.mapping import address_region, is_code_address, mapping_symbol_kind


def section(symbols, size=0x40):
    return {
        "name": ".text",
        "addr": 0x1000,
        "size": size,
        "data": b"\0" * size,
        "mapping_symbols": symbols,
    }


def symbol(name, value, kind=None):
    return {
        "name": name,
        "value": value,
        "kind": kind or mapping_symbol_kind(name),
    }


def test_mapping_regions_and_transitions():
    mappings = [
        symbol("$x", 0x1000),
        symbol("$d", 0x1010),
        symbol("$x", 0x1020),
    ]
    code_data = section(mappings, size=0x30)

    assert all(is_code_address(code_data, address) for address in range(0x1000, 0x1010))
    assert all(address_region(code_data, address) == "data" for address in range(0x1010, 0x1020))
    assert all(is_code_address(code_data, address) for address in range(0x1020, 0x1030))


def test_mapping_symbol_names_and_ordinary_symbols():
    assert mapping_symbol_kind("$x") == "code"
    assert mapping_symbol_kind("$x.foo") == "code"
    assert mapping_symbol_kind("$d") == "data"
    assert mapping_symbol_kind("$d.foo") == "data"
    assert mapping_symbol_kind("function") is None
    assert mapping_symbol_kind("$xfoo") is None


def test_no_mapping_symbols_preserves_code_default():
    code_data = section([])

    assert is_code_address(code_data, 0x1000)
    assert is_code_address(code_data, 0x103f)


def test_843419_ignores_matches_in_data_regions(monkeypatch):
    data = bytearray(0x2000)
    sequence = struct.pack("<III", 0x90000000, 0xF9400062, 0xF9400001)
    data[0xFF8:0x1004] = sequence
    data[0x1FF8:0x2004] = sequence
    code_data = {
        "name": ".text",
        "addr": 0x400000,
        "size": len(data),
        "data": bytes(data),
        "mapping_symbols": [
            symbol("$x", 0x400000),
            symbol("$d", 0x400FF8),
            symbol("$x", 0x401008),
        ],
    }
    monkeypatch.setattr("scanner.detector.load_code_sections", lambda path: [code_data])

    findings = detect_843419("ignored.elf")

    assert [finding["address"] for finding in findings] == [0x401FF8]