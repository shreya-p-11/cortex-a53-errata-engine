import struct

from scanner.detector import detect_843419


def test_ordinary_adr_is_not_mitigation(monkeypatch):
    # ADR followed by a matching access, but no linker veneer evidence.
    data = bytearray(0x1008)
    data[0xFF8:0x1004] = struct.pack(
        "<III", 0x10000000, 0xF9400062, 0xF9400001
    )
    section = {
        "name": ".text",
        "addr": 0x400000,
        "size": len(data),
        "data": bytes(data),
        "symbols": [],
        "mapping_symbols": [{"value": 0x400000, "kind": "code"}],
    }
    monkeypatch.setattr("scanner.detector.load_code_sections", lambda path: [section])

    assert detect_843419("ignored.elf") == []