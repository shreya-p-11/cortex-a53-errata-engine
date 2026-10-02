import struct

import pytest

from scanner.detector import detect_835769
from scanner.rules import get_rule, load_rules, rule_detectors


def section(*words):
    return {"name": ".text", "addr": 0x400000, "data": b"".join(
        struct.pack("<I", word) for word in words
    )}


@pytest.fixture
def fake_loader(monkeypatch):
    def load(words):
        monkeypatch.setattr(
            "scanner.detector.load_code_sections", lambda path: [section(*words)]
        )

    return load


def test_yaml_rules_load_and_bind_detectors():
    rules = load_rules()

    assert set(rules) == {"835769", "843419"}
    assert get_rule("835769").implementation == "detect_835769"
    assert get_rule("835769").detector is detect_835769
    assert rule_detectors()["843419"].__name__ == "detect_843419"


def test_memory_followed_by_64_bit_madd_matches(fake_loader):
    # ldr x2, [x3]; madd x0, x1, x2, x3
    fake_loader([0xF9400062, 0x9B020C20])

    findings = detect_835769("ignored.elf")

    assert len(findings) == 1
    assert findings[0]["errata_id"] == "835769"
    assert findings[0]["sequence"] == "sequence_1"
    assert findings[0]["status"] == "VULNERABLE"


@pytest.mark.parametrize(
    "words",
    [
        (0xF9400062, 0x9B027C20),  # ldr; mul (Ra == XZR)
        (0xF9400062, 0x1B020C20),  # ldr; 32-bit madd
        (0x8B050083, 0x9B020C20),  # add; 64-bit madd
        (0x8B050083, 0x9B020C20),  # non-memory; 64-bit madd
    ],
)
def test_non_matching_835769_sequences_are_ignored(fake_loader, words):
    fake_loader(words)

    findings = detect_835769("ignored.elf")

    assert findings == []