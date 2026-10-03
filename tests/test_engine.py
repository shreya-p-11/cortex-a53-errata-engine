import struct
from pathlib import Path

import pytest

from scanner.detector import detect_835769, detect_843419
from scanner.engine import detect_rule, load_rule


ROOT = Path(__file__).resolve().parent.parent
PRE = ROOT / "samples" / "prebuilt"
RULE = ROOT / "rules" / "843419.yaml"
RULE_835769 = ROOT / "rules" / "835769.yaml"
DEMO_RULE = ROOT / "rules" / "demo_rule.yaml"


def structural_findings(findings):
    return [
        (finding["address"], finding["sequence"], finding["pattern"])
        for finding in findings
        if finding["status"] == "VULNERABLE"
    ]


def test_843419_rule_contains_generic_structural_sequences():
    rule = load_rule(RULE)

    assert rule["structural"]["scope"] == "code"
    assert [sequence["name"] for sequence in rule["structural"]["sequences"]] == [1, 2]
    assert rule["structural"]["sequences"][0]["window"] == {"min": 3, "max": 4}


@pytest.mark.parametrize("name", sorted({
    "far_target.elf",
    "far_target_fixed.elf",
    "not_unsigned.elf",
    "safe_offset.elf",
    "seq1_at_ffc.elf",
    "seq1_basic.elf",
    "seq1_basic_fixed.elf",
    "seq1_gap.elf",
    "seq2_basic.elf",
    "too_far.elf",
    "writes_rn.elf",
}))
def test_engine_matches_843419_oracle_structural_results(name):
    path = str(PRE / name)

    oracle = structural_findings(detect_843419(path))
    engine = structural_findings(detect_rule(path, RULE))

    assert engine == oracle


def test_engine_matches_optional_sequence_window():
    findings = detect_rule(str(PRE / "seq1_gap.elf"), RULE)

    assert len(findings) == 1
    assert len(findings[0]["pattern"].split(" ; ")) == 4


def _synthetic_section(words):
    return {
        "name": ".text",
        "addr": 0x400000,
        "data": b"".join(struct.pack("<I", word) for word in words),
    }


@pytest.mark.parametrize(
    "words",
    [
        (0xF9400062, 0x9B020C20),  # ldr; 64-bit madd
        (0xF9400062, 0x9B027C20),  # ldr; mul / XZR accumulator
        (0xF9400062, 0x1B020C20),  # ldr; 32-bit madd
        (0x8B050083, 0x9B020C20),  # add; 64-bit madd
    ],
)
def test_engine_matches_835769_oracle(monkeypatch, words):
    section = _synthetic_section(words)
    monkeypatch.setattr("scanner.detector.load_code_sections", lambda path: [section])
    monkeypatch.setattr("scanner.engine.load_code_sections", lambda path: [section])

    oracle = detect_835769("ignored.elf")
    engine = detect_rule("ignored.elf", RULE_835769)

    assert [
        (finding["address"], finding["sequence"], finding["status"], finding["pattern"])
        for finding in engine
    ] == [
        (finding["address"], finding["sequence"], finding["status"], finding["pattern"])
        for finding in oracle
    ]


def test_engine_rejects_wrong_835769_mnemonic(monkeypatch):
    section = _synthetic_section((0xF9400062, 0x8B050083))  # ldr; add
    monkeypatch.setattr("scanner.detector.load_code_sections", lambda path: [section])
    monkeypatch.setattr("scanner.engine.load_code_sections", lambda path: [section])

    assert detect_rule("ignored.elf", RULE_835769) == detect_835769("ignored.elf") == []


def test_engine_requires_two_835769_instructions(monkeypatch):
    section = _synthetic_section((0xF9400062,))  # incomplete memory-only sequence
    monkeypatch.setattr("scanner.detector.load_code_sections", lambda path: [section])
    monkeypatch.setattr("scanner.engine.load_code_sections", lambda path: [section])

    assert detect_rule("ignored.elf", RULE_835769) == detect_835769("ignored.elf") == []


def test_malformed_rule_is_rejected(tmp_path):
    malformed = tmp_path / "malformed.yaml"
    malformed.write_text("id: malformed\n", encoding="utf-8")

    with pytest.raises(ValueError, match="structural"):
        load_rule(malformed)


def test_unsupported_step_predicate_is_rejected(tmp_path, monkeypatch):
    unsupported = tmp_path / "unsupported.yaml"
    unsupported.write_text(
        """id: unsupported
structural:
  sequences:
    - name: bad
      fix_hint: none
      window: {min: 1, max: 1}
      steps:
        - imaginary_predicate: true
""",
        encoding="utf-8",
    )
    section = _synthetic_section((0xD503201F,))
    monkeypatch.setattr("scanner.engine.load_code_sections", lambda path: [section])

    with pytest.raises(ValueError, match="Unsupported step predicate"):
        detect_rule("ignored.elf", unsupported)


def test_yaml_only_demo_rule_needs_no_python_detector(monkeypatch):
    section = _synthetic_section((0xD503201F, 0xD65F03C0))  # nop; ret
    monkeypatch.setattr("scanner.engine.load_code_sections", lambda path: [section])

    findings = detect_rule("ignored.elf", DEMO_RULE)

    assert [(finding["errata_id"], finding["sequence"], finding["status"])
            for finding in findings] == [("demo_nop_return", "nop_then_return", "VULNERABLE")]