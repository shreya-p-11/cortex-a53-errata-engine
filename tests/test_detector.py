import subprocess
import sys
from pathlib import Path

import pytest

from scanner.detector import detect_843419

ROOT = Path(__file__).resolve().parent.parent
PRE = ROOT / "samples" / "prebuilt"

# (file, expected sequence)
VULNERABLE = [
    ("seq1_basic.elf", 1),
    ("seq1_gap.elf", 1),
    ("seq1_at_ffc.elf", 1),
    ("seq2_basic.elf", 2),
    ("far_target.elf", 1),
]

CLEAN = [
    "safe_offset.elf",
    "too_far.elf",
    "writes_rn.elf",
    "not_unsigned.elf",
    "seq1_basic_fixed.elf",
    "far_target_fixed.elf",
]


@pytest.mark.parametrize("name,seq", VULNERABLE)
def test_vulnerable_binaries_are_flagged(name, seq):
    findings = detect_843419(str(PRE / name))
    assert len(findings) == 1
    assert findings[0]["sequence"] == seq
    assert findings[0]["errata_id"] == "843419"
    assert findings[0]["status"] == "VULNERABLE"


@pytest.mark.parametrize("name", CLEAN)
def test_clean_binaries_have_no_findings(name):
    assert detect_843419(str(PRE / name)) == []


def test_finding_addresses():
    assert detect_843419(str(PRE / "seq1_basic.elf"))[0]["address"] == 0x400FF8
    assert detect_843419(str(PRE / "seq1_at_ffc.elf"))[0]["address"] == 0x400FFC


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "scanner.cli", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


def test_cli_exit_code_findings():
    assert run_cli("--elf", str(PRE / "seq1_basic.elf")).returncode == 1


def test_cli_exit_code_clean():
    assert run_cli("--elf", str(PRE / "safe_offset.elf")).returncode == 0


def test_cli_exit_code_missing_file():
    r = run_cli("--elf", "does_not_exist.elf")
    assert r.returncode == 2
    assert "Traceback" not in r.stderr


def test_cli_rejects_object_file():
    r = run_cli("--elf", str(ROOT / "hello.c"))
    assert r.returncode == 2
