import json
import subprocess
import sys
from pathlib import Path

import pytest

from scanner.report import print_json_report, print_text_report, report_data


ROOT = Path(__file__).resolve().parent.parent
PRE = ROOT / "samples" / "prebuilt"


def finding(status="VULNERABLE"):
    return {
        "errata_id": "843419",
        "sequence": 1,
        "status": status,
        "address": 0x400FF8,
        "section": ".text",
        "pattern": "adrp x2, 0x400000 ; ldr x2, [x2]",
        "fix_hint": "insert a NOP",
    }


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "scanner.cli", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


def test_text_report_contains_finding_details(capsys):
    print_text_report([finding()], "sample.elf")

    output = capsys.readouterr().out
    assert "sample.elf" in output
    assert "Verdict: VULNERABLE" in output
    assert "Errata:   Cortex-A53 843419" in output
    assert "Status:   VULNERABLE" in output
    assert "Sequence: 1" in output
    assert "Address:  0x400ff8" in output
    assert "Section:  .text" in output
    assert "Pattern:  adrp x2, 0x400000 ; ldr x2, [x2]" in output
    assert "Fix:      insert a NOP" in output


def test_text_report_handles_clean_mitigated_and_mixed(capsys):
    print_text_report([], "clean.elf")
    clean = capsys.readouterr().out
    assert "Verdict: CLEAN" in clean

    print_text_report([finding("MITIGATED")], "fixed.elf")
    mitigated = capsys.readouterr().out
    assert "Verdict: MITIGATED" in mitigated
    assert "Status:   MITIGATED" in mitigated

    print_text_report([finding(), finding("MITIGATED")], "mixed.elf")
    mixed = capsys.readouterr().out
    assert "Verdict: MIXED (MITIGATED, VULNERABLE)" in mixed
    assert "Status:   VULNERABLE" in mixed
    assert "Status:   MITIGATED" in mixed


def test_json_report_is_valid_and_has_required_fields(capsys):
    print_json_report([finding()], "sample.elf")

    report = json.loads(capsys.readouterr().out)
    assert report["elf"] == "sample.elf"
    assert report["verdict"] == "VULNERABLE"
    assert report["findings"] == [{
        "address": "0x400ff8",
        "errata_id": "843419",
        "fix_hint": "insert a NOP",
        "pattern": "adrp x2, 0x400000 ; ldr x2, [x2]",
        "section": ".text",
        "sequence": 1,
        "status": "VULNERABLE",
    }]


@pytest.mark.parametrize(
    "findings,verdict",
    [([], "CLEAN"), ([finding()], "VULNERABLE"),
     ([finding("MITIGATED")], "MITIGATED")],
)
def test_json_report_verdicts(findings, verdict, capsys):
    print_json_report(findings, "sample.elf")

    report = json.loads(capsys.readouterr().out)
    assert report["verdict"] == verdict
    assert report["findings"] == report_data(findings, "sample.elf")["findings"]


@pytest.mark.parametrize("fmt,expected_code", [("text", 1), ("json", 1)])
def test_cli_format_and_findings_exit_code(fmt, expected_code):
    result = run_cli("--elf", str(PRE / "seq1_basic.elf"), "--format", fmt)

    assert result.returncode == expected_code
    if fmt == "json":
        assert json.loads(result.stdout)["verdict"] == "VULNERABLE"
    else:
        assert "Verdict: VULNERABLE" in result.stdout


@pytest.mark.parametrize("fmt", ["text", "json"])
def test_cli_clean_exit_code(fmt):
    result = run_cli("--elf", str(PRE / "safe_offset.elf"), "--format", fmt)

    assert result.returncode == 0
    if fmt == "json":
        assert json.loads(result.stdout) == {
            "elf": str(PRE / "safe_offset.elf"),
            "findings": [],
            "verdict": "CLEAN",
        }
    else:
        assert "Verdict: CLEAN" in result.stdout


@pytest.mark.parametrize("fmt", ["text", "json"])
@pytest.mark.parametrize("elf", ["does_not_exist.elf", "hello.c"])
def test_cli_input_errors_have_exit_code_two_without_traceback(fmt, elf):
    result = run_cli("--elf", elf, "--format", fmt)

    assert result.returncode == 2
    assert "error:" in result.stderr
    assert "Traceback" not in result.stderr