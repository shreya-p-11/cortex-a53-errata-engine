import json
import struct
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PRE = ROOT / "samples" / "prebuilt"


def run_cli(*args):
    return subprocess.run(
        [sys.executable, "-m", "scanner.cli", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def write_aarch64_elf(path, words):
    text = b"".join(struct.pack("<I", word) for word in words)
    shstr = b"\0.text\0.shstrtab\0"
    text_offset = 64
    shstr_offset = text_offset + len(text)
    section_header_offset = (shstr_offset + len(shstr) + 7) & ~7
    elf_header = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\0" * 9,
        2,
        183,
        1,
        0x400000,
        0,
        section_header_offset,
        0,
        64,
        0,
        0,
        64,
        3,
        2,
    )
    null_header = b"\0" * 64
    text_header = struct.pack(
        "<IIQQQQIIQQ",
        1,
        1,
        0x6,
        0x400000,
        text_offset,
        len(text),
        0,
        0,
        4,
        0,
    )
    shstr_header = struct.pack(
        "<IIQQQQIIQQ",
        7,
        3,
        0,
        0,
        shstr_offset,
        len(shstr),
        0,
        0,
        1,
        0,
    )
    data = bytearray(elf_header)
    data.extend(text)
    data.extend(shstr)
    data.extend(b"\0" * (section_header_offset - len(data)))
    data.extend(null_header)
    data.extend(text_header)
    data.extend(shstr_header)
    path.write_bytes(data)


def test_cli_843419_status_and_exit_codes(tmp_path):
    vulnerable = run_cli("--elf", str(PRE / "seq1_basic.elf"), "--rule", "843419")
    clean = run_cli("--elf", str(PRE / "safe_offset.elf"), "--rule", "843419")
    mitigated = run_cli(
        "--elf", str(PRE / "seq1_basic_fixed.elf"), "--rule", "843419"
    )

    assert vulnerable.returncode == 1
    assert clean.returncode == 0
    assert mitigated.returncode == 0

    report_path = tmp_path / "mitigated.json"
    result = run_cli(
        "--elf", str(PRE / "seq1_basic_fixed.elf"),
        "--rule", "843419",
        "--json", str(report_path),
    )
    assert result.returncode == 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["scan_result"] == "PASS"
    assert report["findings"][0]["status"] == "MITIGATED"

    html_path = tmp_path / "mitigated.html"
    html_result = run_cli(
        "--elf", str(PRE / "seq1_basic_fixed.elf"),
        "--rule", "843419",
        "--html", str(html_path),
        "--plain",
    )
    html = html_path.read_text(encoding="utf-8")
    assert html_result.returncode == 0
    assert "PASS<small>1 mitigated finding(s)" in html
    assert "<table" in html


def test_cli_835769_engine_rule(tmp_path):
    positive = tmp_path / "835769-positive.elf"
    write_aarch64_elf(positive, [0xF9400062, 0x9B020C20])

    vulnerable = run_cli("--elf", str(positive), "--rule", "835769")
    clean = run_cli("--elf", str(PRE / "seq1_basic.elf"), "--rule", "835769")

    assert vulnerable.returncode == 1
    assert clean.returncode == 0


def test_cli_all_uses_discovered_yaml_rules(tmp_path):
    result_path = tmp_path / "all.json"
    result = run_cli(
        "--elf", str(PRE / "seq1_basic.elf"),
        "--rule", "all",
        "--json", str(result_path),
    )

    assert result.returncode == 1
    report = json.loads(result_path.read_text(encoding="utf-8"))
    assert report["summary"]["rules_checked"] == ["835769", "843419", "demo_nop_return"]
    assert report["scan_result"] == "FAIL"


def test_cli_engine_only_demo_rule_and_validation(tmp_path):
    demo_elf = tmp_path / "demo.elf"
    write_aarch64_elf(demo_elf, [0xD503201F, 0xD65F03C0])  # nop; ret

    demo = run_cli("--elf", str(demo_elf), "--rule", "demo_nop_return")
    validation = run_cli("--validate-rules")

    assert demo.returncode == 1
    assert "demo_nop_return" in demo.stdout
    assert validation.returncode == 0
    assert "Validating rules..." in validation.stdout
    assert "demo_rule.yaml" in validation.stdout
    assert "All rules valid." in validation.stdout


def test_cli_discovers_new_yaml_only_rule(tmp_path):
    positive = tmp_path / "demo-new-positive.elf"
    clean = tmp_path / "demo-new-clean.elf"
    write_aarch64_elf(positive, [0xD503201F, 0xD65F03C0])  # nop; ret
    write_aarch64_elf(clean, [0xD65F03C0, 0xD503201F])  # ret; nop

    validation = run_cli("--validate-rules")
    vulnerable = run_cli("--elf", str(positive), "--rule", "demo_new_rule")
    clean_result = run_cli("--elf", str(clean), "--rule", "demo_new_rule")

    assert validation.returncode == 0
    assert "demo_new_rule.yaml" in validation.stdout
    assert vulnerable.returncode == 1
    assert "demo_new_rule" in vulnerable.stdout
    assert clean_result.returncode == 0
    assert "CLEAN" in clean_result.stdout


def test_cli_invalid_rule_and_arguments_return_two():
    invalid_rule = run_cli("--elf", str(PRE / "safe_offset.elf"), "--rule", "missing")
    missing_elf = run_cli("--rule", "843419")

    assert invalid_rule.returncode == 2
    assert "Traceback" not in invalid_rule.stderr
    assert missing_elf.returncode == 2
    assert "Traceback" not in missing_elf.stderr