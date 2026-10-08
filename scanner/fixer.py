"""Automatic NOP workaround: patch the .S source, rebuild, rescan until clean."""
import argparse
import subprocess
import sys
from pathlib import Path

from scanner.loader import ScanError
from scanner.engine import detect_rule
from scanner.rules import load_rules

AS = "aarch64-linux-gnu-as"
LD = "aarch64-linux-gnu-ld"
ADDR2LINE = "aarch64-linux-gnu-addr2line"
TEXT_ADDR = "0x400000"
MAX_ROUNDS = 5
OUT_DIR = Path("samples/fixed")


def build(src, stem):
    """Assemble (with line info) and link, same way build_cases.sh does."""
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    obj = OUT_DIR / f"{stem}.o"
    elf = OUT_DIR / f"{stem}.elf"
    subprocess.run([AS, "-g", str(src), "-o", str(obj)], check=True)
    subprocess.run([LD, f"-Ttext={TEXT_ADDR}", str(obj), "-o", str(elf)], check=True)
    return elf


def scan_all(elf):
    """Scan an ELF with every configured rule using the generic engine."""
    findings = []
    configured_rules = load_rules()
    for rule_id in sorted(configured_rules):
        rule = configured_rules[rule_id]
        findings.extend(detect_rule(
            str(elf),
            rule.path,
            mitigation_detector=rule.mitigation_detector,
        ))
    return findings


def source_line(elf, address):
    """Map a machine address back to its line in the .S file."""
    out = subprocess.run([ADDR2LINE, "-e", str(elf), hex(address)],
                         capture_output=True, text=True, check=True).stdout.strip()
    try:
        line = int(out.rsplit(":", 1)[1].split()[0])
    except (IndexError, ValueError):
        return None
    return line if line > 0 else None


def fix(source):
    source = Path(source)
    lines = source.read_text().splitlines(keepends=True)
    stem = source.stem + "_fixed"
    work = OUT_DIR / f"{stem}.S"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    # ANSI Escape Codes
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    for round_no in range(1, MAX_ROUNDS + 1):
        work.write_text("".join(lines))
        elf = build(work, stem)
        vulnerable = [f for f in scan_all(elf) if f["status"] == "VULNERABLE"]

        if vulnerable:
            print(f"{YELLOW}⟳  Round {round_no}: {len(vulnerable)} vulnerable finding(s) — patching source...{RESET}")
        else:
            print(f"{CYAN}⟳  Round {round_no}: 0 findings — verifying...{RESET}")

        if not vulnerable:
            title = "✔  WORKAROUND APPLIED — BINARY IS CLEAN  ✔"
            inner_width = 63
            pad = max(0, inner_width - len(title))
            left = pad // 2
            right = pad - left

            print()
            print(f"{GREEN}{BOLD}╭{'─' * inner_width}╮{RESET}")
            print(f"{GREEN}{BOLD}│{' ' * left}{title}{' ' * right}│{RESET}")
            print(f"{GREEN}{BOLD}╰{'─' * inner_width}╯{RESET}")
            print()
            print(f"  {BOLD}Verdict:{RESET}        {GREEN}{BOLD}CLEAN{RESET}  {DIM}(no errata patterns remain){RESET}")
            print(f"  {BOLD}Rounds taken:{RESET}   {round_no}")
            print(f"  {BOLD}Fixed ELF:{RESET}      {GREEN}{elf}{RESET}")
            print(f"  {BOLD}Fixed source:{RESET}   {work}")
            print()
            return 0

        targets = set()
        for f in vulnerable:
            n = source_line(elf, f["address"])
            if n is None:
                print(f"error: cannot map {hex(f['address'])} to a source line", file=sys.stderr)
                return 2
            print(f"  {f['errata_id']} at {hex(f['address'])} -> line {n}: {lines[n - 1].strip()}")
            targets.add(n)

        # Insert a NOP right after each flagged instruction, bottom-up so
        # earlier line numbers stay valid.
        for n in sorted(targets, reverse=True):
            if not lines[n - 1].endswith("\n"):
                lines[n - 1] += "\n"
            indent = lines[n - 1][:len(lines[n - 1]) - len(lines[n - 1].lstrip())]
            lines.insert(n, indent + "nop\n")
            print(f"     {CYAN}↳ inserted NOP after line {n}{RESET}")

    print(f"FAILED: still vulnerable after {MAX_ROUNDS} rounds. See {work}")
    return 1


def main():
    parser = argparse.ArgumentParser(description="Auto-apply NOP workarounds to a .S source")
    parser.add_argument("source", help="Assembly source (.S) to fix")
    args = parser.parse_args()
    try:
        return fix(args.source)
    except (ScanError, subprocess.CalledProcessError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())