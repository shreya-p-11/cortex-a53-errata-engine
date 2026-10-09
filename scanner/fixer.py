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
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    obj = OUT_DIR / f"{stem}.o"
    elf = OUT_DIR / f"{stem}.elf"
    subprocess.run([AS, "-g", str(src), "-o", str(obj)], check=True)
    subprocess.run([LD, f"-Ttext={TEXT_ADDR}", str(obj), "-o", str(elf)], check=True)
    return elf

def scan_all(elf, configured_rules):
    findings = []
    for rule_id in sorted(configured_rules):
        rule = configured_rules[rule_id]
        findings.extend(detect_rule(str(elf), rule))
    return findings

def source_line(elf, address):
    out = subprocess.run([ADDR2LINE, "-e", str(elf), hex(address)],
                         capture_output=True, text=True, check=True).stdout.strip()
    try:
        line = int(out.rsplit(":", 1)[1].split()[0])
    except (IndexError, ValueError):
        return None
    return line if line > 0 else None

def apply_fix_action(lines, line_num, fix_action):
    action_type = fix_action.get("type")
    instruction = fix_action.get("instruction", "nop")
    
    if action_type == "insert_instruction":
        position = fix_action.get("position", "after")
        insert_idx = line_num if position == "after" else line_num - 1
        indent = lines[insert_idx][:len(lines[insert_idx]) - len(lines[insert_idx].lstrip())]
        lines.insert(insert_idx, f"{indent}{instruction}\n")
        print(f"     ↳ inserted {instruction} {position} line {line_num}")
        
    elif action_type == "replace_instruction":
        indent = lines[line_num - 1][:len(lines[line_num - 1]) - len(lines[line_num - 1].lstrip())]
        lines[line_num - 1] = f"{indent}{instruction}\n"
        print(f"     ↳ replaced line {line_num} with {instruction}")

    elif action_type == "replace_op_str":
        old_str = fix_action.get("old")
        new_str = fix_action.get("new")
        if old_str in lines[line_num - 1]:
            lines[line_num - 1] = lines[line_num - 1].replace(old_str, new_str)
            print(f"     ↳ replaced '{old_str}' with '{new_str}' on line {line_num}")
        else:
            print(f"     ↳ WARNING: '{old_str}' not found on line {line_num}")

def fix(source, configured_rules):
    source = Path(source)
    lines = source.read_text().splitlines(keepends=True)
    stem = source.stem + "_fixed"
    work = OUT_DIR / f"{stem}.S"
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    GREEN, YELLOW, CYAN, BOLD, DIM, RESET = "\033[92m", "\033[93m", "\033[96m", "\033[1m", "\033[2m", "\033[0m"

    for round_no in range(1, MAX_ROUNDS + 1):
        work.write_text("".join(lines))
        elf = build(work, stem)
        vulnerable = [f for f in scan_all(elf, configured_rules) if f["status"] == "VULNERABLE"]

        if vulnerable:
            print(f"{YELLOW}⟳  Round {round_no}: {len(vulnerable)} vulnerable finding(s) — patching source...{RESET}")
        else:
            print(f"{CYAN}⟳  Round {round_no}: 0 findings — verifying...{RESET}")

        if not vulnerable:
            print(f"\n{GREEN}{BOLD}✔  WORKAROUND APPLIED — BINARY IS CLEAN  ✔{RESET}\n")
            print(f"  {BOLD}Verdict:{RESET}        {GREEN}{BOLD}CLEAN{RESET}")
            print(f"  {BOLD}Rounds taken:{RESET}   {round_no}")
            print(f"  {BOLD}Fixed ELF:{RESET}      {GREEN}{elf}{RESET}")
            print(f"  {BOLD}Fixed source:{RESET}   {work}\n")
            return 0

        targets = {}
        for f in vulnerable:
            n = source_line(elf, f["address"])
            if n is None:
                print(f"error: cannot map {hex(f['address'])} to a source line", file=sys.stderr)
                return 2
            
            rule = configured_rules[f["errata_id"]]
            sequence = next((s for s in rule.structural["sequences"] if s["name"] == f["sequence"]), None)
            fix_action = sequence.get("fix_action") if sequence else None
            
            if not fix_action:
                print(f"error: no fix_action defined for {f['errata_id']} sequence {f['sequence']}", file=sys.stderr)
                return 2
                
            targets[n] = fix_action
            print(f"  {f['errata_id']} at {hex(f['address'])} -> line {n}: {lines[n - 1].strip()}")

        for n in sorted(targets.keys(), reverse=True):
            if not lines[n - 1].endswith("\n"):
                lines[n - 1] += "\n"
            apply_fix_action(lines, n, targets[n])

    print(f"FAILED: still vulnerable after {MAX_ROUNDS} rounds. See {work}")
    return 1

def main():
    parser = argparse.ArgumentParser(description="Auto-apply workarounds to a .S source")
    parser.add_argument("source", help="Assembly source (.S) to fix")
    args = parser.parse_args()
    try:
        configured_rules = load_rules()
        return fix(args.source, configured_rules)
    except (ScanError, subprocess.CalledProcessError, OSError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())