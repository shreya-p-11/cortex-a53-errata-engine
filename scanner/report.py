import json


def report_verdict(findings):
    statuses = {finding["status"] for finding in findings}
    if not statuses:
        return "CLEAN"
    if len(statuses) == 1:
        return statuses.pop()
    return "MIXED"


def _serialized_finding(finding):
    return {
        "errata_id": finding["errata_id"],
        "sequence": finding["sequence"],
        "status": finding["status"],
        "address": f"0x{finding['address']:x}",
        "section": finding["section"],
        "pattern": finding["pattern"],
        "fix_hint": finding["fix_hint"],
    }


def report_data(findings, elf_path):
    return {
        "elf": elf_path,
        "verdict": report_verdict(findings),
        "findings": [_serialized_finding(finding) for finding in findings],
    }


def print_text_report(findings, elf_path):
    print(f"\n=== Errata Scan Report: {elf_path} ===")
    verdict = report_verdict(findings)
    if verdict == "CLEAN":
        print("Verdict: CLEAN")
        print("No matching errata patterns detected.")
        return

    if verdict == "MIXED":
        statuses = sorted({finding["status"] for finding in findings})
        verdict_label = f"MIXED ({', '.join(statuses)})"
    else:
        verdict_label = verdict
    print(f"Verdict: {verdict_label} ({len(findings)} finding(s))\n")
    for f in findings:
        print(f"Errata:   Cortex-A53 {f['errata_id']} (sequence {f['sequence']})")
        print(f"Sequence: {f['sequence']}")
        print(f"Status:   {f['status']}")
        print(f"Address:  0x{f['address']:x}")
        print(f"Section:  {f['section']}")
        print(f"Pattern:  {f['pattern']}")
        print(f"Fix:      {f['fix_hint']}")
        print("-" * 40)


def print_json_report(findings, elf_path):
    print(json.dumps(report_data(findings, elf_path), indent=2, sort_keys=True))
