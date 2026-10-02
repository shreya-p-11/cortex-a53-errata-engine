def print_text_report(findings, elf_path):
    print(f"\n=== Errata Scan Report: {elf_path} ===")
    if not findings:
        print("Verdict: CLEAN")
        print("No matching errata patterns detected.")
        return

    print(f"Verdict: VULNERABLE ({len(findings)} finding(s))\n")
    for f in findings:
        print(f"Errata:   Cortex-A53 {f['errata_id']} (sequence {f['sequence']})")
        print(f"Status:   {f['status']}")
        print(f"Address:  0x{f['address']:x}")
        print(f"Section:  {f['section']}")
        print(f"Pattern:  {f['pattern']}")
        print(f"Fix:      {f['fix_hint']}")
        print("-" * 40)
