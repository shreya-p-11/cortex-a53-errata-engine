import hashlib
import html
import json
import os
from datetime import datetime, timezone


TOOL_NAME = "errata-scanner"
TOOL_VERSION = "0.1.0"


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


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_result(findings, elf_path, rules_checked=None):
    return {
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "binary": {"path": elf_path, "sha256": sha256_of(elf_path)},
        "scan_result": "FAIL" if findings else "PASS",
        "findings": [_serialized_finding(finding) for finding in findings],
        "summary": {
            "total_findings": len(findings),
            "rules_checked": list(rules_checked or ["843419"]),
        },
    }


def _ensure_dir(path):
    folder = os.path.dirname(path)
    if folder:
        os.makedirs(folder, exist_ok=True)


def write_json(result, path):
    _ensure_dir(path)
    with open(path, "w", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)


def print_text_report(findings, elf_path, plain=False):
    if plain:
        _print_plain(findings, elf_path)
        return

    try:
        from rich import box
        from rich.console import Console
        from rich.panel import Panel
        from rich.table import Table
        from rich.text import Text
    except ImportError:
        _print_plain(findings, elf_path)
        return

    console = Console(highlight=False)
    verdict = report_verdict(findings)
    if not findings:
        console.print(Panel(
            Text(f"Verdict: CLEAN\nNo matching errata patterns detected in {elf_path}",
                 style="bold green"),
            title="Cortex-A53 Errata Scan", border_style="green"))
        return

    details = "\n\n".join(
        f"Errata:   Cortex-A53 {finding['errata_id']} (sequence {finding['sequence']})\n"
        f"Sequence: {finding['sequence']}\n"
        f"Status:   {finding['status']}\n"
        f"Address:  0x{finding['address']:x}\n"
        f"Section:  {finding['section']}\n"
        f"Pattern:  {finding['pattern']}\n"
        f"Fix:      {finding['fix_hint']}"
        for finding in findings
    )
    verdict_label = verdict
    if verdict == "MIXED":
        statuses = sorted({finding["status"] for finding in findings})
        verdict_label = f"MIXED ({', '.join(statuses)})"
    console.print(Panel(
        Text(f"Verdict: {verdict_label}\n{elf_path}\n\n{details}",
             style="bold red"),
        title="Cortex-A53 Errata Scan", border_style="red"))
    table = Table(box=box.ROUNDED, show_lines=True, header_style="bold")
    for column in ("#", "Errata", "Seq", "Address", "Section", "Pattern", "Recommended fix"):
        table.add_column(column, overflow="fold")
    for number, finding in enumerate(findings, 1):
        table.add_row(
            Text(str(number)),
            Text(f"Cortex-A53 {finding['errata_id']}", style="bold"),
            Text(str(finding["sequence"])),
            Text(f"0x{finding['address']:x}", style="yellow"),
            Text(finding["section"]),
            Text(finding["pattern"], style="cyan"),
            Text(finding["fix_hint"], style="green"),
        )
    console.print(table)


def _print_plain(findings, elf_path):
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


CSS = """
:root{--bg:#f4f6f9;--card:#fff;--text:#1b2430;--muted:#5b6776;--line:#e1e6ed;
--fail:#c62828;--failbg:#fdecea;--pass:#1b7a3d;--passbg:#e8f5ec;--accent:#1f4fd8}
@media (prefers-color-scheme:dark){:root{--bg:#10151c;--card:#18202b;--text:#e8edf3;
--muted:#9aa7b5;--line:#2a3544;--failbg:#3a1d1d;--passbg:#16301f;--fail:#ff8a80;
--pass:#7bd88f;--accent:#8ab4ff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;line-height:1.5}
.wrap{max-width:1000px;margin:0 auto;padding:24px 16px}h1{font-size:1.4rem;margin:0 0 4px}
.sub{color:var(--muted);margin:0 0 20px}.banner{border-radius:12px;padding:18px 20px;
font-size:1.3rem;font-weight:700;margin-bottom:16px}.banner.fail{background:var(--failbg);color:var(--fail)}
.banner.pass{background:var(--passbg);color:var(--pass)}.banner small{display:block;font-weight:400;
font-size:.9rem;opacity:.9}.card{background:var(--card);border:1px solid var(--line);
border-radius:12px;padding:16px;margin-bottom:16px;overflow-x:auto}.meta{display:grid;
grid-template-columns:140px 1fr;gap:6px 12px;margin:0}.meta dt{color:var(--muted)}.meta dd{margin:0;word-break:break-all}
table{border-collapse:collapse;width:100%;min-width:640px}th,td{text-align:left;padding:10px 8px;
border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;font-size:.85rem}
code{font-family:ui-monospace,Consolas,monospace;font-size:.85rem;color:var(--accent)}
footer{color:var(--muted);font-size:.8rem;margin-top:8px}
"""


def write_html(result, path):
    _ensure_dir(path)
    escape = html.escape
    verdict = result["scan_result"]
    total = result["summary"]["total_findings"]
    rows = "".join(
        "<tr>"
        f"<td>{number}</td><td><b>Cortex-A53 {escape(finding['errata_id'])}</b></td>"
        f"<td>{escape(str(finding['sequence']))}</td><td><code>{escape(finding['address'])}</code></td>"
        f"<td>{escape(finding['section'])}</td><td><code>{escape(finding['pattern'])}</code></td>"
        f"<td>{escape(finding['fix_hint'])}</td></tr>"
        for number, finding in enumerate(result["findings"], 1)
    )
    if verdict == "FAIL":
        banner = (f'<div class="banner fail">VULNERABLE<small>{total} potential '
                  f"finding(s) in this binary</small></div>")
        body = ("<div class=\"card\"><table><thead><tr><th>#</th><th>Errata</th><th>Seq</th>"
                "<th>Address</th><th>Section</th><th>Pattern</th><th>Recommended fix</th>"
                f"</tr></thead><tbody>{rows}</tbody></table></div>")
    else:
        banner = '<div class="banner pass">CLEAN<small>No matching errata patterns detected</small></div>'
        body = ""
    binary = result["binary"]
    page = (
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>Errata Scan Report</title><style>" + CSS + "</style></head><body>"
        "<div class='wrap'><h1>Cortex-A53 Errata Scan Report</h1>"
        f"<p class='sub'>{escape(result['tool'])} {escape(result['tool_version'])}</p>"
        + banner + "<div class='card'><dl class='meta'>"
        f"<dt>Binary</dt><dd>{escape(binary['path'])}</dd>"
        f"<dt>SHA-256</dt><dd><code>{escape(binary['sha256'])}</code></dd>"
        f"<dt>Scanned (UTC)</dt><dd>{escape(result['timestamp'])}</dd>"
        f"<dt>Rules checked</dt><dd>{escape(', '.join(result['summary']['rules_checked']))}</dd>"
        "</dl></div>" + body +
        "<footer>Findings are potential: runtime addresses are required to decide "
        "whether the erratum boundary-crossing condition occurs.</footer></div></body></html>"
    )
    with open(path, "w", encoding="utf-8") as stream:
        stream.write(page)
