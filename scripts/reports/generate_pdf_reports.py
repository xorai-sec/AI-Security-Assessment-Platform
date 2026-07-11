from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REPORT_DIR = ROOT / "data" / "reports"


def escape_pdf(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def write_simple_pdf(text: str, output: Path) -> None:
    lines = text.splitlines()[:45]
    stream = "BT /F1 10 Tf 50 780 Td 14 TL\n"
    for line in lines:
        stream += f"({escape_pdf(line[:100])}) Tj T*\n"
    stream += "ET"
    objects = [
        "1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n",
        "2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n",
        "3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >> endobj\n",
        "4 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj\n",
        f"5 0 obj << /Length {len(stream.encode('utf-8'))} >> stream\n{stream}\nendstream endobj\n",
    ]
    content = "%PDF-1.4\n"
    offsets = [0]
    for obj in objects:
        offsets.append(len(content.encode("utf-8")))
        content += obj
    xref = len(content.encode("utf-8"))
    content += f"xref\n0 {len(objects)+1}\n0000000000 65535 f \n"
    for offset in offsets[1:]:
        content += f"{offset:010d} 00000 n \n"
    content += f"trailer << /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
    output.write_bytes(content.encode("utf-8"))


def main() -> None:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    markdown_reports = sorted(REPORT_DIR.glob("*.md"), reverse=True)
    if not markdown_reports:
        raise SystemExit("No Markdown reports found in data/reports")
    for report in markdown_reports:
        output = report.with_suffix(".pdf")
        write_simple_pdf(report.read_text(encoding="utf-8"), output)
        print(output)


if __name__ == "__main__":
    main()
