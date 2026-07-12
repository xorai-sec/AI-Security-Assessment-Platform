from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path

from .models import AssessmentResult
from .storage import write_text


def render_markdown(result: AssessmentResult) -> str:
    lines = [
        "# AI Security Assessment and ISO/IEC 42001 Evidence Report",
        "",
        f"**Assessment:** {result.scope.assessment_name}",
        f"**Target:** {result.scope.target_name}",
        f"**Mode:** {result.target_mode}",
        f"**Organization:** {result.scope.organization_name}",
        f"**Authorized tester:** {result.scope.authorized_tester}",
        f"**Completed:** {result.completed_at}",
        "",
        "## Executive Summary",
        "",
        f"- Executions: {len(result.executions)}",
        f"- Findings: {len(result.findings)}",
        f"- ISO mapping candidates: {len(result.iso_mappings)}",
        "",
        "This report provides technical evidence and ISO/IEC 42001 evidence mapping candidates. It does not certify conformity and does not declare a confirmed nonconformity.",
        "",
        "## Findings",
        "",
        "| ID | Severity | Category | Status | Finding |",
        "|---|---|---|---|---|",
    ]
    for finding in result.findings:
        lines.append(f"| `{finding.id}` | {finding.severity.value} | {finding.category} | {finding.status.value} | {finding.title} |")

    lines.extend(["", "## Evidence Detail", ""])
    for execution in result.executions:
        lines.extend(
            [
                f"### {execution.id}",
                "",
                f"- Framework: {execution.framework}",
                f"- Success: {execution.success}",
                f"- Confidence: {execution.confidence}",
                f"- Evidence hash: `{execution.evidence_hash}`",
                "",
                "**Prompt**",
                "",
                "```text",
                execution.prompt[:1400],
                "```",
                "",
                "**Response**",
                "",
                "```text",
                execution.response[:1400],
                "```",
                "",
                "**Telemetry**",
                "",
                f"- Retrieval trace: `{json.dumps(execution.retrieval_trace, default=str)[:1000]}`",
                f"- Tool trace: `{json.dumps(execution.tool_trace, default=str)[:1000]}`",
                f"- Authorization trace: `{json.dumps(execution.authorization_trace, default=str)[:1000]}`",
                "",
            ]
        )

    lines.extend(["", "## ISO/IEC 42001 Evidence Mapping", ""])
    lines.append("| Finding | Mapping | Sufficiency | Human review | Missing evidence |")
    lines.append("|---|---|---|---|---|")
    for mapping in result.iso_mappings:
        missing = ", ".join(mapping.missing_evidence)
        lines.append(f"| `{mapping.finding_id}` | {mapping.requirement_title} | {mapping.evidence_sufficiency} | {mapping.human_review_status} | {missing} |")

    return "\n".join(lines) + "\n"


def _escape(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _short(value: str, limit: int = 2200) -> str:
    return value if len(value) <= limit else f"{value[:limit]}\n...[truncated for report view]"


def _risk_score(result: AssessmentResult) -> str:
    if not result.findings:
        return "No confirmed findings"
    severities = [finding.severity.value.lower() for finding in result.findings]
    if "critical" in severities or "high" in severities:
        return "High attention"
    if "medium" in severities:
        return "Moderate attention"
    return "Low attention"


def render_html_report(result: AssessmentResult) -> str:
    finding_by_id = {finding.id: finding for finding in result.findings}

    finding_rows = []
    for finding in result.findings:
        linked_execs = " ".join(f"<a href='#{_escape(execution_id)}'>{_escape(execution_id)}</a>" for execution_id in finding.related_executions)
        finding_rows.append(
            "<tr>"
            f"<td><a id='{_escape(finding.id)}' href='#{_escape(finding.related_executions[0] if finding.related_executions else finding.id)}'>{_escape(finding.id)}</a></td>"
            f"<td><span class='sev sev-{_escape(finding.severity.value.lower())}'>{_escape(finding.severity.value)}</span></td>"
            f"<td>{_escape(finding.category)}</td>"
            f"<td>{_escape(finding.title)}<small>{_escape(finding.remediation)}</small></td>"
            f"<td>{linked_execs}</td>"
            "</tr>"
        )

    iso_rows = []
    for mapping in result.iso_mappings:
        finding = finding_by_id.get(mapping.finding_id)
        related_execution = finding.related_executions[0] if finding and finding.related_executions else ""
        prompt_response_link = f"<a href='#{_escape(related_execution)}'>Prompt/response</a>" if related_execution else "No linked execution"
        iso_rows.append(
            "<tr>"
            f"<td><a id='{_escape(mapping.id)}' href='#{_escape(mapping.finding_id)}'>{_escape(mapping.finding_id)}</a></td>"
            f"<td>{_escape(mapping.clause_or_control_id)}<small>{_escape(mapping.requirement_title)}</small></td>"
            f"<td>{_escape(mapping.evidence_sufficiency)}<small>{_escape(mapping.mapping_rationale)}</small></td>"
            f"<td>{prompt_response_link}</td>"
            f"<td>{_escape(mapping.human_review_status)}</td>"
            "</tr>"
        )

    evidence_cards = []
    for index, execution in enumerate(result.executions, start=1):
        linked_findings = [finding for finding in result.findings if execution.id in finding.related_executions]
        finding_links = " ".join(f"<a href='#{_escape(finding.id)}'>{_escape(finding.id)}</a>" for finding in linked_findings) or "No confirmed finding"
        evidence_cards.append(
            f"<article class='evidence-card' id='{_escape(execution.id)}'>"
            f"<div class='evidence-head'><h3>Prompt/Response Evidence {index}</h3><span>{_escape(execution.framework)}</span></div>"
            f"<dl><dt>Execution ID</dt><dd>{_escape(execution.id)}</dd><dt>Evidence Hash</dt><dd>{_escape(execution.evidence_hash)}</dd><dt>Finding Link</dt><dd>{finding_links}</dd><dt>Confidence</dt><dd>{round(execution.confidence * 100)}%</dd></dl>"
            "<div class='prompt-grid'>"
            f"<section><h4>Prompt Sent</h4><pre>{_escape(_short(execution.prompt))}</pre></section>"
            f"<section><h4>Model Response</h4><pre>{_escape(_short(execution.response or '[no response text]'))}</pre></section>"
            "</div>"
            f"<details><summary>Telemetry</summary><pre>{_escape(json.dumps({'retrieval': execution.retrieval_trace, 'tools': execution.tool_trace, 'authorization': execution.authorization_trace}, indent=2, default=str)[:3000])}</pre></details>"
            "</article>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AI Security Evidence Report - {_escape(result.id)}</title>
  <style>
    :root {{ --ink:#102033; --muted:#66758a; --line:#d8e1eb; --teal:#0f766e; --navy:#102033; --paper:#ffffff; --bg:#eef3f7; --warn:#9a6700; --danger:#b42318; }}
    body {{ margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:var(--bg); color:var(--ink); line-height:1.5; }}
    .hero {{ background:linear-gradient(135deg,#102033,#0f766e); color:white; padding:42px 56px; }}
    .hero p {{ color:#dcefed; max-width:1000px; }}
    .wrap {{ max-width:1240px; margin:0 auto; padding:28px; }}
    .grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin-top:-52px; }}
    .metric,.panel,.evidence-card {{ background:var(--paper); border:1px solid var(--line); border-radius:8px; box-shadow:0 14px 34px rgba(16,32,51,.08); }}
    .metric {{ padding:18px; }}
    .metric strong {{ display:block; font-size:28px; }}
    .metric span, small {{ color:var(--muted); display:block; }}
    .panel {{ padding:22px; margin-top:18px; overflow:auto; }}
    h1 {{ margin:0 0 10px; font-size:38px; }}
    h2 {{ margin:0 0 14px; }}
    table {{ width:100%; border-collapse:collapse; }}
    th {{ text-align:left; background:#f5f8fb; color:#33465f; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
    th,td {{ border-bottom:1px solid var(--line); padding:12px; vertical-align:top; }}
    a {{ color:var(--teal); font-weight:800; text-decoration:none; }}
    .sev {{ border-radius:999px; padding:4px 9px; font-size:12px; font-weight:800; background:#eef2f6; }}
    .sev-high,.sev-critical {{ color:var(--danger); background:#fff1f0; }}
    .sev-medium {{ color:var(--warn); background:#fff8e6; }}
    .evidence-card {{ padding:18px; margin-top:14px; }}
    .evidence-head {{ display:flex; justify-content:space-between; gap:10px; align-items:center; }}
    .prompt-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; }}
    pre {{ white-space:pre-wrap; overflow-wrap:anywhere; background:#0f172a; color:#e6edf5; border-radius:8px; padding:14px; font-size:13px; }}
    dl {{ display:grid; grid-template-columns:150px 1fr; gap:6px 12px; }}
    dt {{ color:var(--muted); font-weight:800; }}
    dd {{ margin:0; overflow-wrap:anywhere; }}
    .note {{ color:var(--muted); }}
    @media(max-width:900px) {{ .grid,.prompt-grid {{ grid-template-columns:1fr; }} .hero {{ padding:28px; }} }}
  </style>
</head>
<body>
  <header class="hero">
    <h1>AI Security Evidence Report</h1>
    <p>Authorized technical assessment evidence mapped to ISO/IEC 42001:2023 audit-support areas. This report is evidence for review; it is not a certification statement.</p>
  </header>
  <main class="wrap">
    <section class="grid">
      <article class="metric"><strong>{_escape(result.id)}</strong><span>Assessment ID</span></article>
      <article class="metric"><strong>{len(result.executions)}</strong><span>Prompt/response tests</span></article>
      <article class="metric"><strong>{len(result.findings)}</strong><span>Confirmed findings</span></article>
      <article class="metric"><strong>{_escape(_risk_score(result))}</strong><span>Review priority</span></article>
    </section>
    <section class="panel">
      <h2>Assessment Scope</h2>
      <table><tbody>
        <tr><th>Organization</th><td>{_escape(result.scope.organization_name)}</td><th>Target</th><td>{_escape(result.scope.target_name)}</td></tr>
        <tr><th>Mode</th><td>{_escape(result.target_mode)}</td><th>Authorized Tester</th><td>{_escape(result.scope.authorized_tester)}</td></tr>
        <tr><th>Completed</th><td>{_escape(result.completed_at)}</td><th>Data Classification</th><td>{_escape(result.scope.data_classification)}</td></tr>
      </tbody></table>
    </section>
    <section class="panel">
      <h2>Findings</h2>
      <table><thead><tr><th>ID</th><th>Severity</th><th>Category</th><th>Finding and Recommended Action</th><th>Evidence</th></tr></thead><tbody>
        {''.join(finding_rows) or "<tr><td colspan='5'>No confirmed findings were generated.</td></tr>"}
      </tbody></table>
    </section>
    <section class="panel">
      <h2>ISO/IEC 42001:2023 Evidence Mapping</h2>
      <p class="note">Clause and Annex-A references are candidate evidence mappings for human review, generated from the ISO/IEC 42001:2023 management-system structure.</p>
      <table><thead><tr><th>Finding</th><th>ISO 42001 Area</th><th>Evidence Sufficiency</th><th>Prompt/Response</th><th>Review</th></tr></thead><tbody>
        {''.join(iso_rows) or "<tr><td colspan='5'>No ISO mapping candidates were generated.</td></tr>"}
      </tbody></table>
    </section>
    <section class="panel">
      <h2>Prompt and Response Evidence</h2>
      {''.join(evidence_cards) or "<p>No prompt/response evidence was recorded.</p>"}
    </section>
  </main>
</body>
</html>"""


def render_html(markdown: str) -> str:
    body = "\n".join(f"<p>{html.escape(line)}</p>" if line else "" for line in markdown.splitlines())
    return f"<!doctype html><html><head><meta charset='utf-8'><title>AI Security Evidence Report</title></head><body>{body}</body></html>"


def render_findings_csv(result: AssessmentResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "title", "category", "severity", "status", "confidence", "owner"])
    for finding in result.findings:
        writer.writerow([finding.id, finding.title, finding.category, finding.severity.value, finding.status.value, finding.confidence, finding.owner])
    return output.getvalue()


def write_reports(result: AssessmentResult, report_dir: Path) -> dict[str, str]:
    report_dir.mkdir(parents=True, exist_ok=True)
    markdown = render_markdown(result)
    paths = {
        "markdown": str(write_text(report_dir / f"{result.id}.md", markdown)),
        "html": str(write_text(report_dir / f"{result.id}.html", render_html_report(result))),
        "json": str(write_text(report_dir / f"{result.id}.json", result.model_dump_json(indent=2))),
        "csv": str(write_text(report_dir / f"{result.id}-findings.csv", render_findings_csv(result))),
    }
    return paths
