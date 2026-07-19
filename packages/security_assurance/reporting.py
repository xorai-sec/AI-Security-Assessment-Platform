from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path

from .framework_models import FrameworkAssessmentResult
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


def _framework_evidence_id(record: dict[str, object], index: int) -> str:
    return str(record.get("id") or record.get("evidence_id") or record.get("execution_id") or f"framework-evidence-{index}")


def _framework_prompt(record: dict[str, object]) -> str:
    for key in ("prompt", "input", "attack_prompt", "payload", "test_case"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return "[prompt not provided by native artifact]"


def _framework_response(record: dict[str, object]) -> str:
    for key in ("response", "output", "model_response", "actual_output"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return "[response not provided by native artifact]"


def render_framework_markdown_report(result: FrameworkAssessmentResult) -> str:
    lines = [
        "# Multi-Framework AI Security Evidence Report",
        "",
        f"**Assessment:** {result.id}",
        f"**Target ID:** {result.target_id}",
        f"**Status:** {result.status}",
        f"**Strategy:** {result.strategy}",
        f"**Frameworks:** {', '.join(result.frameworks) or 'not selected'}",
        f"**Completed:** {result.completed_at}",
        "",
        "## Executive Summary",
        "",
        f"- Evidence records: {len(result.normalized_evidence)}",
        f"- Unique technical signals: {sum(int(item.get('unique_evidence_count', item.get('evidence_count', 0)) or 0) for item in result.correlated_findings)}",
        f"- Correlated finding candidates: {len(result.correlated_findings)}",
        "- Confirmed / corroborated / candidate / inconclusive / not vulnerable / false positive: "
        + " / ".join(str(sum(item.get('status') == status for item in result.correlated_findings)) for status in ("confirmed", "corroborated", "candidate", "inconclusive", "not_vulnerable", "false_positive")),
        f"- Framework errors: {len(result.errors)}",
        f"- Planner decisions: {len(result.execution_plan)}",
        "",
        "This report preserves normalized evidence from native framework executions and maps it to candidate ISO/IEC 42001 review areas. It does not certify conformity.",
        "",
        "## Framework Execution Summary",
        "",
        "| Framework | Status | Evidence | Errors | Native engine | Artifacts |",
        "|---|---|---:|---:|---|---|",
    ]
    for worker in result.worker_results:
        artifacts = worker.get("raw_artifacts") or worker.get("artifacts") or {}
        artifact_text = ", ".join(sorted(map(str, artifacts.keys()))) if isinstance(artifacts, dict) else str(artifacts)
        lines.append(
            "| "
            f"{worker.get('framework') or worker.get('framework_id') or 'unknown'} | "
            f"{worker.get('status', 'completed')} | "
            f"{len(worker.get('evidence', []))} | "
            f"{len(worker.get('errors', [])) if isinstance(worker.get('errors', []), list) else 1 if worker.get('errors') else 0} | "
            f"{worker.get('native_engine_invoked', 'unknown')} | "
            f"{artifact_text} |"
        )

    lines.extend(["", "## Adaptive Evidence Handoffs", ""])
    if not result.handoff_plans:
        lines.append("No adaptive handoff was used for this assessment mode.")
    for handoff in result.handoff_plans:
        payload = handoff.get("payload", {})
        lines.extend(
            [
                f"### {handoff.get('source_framework')} → {handoff.get('target_framework')}",
                "",
                f"- Objective: {payload.get('objective', '')}",
                f"- Rationale: {handoff.get('rationale', '')}",
                f"- Source evidence: {', '.join(map(str, handoff.get('evidence_references', [])))}",
                f"- Artifact: `{handoff.get('artifact_path', '')}`",
                "",
            ]
        )

    lines.extend(["", "## Correlated Findings", ""])
    lines.append("| ID | Status | Severity | Confidence | Frameworks | Evidence | OWASP | ISO candidate |")
    lines.append("|---|---|---|---:|---|---:|---|---|")
    for finding in result.correlated_findings:
        lines.append(
            "| "
            f"`{finding.get('id')}` | "
            f"{finding.get('status')} | "
            f"{finding.get('severity', 'candidate')} | "
            f"{finding.get('confidence')} | "
            f"{', '.join(map(str, finding.get('frameworks', [])))} | "
            f"{finding.get('unique_evidence_count', finding.get('evidence_count', 0))} | "
            f"{', '.join(map(str, finding.get('owasp_llm_mapping', [])))} | "
            f"{finding.get('iso_42001_clause_control_candidate', {}).get('control_id', 'candidate')} |"
        )

    lines.extend(["", "## Compliance Mapping Rationale", ""])
    lines.append("All mappings below are evidence supporting review and require human auditor validation; they do not claim ISO/IEC 42001 certification or conformity.")
    for finding in result.correlated_findings:
        control = finding.get("iso_42001_clause_control_candidate", {})
        lines.extend(
            [
                f"### {finding.get('id')} — {finding.get('title')}",
                "",
                f"- Technical evidence: {finding.get('technical_evidence_summary', '')}",
                f"- OWASP LLM mapping: {', '.join(map(str, finding.get('owasp_llm_mapping', [])))}",
                f"- OWASP mapping reason: {finding.get('owasp_mapping_reason', '')}",
                f"- Final status justification: {finding.get('vulnerability_justification', '')}",
                f"- Exact prompt/response references: {', '.join(map(str, finding.get('prompt_response_references', [])))}",
                f"- Framework evidence references: {', '.join(map(str, finding.get('evidence_ids', [])))}",
                f"- Detector/scorer/assertion results: `{json.dumps(finding.get('detector_scorer_assertion_results', []), default=str)[:1000]}`",
                f"- Canary matched: {finding.get('canary_matched', False)}",
                f"- Framework contribution: {json.dumps(finding.get('framework_contributions', {}), sort_keys=True)}",
                f"- ISO/IEC 42001 candidate control: {control.get('control_id', 'candidate')} — {control.get('area', '')}",
                f"- Compliance rationale: {finding.get('compliance_rationale', '')}",
                f"- Auditor question: {finding.get('auditor_question', '')}",
                f"- Remediation recommendation: {finding.get('remediation_recommendation', '')}",
                f"- Evidence sufficiency: {finding.get('evidence_sufficiency', 'candidate')}; human review: {finding.get('human_review_status', 'requires_human_review')}",
                "",
            ]
        )

    lines.extend(["", "## Prompt and Response Evidence", ""])
    for index, record in enumerate(result.normalized_evidence, start=1):
        evidence_id = _framework_evidence_id(record, index)
        lines.extend(
            [
                f"### {evidence_id}",
                "",
                f"- Framework: {record.get('framework') or record.get('source') or 'unknown'}",
                f"- Category: {record.get('category') or record.get('vulnerability') or 'uncategorized'}",
                f"- Confidence: {record.get('confidence', 'n/a')}",
                f"- Handoff rationale: {record.get('handoff_rationale', 'not applicable')}",
                f"- OWASP LLM mapping: {', '.join(map(str, record.get('owasp_llm_mapping', [])))}",
                f"- ISO/IEC 42001 relevance: {', '.join(map(str, record.get('iso_42001_evidence_relevance', [])))}",
                f"- Detector/scorer/assertion: `{json.dumps(record.get('evaluator_results', []), default=str)[:800]}`",
                f"- Native artifact: `{record.get('native_artifact_path', '')}`",
                "",
                "**Prompt**",
                "",
                "```text",
                _framework_prompt(record)[:1400],
                "```",
                "",
                "**Response**",
                "",
                "```text",
                _framework_response(record)[:1400],
                "```",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def render_framework_html_report(result: FrameworkAssessmentResult) -> str:
    framework_rows = []
    for worker in result.worker_results:
        artifacts = worker.get("raw_artifacts") or worker.get("artifacts") or {}
        artifact_text = ", ".join(sorted(map(str, artifacts.keys()))) if isinstance(artifacts, dict) else str(artifacts)
        framework_rows.append(
            "<tr>"
            f"<td>{_escape(worker.get('framework') or worker.get('framework_id') or 'unknown')}</td>"
            f"<td>{_escape(worker.get('status', 'completed'))}</td>"
            f"<td>{len(worker.get('evidence', []))}</td>"
            f"<td>{_escape(worker.get('native_engine_invoked', 'unknown'))}</td>"
            f"<td>{_escape(artifact_text)}</td>"
            "</tr>"
        )

    finding_rows = []
    for finding in result.correlated_findings:
        evidence_links = " ".join(
            f"<a href='#{_escape(evidence_id)}'>{_escape(evidence_id)}</a>"
            for evidence_id in finding.get("evidence_ids", [])[:12]
        )
        finding_rows.append(
            "<tr>"
            f"<td><a id='{_escape(finding.get('id'))}' href='#{_escape((finding.get('evidence_ids') or [''])[0])}'>{_escape(finding.get('id'))}</a></td>"
            f"<td>{_escape(finding.get('title'))}<small>{_escape(', '.join(map(str, finding.get('frameworks', []))))}</small></td>"
            f"<td>{_escape(finding.get('status'))}</td>"
            f"<td>{round(float(finding.get('confidence', 0) or 0) * 100)}%</td>"
            f"<td>{evidence_links or 'No linked evidence'}</td>"
            "</tr>"
        )

    handoff_rows = []
    for handoff in result.handoff_plans:
        payload = handoff.get("payload", {})
        handoff_rows.append(
            "<tr>"
            f"<td>{_escape(handoff.get('source_framework'))} → {_escape(handoff.get('target_framework'))}</td>"
            f"<td>{_escape(payload.get('objective', ''))}</td>"
            f"<td>{_escape(handoff.get('rationale', ''))}</td>"
            f"<td>{len(handoff.get('evidence_references', []))}</td>"
            "</tr>"
        )

    iso_rows = []
    for finding in result.correlated_findings:
        evidence_id = str((finding.get("evidence_ids") or [""])[0])
        evidence_link = f"<a href='#{_escape(evidence_id)}'>Prompt/response</a>" if evidence_id else "No linked evidence"
        for mapping in finding.get("iso_42001_evidence_mapping", []) or ["ISO/IEC 42001 AI risk and operational evidence"]:
            iso_rows.append(
                "<tr>"
                f"<td><a href='#{_escape(finding.get('id'))}'>{_escape(finding.get('id'))}</a></td>"
                f"<td>{_escape(mapping)}</td>"
                f"<td>candidate<small>Requires human review against the organization's AI management system.</small></td>"
                f"<td>{evidence_link}</td>"
                "</tr>"
            )

    compliance_rows = []
    for finding in result.correlated_findings:
        control = finding.get("iso_42001_clause_control_candidate", {})
        compliance_rows.append(
            "<tr>"
            f"<td>{_escape(finding.get('id'))}</td>"
            f"<td>{_escape(', '.join(map(str, finding.get('owasp_llm_mapping', []))) or 'Analyst classification required')}</td>"
            f"<td>{_escape(control.get('control_id', 'candidate'))} · {_escape(control.get('area', ''))}</td>"
            f"<td>{_escape(finding.get('compliance_rationale', ''))}<br><strong>Auditor question:</strong> {_escape(finding.get('auditor_question', ''))}</td>"
            f"<td>{_escape(finding.get('evidence_sufficiency', 'candidate'))}<br>{_escape(finding.get('human_review_status', 'requires_human_review'))}</td>"
            "</tr>"
        )

    evidence_cards = []
    for index, record in enumerate(result.normalized_evidence, start=1):
        evidence_id = _framework_evidence_id(record, index)
        evidence_cards.append(
            f"<article class='evidence-card' id='{_escape(evidence_id)}'>"
            f"<div class='evidence-head'><h3>{_escape(record.get('framework') or record.get('source') or 'Framework')} evidence {index}</h3><span>{_escape(record.get('category') or record.get('vulnerability') or 'uncategorized')}</span></div>"
            f"<dl><dt>Evidence ID</dt><dd>{_escape(evidence_id)}</dd><dt>Confidence</dt><dd>{_escape(record.get('confidence', 'n/a'))}</dd><dt>Handoff rationale</dt><dd>{_escape(record.get('handoff_rationale', 'not applicable'))}</dd><dt>OWASP LLM</dt><dd>{_escape(', '.join(map(str, record.get('owasp_llm_mapping', []))))}</dd><dt>ISO/IEC 42001</dt><dd>{_escape(', '.join(map(str, record.get('iso_42001_evidence_relevance', []))))}</dd><dt>Native artifact</dt><dd>{_escape(record.get('native_artifact_path', ''))}</dd></dl>"
            "<div class='prompt-grid'>"
            f"<section><h4>Prompt Sent</h4><pre>{_escape(_short(_framework_prompt(record)))}</pre></section>"
            f"<section><h4>Model Response</h4><pre>{_escape(_short(_framework_response(record)))}</pre></section>"
            "</div>"
            f"<details><summary>Normalized Evidence JSON</summary><pre>{_escape(json.dumps(record, indent=2, default=str)[:4000])}</pre></details>"
            "</article>"
        )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Multi-Framework AI Security Report - {_escape(result.id)}</title>
  <style>
    :root {{ --ink:#102033; --muted:#66758a; --line:#d8e1eb; --teal:#0f766e; --navy:#102033; --paper:#ffffff; --bg:#eef3f7; --warn:#9a6700; --danger:#b42318; }}
    body {{ margin:0; font-family:Inter,Segoe UI,Arial,sans-serif; background:var(--bg); color:var(--ink); line-height:1.5; }}
    .hero {{ background:linear-gradient(135deg,#102033,#0f766e); color:white; padding:42px 56px; }}
    .hero p {{ color:#dcefed; max-width:1000px; }}
    .wrap {{ max-width:1240px; margin:0 auto; padding:28px; }}
    .grid {{ display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin-top:-52px; }}
    .metric,.panel,.evidence-card {{ background:var(--paper); border:1px solid var(--line); border-radius:8px; box-shadow:0 14px 34px rgba(16,32,51,.08); }}
    .metric {{ padding:18px; }}
    .metric strong {{ display:block; font-size:28px; overflow-wrap:anywhere; }}
    .metric span, small {{ color:var(--muted); display:block; }}
    .panel {{ padding:22px; margin-top:18px; overflow:auto; }}
    h1 {{ margin:0 0 10px; font-size:38px; }}
    h2 {{ margin:0 0 14px; }}
    table {{ width:100%; border-collapse:collapse; }}
    th {{ text-align:left; background:#f5f8fb; color:#33465f; font-size:12px; text-transform:uppercase; letter-spacing:.06em; }}
    th,td {{ border-bottom:1px solid var(--line); padding:12px; vertical-align:top; }}
    a {{ color:var(--teal); font-weight:800; text-decoration:none; }}
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
    <h1>Multi-Framework AI Security Evidence Report</h1>
    <p>Adaptive authorized assessment evidence from native framework workers, correlated into finding candidates and ISO/IEC 42001 review mappings.</p>
  </header>
  <main class="wrap">
    <section class="grid">
      <article class="metric"><strong>{_escape(result.id)}</strong><span>Assessment ID</span></article>
      <article class="metric"><strong>{len(result.normalized_evidence)}</strong><span>Raw evidence records</span></article>
      <article class="metric"><strong>{sum(item.get('status') == 'confirmed' for item in result.correlated_findings)} / {sum(item.get('status') == 'corroborated' for item in result.correlated_findings)} / {sum(item.get('status') == 'candidate' for item in result.correlated_findings)}</strong><span>Confirmed / corroborated / candidate</span></article>
      <article class="metric"><strong>{_escape(result.status)}</strong><span>Run status</span></article>
    </section>
    <section class="panel"><h2>Framework Execution</h2><table><thead><tr><th>Framework</th><th>Status</th><th>Evidence</th><th>Native Engine</th><th>Artifacts</th></tr></thead><tbody>{''.join(framework_rows) or "<tr><td colspan='5'>No framework worker results were recorded.</td></tr>"}</tbody></table></section>
    <section class="panel"><h2>Adaptive Evidence Handoffs</h2><table><thead><tr><th>Chain</th><th>Objective</th><th>Rationale</th><th>Source evidence</th></tr></thead><tbody>{''.join(handoff_rows) or "<tr><td colspan='4'>No adaptive handoff was used for this assessment mode.</td></tr>"}</tbody></table></section>
    <section class="panel"><h2>Correlated Findings</h2><table><thead><tr><th>ID</th><th>Finding</th><th>Status</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>{''.join(finding_rows) or "<tr><td colspan='5'>No correlated findings were generated.</td></tr>"}</tbody></table></section>
    <section class="panel"><h2>ISO/IEC 42001:2023 Evidence Mapping</h2><p class="note">Candidate mappings require human review against the organization's AI management system.</p><table><thead><tr><th>Finding</th><th>ISO 42001 Area</th><th>Sufficiency</th><th>Prompt/Response</th></tr></thead><tbody>{''.join(iso_rows) or "<tr><td colspan='4'>No ISO mappings were generated.</td></tr>"}</tbody></table></section>
    <section class="panel"><h2>Compliance Mapping Rationale</h2><p class="note">This table explains how technical evidence supports review of AI management controls. It does not claim certification or conformity.</p><table><thead><tr><th>Finding</th><th>OWASP LLM</th><th>ISO candidate</th><th>Why it matters / auditor question</th><th>Review</th></tr></thead><tbody>{''.join(compliance_rows) or "<tr><td colspan='5'>No compliance mappings were generated.</td></tr>"}</tbody></table></section>
    <section class="panel"><h2>Prompt and Response Evidence</h2>{''.join(evidence_cards) or "<p>No prompt/response evidence was recorded.</p>"}</section>
  </main>
</body>
</html>"""


def render_framework_findings_csv(result: FrameworkAssessmentResult) -> str:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "title", "status", "severity", "confidence", "frameworks", "evidence_count", "unique_evidence_count", "owasp_llm_mapping", "ISO/IEC 42001 candidate control", "evidence_sufficiency", "human_review_status", "remediation"])
    for finding in result.correlated_findings:
        writer.writerow(
            [
                finding.get("id"),
                finding.get("title"),
                finding.get("status"),
                finding.get("severity", "candidate"),
                finding.get("confidence"),
                ", ".join(map(str, finding.get("frameworks", []))),
                finding.get("evidence_count", 0),
                finding.get("unique_evidence_count", finding.get("evidence_count", 0)),
                ", ".join(map(str, finding.get("owasp_llm_mapping", []))),
                finding.get("iso_42001_clause_control_candidate", {}).get("control_id", "candidate"),
                finding.get("evidence_sufficiency", "candidate"),
                finding.get("human_review_status", "requires_human_review"),
                finding.get("remediation_recommendation", ""),
            ]
        )
    return output.getvalue()


def write_framework_reports(result: FrameworkAssessmentResult, report_dir: Path) -> dict[str, str]:
    report_dir.mkdir(parents=True, exist_ok=True)
    markdown = render_framework_markdown_report(result)
    paths = {
        "markdown": str(write_text(report_dir / f"{result.id}.md", markdown)),
        "html": str(write_text(report_dir / f"{result.id}.html", render_framework_html_report(result))),
        "json": str(write_text(report_dir / f"{result.id}.json", result.model_dump_json(indent=2))),
        "csv": str(write_text(report_dir / f"{result.id}-findings.csv", render_framework_findings_csv(result))),
    }
    return paths
