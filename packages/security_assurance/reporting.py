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


def render_html(markdown: str) -> str:
    body = "\n".join(f"<p>{html.escape(line)}</p>" if line else "" for line in markdown.splitlines())
    return f"<!doctype html><html><head><meta charset='utf-8'><title>AI Security Evidence Report</title><style>body{{font-family:Arial,sans-serif;max-width:1100px;margin:40px auto;line-height:1.5}}code,pre{{background:#f4f6f8;padding:8px;border-radius:6px;display:block;white-space:pre-wrap}}</style></head><body>{body}</body></html>"


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
        "html": str(write_text(report_dir / f"{result.id}.html", render_html(markdown))),
        "json": str(write_text(report_dir / f"{result.id}.json", result.model_dump_json(indent=2))),
        "csv": str(write_text(report_dir / f"{result.id}-findings.csv", render_findings_csv(result))),
    }
    return paths

