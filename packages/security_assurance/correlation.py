from __future__ import annotations

from collections import defaultdict

from .models import Finding


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    groups: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        key = f"{finding.category}:{finding.affected_component}:{finding.root_cause[:40]}"
        groups[key].append(finding)

    correlated: list[Finding] = []
    for key, group in groups.items():
        primary = group[0]
        primary.duplicate_group = key
        if len(group) > 1:
            primary.related_executions = sorted({e for f in group for e in f.related_executions})
            primary.evidence_references = sorted({e for f in group for e in f.evidence_references})
            primary.description += f" Supporting executions: {len(group)}."
        correlated.append(primary)
    return correlated

