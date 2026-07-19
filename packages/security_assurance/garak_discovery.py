from typing import Any

CAPABILITY_PROBES = {
    "raw": ["promptinject.HijackLongPrompt", "dan.AutoDANCached", "leakreplay.GuardianCloze", "encoding.InjectBase64"],
    "rag": ["promptinject.HijackLongPrompt", "leakreplay.GuardianCloze"],
    "tools": ["goodside.Tag", "promptinject.HijackLongPrompt"],
    "memory": ["leakreplay.GuardianCloze", "promptinject.HijackLongPrompt"],
}


def capability_probe_selection(capabilities: dict[str, Any] | None, phase: str = "reconnaissance") -> list[str]:
    capabilities = capabilities or {}
    selected: list[str] = []
    if capabilities.get("rag"):
        selected.extend(CAPABILITY_PROBES["rag"])
    if capabilities.get("tools") or capabilities.get("agent_actions"):
        selected.extend(CAPABILITY_PROBES["tools"])
    if capabilities.get("memory") or capabilities.get("memory_telemetry"):
        selected.extend(CAPABILITY_PROBES["memory"])
    if not selected or capabilities.get("chat", True):
        selected.extend(CAPABILITY_PROBES["raw"])
    return list(dict.fromkeys(selected))[: 2 if phase == "reconnaissance" else 6]
