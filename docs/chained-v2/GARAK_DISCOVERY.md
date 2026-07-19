# Garak discovery stage

Garak is the first-stage discovery engine. Its generator is always the authorized target proxy; garak does not use the attacker model. Discovery runs in two bounded phases: reconnaissance selects a small capability-aware probe set, then targeted expansion selects additional probes only when reconnaissance produces qualified evidence.

Raw chat targets receive prompt-injection, jailbreak, leakage, and encoding probes. RAG targets add indirect-injection and disclosure probes; tool/agent targets add agency and authorization probes; memory-enabled targets add cross-session and isolation probes. Native garak report rows retain version, probe, detector, attempt ID, prompt, response, detector scores, target generator, timestamps, and a unique evidence fingerprint.

Only rows with real detector evidence, non-empty prompt and response, target relevance, duplicate removal, and confidence of at least 0.35 become PyRIT opportunities. Confidence is not confirmation: hardened refusal responses and zero-score detector rows are rejected. Metrics record attempted/successful probes, unique signals, duplicate rate, detector coverage, rejected opportunities, and handoffs.
