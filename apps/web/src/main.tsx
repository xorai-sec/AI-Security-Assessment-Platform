import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Activity,
  ClipboardCheck,
  FileText,
  Layers,
  Play,
  RefreshCw,
  SearchCheck,
  ServerCog,
  ShieldCheck,
  SlidersHorizontal,
  TriangleAlert,
} from "lucide-react";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8080";

type Target = {
  id: string;
  organization: string;
  system_name: string;
  target_name: string;
  target_type: string;
  environment: string;
  model_provider: string;
  model_name: string;
  deployment_type: string;
  criticality: string;
  data_classification: string;
  enabled: boolean;
  visibility: string;
  configuration: { base_url?: string; model_name?: string; chat_path?: string; response_text_path?: string };
  discovered_capabilities?: Record<string, boolean>;
  last_health?: { status: string; reachable: boolean; message: string };
  last_assessment_id?: string;
};

type Assessment = {
  id: string;
  target: string;
  mode: string;
  findings: number;
  completed_at: string;
};

type AssessmentDetail = {
  id: string;
  scope: { assessment_name: string; target_name: string; organization_name: string };
  executions: Array<{
    id: string;
    framework: string;
    prompt: string;
    response: string;
    success: boolean;
    confidence: number;
    retrieval_trace: Array<Record<string, unknown>>;
    tool_trace: Array<Record<string, unknown>>;
    authorization_trace: Array<Record<string, unknown>>;
  }>;
  findings: Array<{ id: string; title: string; severity: string; category: string; status: string; evidence_references: string[] }>;
  iso_mappings: Array<{ id: string; finding_id: string; clause_or_control_id: string; requirement_title: string; evidence_sufficiency: string; human_review_status: string }>;
  reports: Record<string, string>;
};

type Health = { status: string; adapters: Record<string, { status: string; version: string | null }> };

const blankForm = {
  target_name: "Local AI chat endpoint",
  target_type: "custom_rest",
  organization: "Contoso Global",
  system_name: "Registered AI System",
  system_owner: "AI Platform Owner",
  technical_owner: "AI Engineering",
  model_provider: "custom",
  model_name: "local-chat",
  base_url: "http://enterprise-assist:8090",
  chat_path: "/chat",
  health_path: "/health",
  response_text_path: "response",
  prompt_field_path: "message",
  authorization_confirmed: true,
  kill_switch_acknowledged: true,
  rag: false,
  tools: false,
  memory: false,
};

function App() {
  const [view, setView] = useState("dashboard");
  const [health, setHealth] = useState<Health | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [frameworks, setFrameworks] = useState<any[]>([]);
  const [frameworkCapabilities, setFrameworkCapabilities] = useState<Record<string, any>>({});
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selectedAssessmentId, setSelectedAssessmentId] = useState("");
  const [detail, setDetail] = useState<AssessmentDetail | null>(null);
  const [form, setForm] = useState(blankForm);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  async function api(path: string, options?: RequestInit) {
    const response = await fetch(`${API}${path}`, {
      ...options,
      headers: { "Content-Type": "application/json", ...(options?.headers || {}) },
    });
    if (!response.ok) {
      const text = await response.text();
      throw new Error(text || response.statusText);
    }
    return response.json();
  }

  async function refresh() {
    const [healthData, targetData, assessmentData, frameworkData] = await Promise.all([
      api("/health"),
      api("/api/targets"),
      api("/api/assessments"),
      api("/api/frameworks"),
    ]);
    setHealth(healthData);
    setTargets(targetData.targets || []);
    setAssessments(assessmentData.assessments || []);
    setFrameworks(frameworkData.frameworks || []);
    const firstTarget = targetData.targets?.[0]?.id || "";
    const firstAssessment = assessmentData.assessments?.[0]?.id || "";
    setSelectedTargetId((current) => current || firstTarget);
    setSelectedAssessmentId((current) => current || firstAssessment);
  }

  async function loadAssessment(id: string) {
    if (!id) return;
    const data = await api(`/api/assessments/${id}`);
    setDetail(data);
  }

  async function runAction(label: string, action: () => Promise<void>) {
    setBusy(true);
    setNotice(`${label} started.`);
    try {
      await action();
      setNotice(`${label} completed.`);
      await refresh();
    } catch (error: any) {
      setNotice(`${label} failed: ${error.message}`);
    } finally {
      setBusy(false);
    }
  }

  async function registerLabTarget() {
    await runAction("EnterpriseAssist registration", async () => {
      await api("/api/demo/register-enterprise-assist", { method: "POST", body: "{}" });
    });
  }

  async function registerTarget() {
    await runAction("Target registration", async () => {
      await api("/api/targets", {
        method: "POST",
        body: JSON.stringify({
          organization: form.organization,
          system_name: form.system_name,
          target_name: form.target_name,
          target_type: form.target_type,
          system_owner: form.system_owner,
          technical_owner: form.technical_owner,
          model_provider: form.model_provider,
          model_name: form.model_name,
          authorization_confirmed: form.authorization_confirmed,
          kill_switch_acknowledged: form.kill_switch_acknowledged,
          allowed_testing_categories: ["Prompt Injection", "Indirect Prompt Injection", "Unauthorized Retrieval", "Unauthorized Tool Execution", "Confirmation Bypass", "Memory Isolation"],
          configuration: {
            base_url: form.base_url,
            health_path: form.health_path,
            chat_path: form.chat_path,
            model_name: form.model_name,
            response_text_path: form.response_text_path,
            prompt_field_path: form.prompt_field_path,
            request_json_template: {},
          },
          declared_capabilities: {
            chat: true,
            rag: form.rag,
            tools: form.tools,
            memory: form.memory,
            black_box: !(form.rag || form.tools || form.memory),
            grey_box: form.rag || form.tools || form.memory,
          },
        }),
      });
    });
  }

  async function validateSelectedTarget() {
    if (!selectedTargetId) return;
    await runAction("Target validation", async () => {
      await api(`/api/targets/${selectedTargetId}/validate`, { method: "POST", body: "{}" });
      await api(`/api/targets/${selectedTargetId}/health-check`, { method: "POST", body: "{}" });
      await api(`/api/targets/${selectedTargetId}/discover-capabilities`, { method: "POST", body: "{}" });
      await api(`/api/targets/${selectedTargetId}/test-message`, {
        method: "POST",
        body: JSON.stringify({ prompt: "Reply with READY only." }),
      });
    });
  }

  async function runAssessment() {
    if (!selectedTargetId) return;
    await runAction("Assessment", async () => {
      const data = await api("/api/assessments/target", {
        method: "POST",
        body: JSON.stringify({
          target_id: selectedTargetId,
          assessment_name: "Authorized target assessment",
          target_mode: "vulnerable",
          written_authorization_confirmed: true,
          max_requests: 20,
        }),
      });
      setSelectedAssessmentId(data.id);
      setDetail(data);
    });
  }

  async function checkFrameworks() {
    await runAction("Framework health check", async () => {
      await api("/api/frameworks/health", { method: "POST", body: "{}" });
      const caps = await api("/api/frameworks/capabilities");
      setFrameworkCapabilities(caps.frameworks || {});
    });
  }

  async function runAllFrameworks() {
    if (!selectedTargetId) return;
    await runAction("Multi-framework assessment", async () => {
      await api("/api/assessments/frameworks", {
        method: "POST",
        body: JSON.stringify({
          target_id: selectedTargetId,
          frameworks: ["native", "garak", "pyrit", "promptfoo", "deepteam"],
          objective: "Authorized multi-framework AI security assessment",
          category: "multi_framework",
          strategy: "baseline",
          maximum_requests: 20,
          written_authorization_confirmed: true,
        }),
      });
    });
  }

  useEffect(() => {
    refresh().catch((error) => setNotice(error.message));
  }, []);

  useEffect(() => {
    loadAssessment(selectedAssessmentId).catch(() => undefined);
  }, [selectedAssessmentId]);

  const selectedTarget = useMemo(() => targets.find((target) => target.id === selectedTargetId), [targets, selectedTargetId]);
  const totalFindings = assessments.reduce((sum, assessment) => sum + assessment.findings, 0);
  const enabledTargets = targets.filter((target) => target.enabled).length;
  const latestExecutions = detail?.executions || [];

  return (
    <main>
      <aside>
        <div className="brand">AI<br />AIMS</div>
        {["dashboard", "targets", "frameworks", "assessments", "evidence", "iso", "reports", "administration"].map((item) => (
          <button className={view === item ? "nav active" : "nav"} key={item} onClick={() => setView(item)}>
            {item}
          </button>
        ))}
      </aside>

      <section className="workspace">
        <header>
          <div>
            <p className="eyebrow">Authorized AI security and ISO/IEC 42001 evidence platform</p>
            <h1>General Target Assessment Console</h1>
            <p>Register approved AI systems, validate connectivity, run controlled campaigns, inspect evidence, and generate human-reviewed assurance reports.</p>
          </div>
          <button className="ghost" onClick={() => refresh()} disabled={busy}><RefreshCw size={16} /> Refresh</button>
        </header>

        {notice && <div className="notice">{notice}</div>}

        {view === "dashboard" && (
          <>
            <div className="metrics">
              <Metric icon={<ShieldCheck />} label="API health" value={health?.status || "loading"} />
              <Metric icon={<ServerCog />} label="Registered targets" value={targets.length} />
              <Metric icon={<SearchCheck />} label="Enabled targets" value={enabledTargets} />
              <Metric icon={<TriangleAlert />} label="Total findings" value={totalFindings} />
            </div>
            <section className="panel split">
              <div>
                <p className="eyebrow">Readiness</p>
                <h2>Framework and adapter state</h2>
                <div className="cards compact">
                  {health && Object.entries(health.adapters).map(([name, value]) => (
                    <article className="card" key={name}>
                      <strong>{name}</strong>
                      <StatusBadge status={value.status} />
                    </article>
                  ))}
                </div>
              </div>
              <div>
                <p className="eyebrow">Fast path</p>
                <h2>Controlled lab target</h2>
                <p>Register EnterpriseAssist as a validated adapter target, then run the same native campaigns through the generic target pipeline.</p>
                <div className="actions">
                  <button onClick={registerLabTarget} disabled={busy}><ClipboardCheck size={16} /> Register Lab Target</button>
                  <button onClick={runAssessment} disabled={busy || !selectedTargetId}><Play size={16} /> Run Selected Target</button>
                </div>
              </div>
            </section>
          </>
        )}

        {view === "targets" && (
          <section className="grid-two">
            <TargetRegistration form={form} setForm={setForm} onSubmit={registerTarget} busy={busy} />
            <TargetInventory
              targets={targets}
              selectedTargetId={selectedTargetId}
              setSelectedTargetId={setSelectedTargetId}
              onValidate={validateSelectedTarget}
              onAssess={runAssessment}
              busy={busy}
            />
          </section>
        )}

        {view === "assessments" && (
          <section className="panel">
            <PanelTitle icon={<Activity />} title="Assessments" subtitle="Real completed runs and generated reports." />
            <div className="table">
              <div className="row head"><span>ID</span><span>Target</span><span>Mode</span><span>Findings</span><span>Completed</span></div>
              {assessments.length === 0 && <div className="empty">No assessments have been run yet.</div>}
              {assessments.map((assessment) => (
                <button className="row clickable" key={assessment.id} onClick={() => setSelectedAssessmentId(assessment.id)}>
                  <span>{assessment.id}</span><span>{assessment.target}</span><span>{assessment.mode}</span><span>{assessment.findings}</span><span>{assessment.completed_at}</span>
                </button>
              ))}
            </div>
          </section>
        )}

        {view === "frameworks" && (
          <section className="panel">
            <PanelTitle icon={<SlidersHorizontal />} title="Framework Manager" subtitle="Isolated worker health, capabilities, and controlled multi-framework execution." />
            <div className="actions">
              <button onClick={checkFrameworks} disabled={busy}><RefreshCw size={16} /> Health + Capabilities</button>
              <button onClick={runAllFrameworks} disabled={busy || !selectedTargetId}><Play size={16} /> Run All Compatible</button>
            </div>
            <div className="cards">
              {frameworks.map((framework: any) => (
                <article className="card" key={framework.id}>
                  <strong>{framework.name}</strong>
                  <StatusBadge status={framework.health || "unknown"} />
                  <span>{framework.version || "version pending"}</span>
                  <span>{framework.enabled ? "enabled" : "disabled"}</span>
                  <p>{(frameworkCapabilities[framework.id]?.capabilities || []).map((item: any) => item.name).join(", ") || "Run capabilities check"}</p>
                </article>
              ))}
            </div>
          </section>
        )}

        {view === "evidence" && (
          <EvidenceView detail={detail} executions={latestExecutions} />
        )}

        {view === "iso" && (
          <section className="panel">
            <PanelTitle icon={<Layers />} title="ISO Assurance Mapping" subtitle="Candidate mappings require human review and do not certify conformity." />
            <div className="table">
              <div className="row iso-head"><span>Finding</span><span>Clause/control</span><span>Evidence sufficiency</span><span>Review</span></div>
              {!detail?.iso_mappings?.length && <div className="empty">Select or run an assessment to view ISO mappings.</div>}
              {detail?.iso_mappings.map((mapping) => (
                <div className="row iso-row" key={mapping.id}>
                  <span>{mapping.finding_id}</span>
                  <span>{mapping.clause_or_control_id} · {mapping.requirement_title}</span>
                  <span>{mapping.evidence_sufficiency}</span>
                  <span>{mapping.human_review_status}</span>
                </div>
              ))}
            </div>
          </section>
        )}

        {view === "reports" && (
          <section className="panel">
            <PanelTitle icon={<FileText />} title="Reports" subtitle="Open report artifacts generated from persisted assessment evidence." />
            {!selectedAssessmentId && <div className="empty">Run an assessment first.</div>}
            {selectedAssessmentId && (
              <div className="actions">
                <a className="buttonlike" href={`${API}/api/reports/${selectedAssessmentId}/markdown`} target="_blank">Markdown</a>
                <a className="buttonlike" href={`${API}/api/reports/${selectedAssessmentId}/html`} target="_blank">HTML</a>
                <a className="buttonlike" href={`${API}/api/reports/${selectedAssessmentId}/json`} target="_blank">JSON</a>
                <a className="buttonlike" href={`${API}/api/reports/${selectedAssessmentId}/csv`} target="_blank">CSV</a>
              </div>
            )}
          </section>
        )}

        {view === "administration" && (
          <section className="panel">
            <PanelTitle icon={<SlidersHorizontal />} title="Administration" subtitle="Safety posture for this build." />
            <ul className="checks">
              <li>Global URL policy restricts schemes, metadata IPs, local/private ranges, redirects, ports, and unsupported protocols.</li>
              <li>Targets require authorization and kill-switch acknowledgement before assessment launch.</li>
              <li>Credentials are masked in API responses and reports; development encryption uses an environment key.</li>
              <li>Production targets remain blocked by default in the assessment scope.</li>
            </ul>
          </section>
        )}
      </section>
    </main>
  );
}

function Metric({ icon, label, value }: { icon: React.ReactNode; label: string; value: string | number }) {
  return <article><div>{icon}</div><strong>{value}</strong><span>{label}</span></article>;
}

function StatusBadge({ status }: { status: string }) {
  const good = ["ok", "healthy", "Available", "available", "enabled", "white_box", "grey_box", "black_box", "confirmed"].includes(status);
  return <span className={good ? "badge good" : "badge warn"}>{status}</span>;
}

function PanelTitle({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle: string }) {
  return <div className="panel-title">{icon}<div><h2>{title}</h2><p>{subtitle}</p></div></div>;
}

function TargetRegistration({ form, setForm, onSubmit, busy }: any) {
  const set = (key: string, value: string | boolean) => setForm((current: any) => ({ ...current, [key]: value }));
  return (
    <section className="panel">
      <PanelTitle icon={<ServerCog />} title="Register Target" subtitle="Connection details are validated before an assessment can run." />
      <div className="form-grid">
        <label>Target name<input value={form.target_name} onChange={(event) => set("target_name", event.target.value)} /></label>
        <label>Target type<select value={form.target_type} onChange={(event) => set("target_type", event.target.value)}>
          <option value="custom_rest">Custom REST</option>
          <option value="openai_compatible">OpenAI-compatible</option>
          <option value="ollama">Ollama</option>
          <option value="vllm">vLLM</option>
          <option value="generic_rag">Generic RAG</option>
          <option value="generic_agent">Generic Agent</option>
        </select></label>
        <label>Organization<input value={form.organization} onChange={(event) => set("organization", event.target.value)} /></label>
        <label>AI system<input value={form.system_name} onChange={(event) => set("system_name", event.target.value)} /></label>
        <label>Base URL<input value={form.base_url} onChange={(event) => set("base_url", event.target.value)} /></label>
        <label>Chat path<input value={form.chat_path} onChange={(event) => set("chat_path", event.target.value)} /></label>
        <label>Model provider<input value={form.model_provider} onChange={(event) => set("model_provider", event.target.value)} /></label>
        <label>Model name<input value={form.model_name} onChange={(event) => set("model_name", event.target.value)} /></label>
        <label>Response path<input value={form.response_text_path} onChange={(event) => set("response_text_path", event.target.value)} /></label>
        <label>Prompt field<input value={form.prompt_field_path} onChange={(event) => set("prompt_field_path", event.target.value)} /></label>
      </div>
      <div className="toggles">
        {["rag", "tools", "memory", "authorization_confirmed", "kill_switch_acknowledged"].map((key) => (
          <label key={key}><input type="checkbox" checked={Boolean((form as any)[key])} onChange={(event) => set(key, event.target.checked)} /> {key.replace(/_/g, " ")}</label>
        ))}
      </div>
      <button onClick={onSubmit} disabled={busy}><ClipboardCheck size={16} /> Save Target</button>
    </section>
  );
}

function TargetInventory({ targets, selectedTargetId, setSelectedTargetId, onValidate, onAssess, busy }: any) {
  return (
    <section className="panel">
      <PanelTitle icon={<SearchCheck />} title="Target Inventory" subtitle="Select a target, validate it, then launch an authorized run." />
      <div className="target-list">
        {targets.length === 0 && <div className="empty">No targets registered yet.</div>}
        {targets.map((target: Target) => (
          <button className={selectedTargetId === target.id ? "target active" : "target"} key={target.id} onClick={() => setSelectedTargetId(target.id)}>
            <strong>{target.target_name}</strong>
            <span>{target.target_type} · {target.model_name}</span>
            <span>{target.configuration?.base_url}</span>
            <div><StatusBadge status={target.enabled ? "enabled" : "disabled"} /> <StatusBadge status={target.visibility} /></div>
          </button>
        ))}
      </div>
      <div className="actions">
        <button onClick={onValidate} disabled={busy || !selectedTargetId}><SearchCheck size={16} /> Validate + Discover</button>
        <button onClick={onAssess} disabled={busy || !selectedTargetId}><Play size={16} /> Run Assessment</button>
      </div>
    </section>
  );
}

function EvidenceView({ detail, executions }: { detail: AssessmentDetail | null; executions: AssessmentDetail["executions"] }) {
  return (
    <section className="panel">
      <PanelTitle icon={<ClipboardCheck />} title="Evidence Transcript" subtitle="Prompt, response, framework result, telemetry, and confidence from the selected assessment." />
      {!detail && <div className="empty">Select or run an assessment to view evidence.</div>}
      {detail && (
        <>
          <div className="finding-strip">
            {detail.findings.map((finding) => (
              <article key={finding.id}><strong>{finding.severity}</strong><span>{finding.category}</span><p>{finding.title}</p></article>
            ))}
          </div>
          <div className="evidence-list">
            {executions.map((execution, index) => (
              <article className="evidence" key={execution.id}>
                <div className="evidence-head">
                  <strong>Prompt {index + 1}</strong>
                  <StatusBadge status={execution.success ? "confirmed" : "blocked"} />
                  <span>confidence {Math.round(execution.confidence * 100)}%</span>
                </div>
                <pre>{execution.prompt}</pre>
                <pre>{execution.response || "[no response text]"}</pre>
                <div className="telemetry">
                  <span>retrieval {execution.retrieval_trace.length}</span>
                  <span>tools {execution.tool_trace.length}</span>
                  <span>authorization {execution.authorization_trace.length}</span>
                </div>
              </article>
            ))}
          </div>
        </>
      )}
    </section>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
