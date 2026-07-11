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

type AssessmentSummary = {
  id: string;
  assessment_type: "native" | "multi_framework";
  friendly_name: string;
  target_id?: string;
  target_name: string;
  target_type?: string;
  model_name?: string;
  organization?: string;
  environment?: string;
  status: string;
  mode: string;
  frameworks: string[];
  framework_count: number;
  evidence_count: number;
  finding_count: number;
  confirmed_count: number;
  candidate_count: number;
  completed_at: string;
  error_count: number;
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
  const [frameworkAssessments, setFrameworkAssessments] = useState<any[]>([]);
  const [reports, setReports] = useState<any[]>([]);
  const [frameworks, setFrameworks] = useState<any[]>([]);
  const [frameworkCapabilities, setFrameworkCapabilities] = useState<Record<string, any>>({});
  const [selectedTargetId, setSelectedTargetId] = useState("");
  const [selectedAssessmentId, setSelectedAssessmentId] = useState("");
  const [detail, setDetail] = useState<any | null>(null);
  const [form, setForm] = useState(blankForm);
  const [notice, setNotice] = useState("");
  const [dataErrors, setDataErrors] = useState<Record<string, string>>({});
  const [loadingSections, setLoadingSections] = useState<Record<string, boolean>>({});
  const [busy, setBusy] = useState(false);

  async function api(path: string, options?: RequestInit) {
    try {
      const response = await fetch(`${API}${path}`, {
        ...options,
        headers: { "Content-Type": "application/json", ...(options?.headers || {}) },
      });
      const text = await response.text();
      let payload: any = null;
      if (text) {
        try {
          payload = JSON.parse(text);
        } catch {
          payload = text;
        }
      }
      if (!response.ok) {
        const message = typeof payload === "string" ? payload : payload?.detail || payload?.message || response.statusText;
        throw new Error(`HTTP ${response.status} from ${path}: ${message}`);
      }
      return payload ?? {};
    } catch (error: any) {
      if (error instanceof TypeError) {
        throw new Error(`Connection failure for ${path}. Check that the API is running at ${API}.`);
      }
      throw error;
    }
  }

  async function refresh() {
    setLoadingSections({ health: true, targets: true, assessments: true, frameworkAssessments: true, reports: true, frameworks: true });
    const results = await Promise.allSettled([
      api("/health"),
      api("/api/targets"),
      api("/api/assessments"),
      api("/api/assessments/frameworks"),
      api("/api/reports"),
      api("/api/frameworks"),
    ]);
    const errors: Record<string, string> = {};
    const [healthResult, targetResult, assessmentResult, frameworkAssessmentResult, reportResult, frameworkResult] = results;

    if (healthResult.status === "fulfilled") setHealth(healthResult.value);
    else errors.health = healthResult.reason.message;

    if (targetResult.status === "fulfilled") {
      const targetData = targetResult.value;
      setTargets(targetData.targets || []);
      const firstTarget = targetData.targets?.[0]?.id || "";
      setSelectedTargetId((current) => current || firstTarget);
    } else {
      errors.targets = targetResult.reason.message;
    }

    if (assessmentResult.status === "fulfilled") setAssessments(assessmentResult.value.assessments || []);
    else errors.assessments = assessmentResult.reason.message;

    if (frameworkAssessmentResult.status === "fulfilled") setFrameworkAssessments(frameworkAssessmentResult.value.assessments || []);
    else errors.frameworkAssessments = frameworkAssessmentResult.reason.message;

    if (reportResult.status === "fulfilled") setReports(reportResult.value.reports || []);
    else errors.reports = reportResult.reason.message;

    if (frameworkResult.status === "fulfilled") setFrameworks(frameworkResult.value.frameworks || []);
    else errors.frameworks = frameworkResult.reason.message;

    setDataErrors(errors);
    setLoadingSections({});
    const firstAssessment = normalizeAssessments(
      assessmentResult.status === "fulfilled" ? assessmentResult.value.assessments || [] : assessments,
      frameworkAssessmentResult.status === "fulfilled" ? frameworkAssessmentResult.value.assessments || [] : frameworkAssessments,
      targetResult.status === "fulfilled" ? targetResult.value.targets || [] : targets,
    )[0]?.id || "";
    setSelectedAssessmentId((current) => current || firstAssessment);
  }

  async function loadAssessment(id: string) {
    if (!id) return;
    const endpoint = id.startsWith("MFASM-") ? `/api/assessments/frameworks/${id}` : `/api/assessments/${id}`;
    const data = await api(endpoint);
    setDetail(data);
  }

  async function runAction(label: string, action: () => Promise<void>, options: { refreshAfter?: boolean } = {}) {
    setBusy(true);
    setNotice(`${label} started.`);
    try {
      await action();
      setNotice(`${label} completed.`);
      if (options.refreshAfter !== false) await refresh();
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
      const frameworkData = await api("/api/frameworks");
      setFrameworks(frameworkData.frameworks || []);
    }, { refreshAfter: false });
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

  function openIsoEvidence(mapping: any) {
    const finding = detail?.findings?.find((item: any) => item.id === mapping.finding_id);
    const executionId = finding?.related_executions?.[0];
    setView("evidence");
    window.setTimeout(() => {
      const element = document.getElementById(executionId || mapping.finding_id);
      element?.scrollIntoView({ behavior: "smooth", block: "start" });
      if (element) window.history.replaceState(null, "", `#${element.id}`);
    }, 80);
  }

  useEffect(() => {
    refresh().catch((error) => setNotice(error.message));
  }, []);

  useEffect(() => {
    loadAssessment(selectedAssessmentId).catch((error) => setDataErrors((current) => ({ ...current, detail: error.message })));
  }, [selectedAssessmentId]);

  const selectedTarget = useMemo(() => targets.find((target) => target.id === selectedTargetId), [targets, selectedTargetId]);
  const assessmentRows = useMemo(() => normalizeAssessments(assessments, frameworkAssessments, targets), [assessments, frameworkAssessments, targets]);
  const totalFindings = assessmentRows.reduce((sum, assessment) => sum + assessment.finding_count, 0);
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
        <ErrorSummary errors={dataErrors} />

        {view === "dashboard" && (
          <>
            <div className="metrics">
              <Metric icon={<ShieldCheck />} label="API health" value={loadingSections.health ? "loading" : health?.status || "unavailable"} />
              <Metric icon={<ServerCog />} label="Registered targets" value={targets.length} />
              <Metric icon={<SearchCheck />} label="Enabled targets" value={enabledTargets} />
              <Metric icon={<TriangleAlert />} label="Total findings" value={totalFindings} />
            </div>
            <section className="panel split">
              <div>
                <p className="eyebrow">Readiness</p>
                <h2>Framework and adapter state</h2>
                <div className="cards compact">
                  {loadingSections.health && <div className="empty">Loading adapter and framework health...</div>}
                  {!loadingSections.health && !health && <div className="empty">API health is unavailable. Check the API container, then refresh.</div>}
                  {health && Object.entries(health.adapters).map(([name, value]) => (
                    <article className="card" key={name}>
                      <strong>{name}</strong>
                      <StatusBadge status={value.status} />
                      <span>{value.version || "version pending"}</span>
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
            <PanelTitle icon={<Activity />} title="Assessments" subtitle="Native and multi-framework runs, normalized for review." />
            <div className="table">
              <div className="row head"><span>Run</span><span>Target</span><span>Status</span><span>Evidence</span><span>Completed</span></div>
              {loadingSections.assessments && <div className="empty">Loading assessment history...</div>}
              {!loadingSections.assessments && assessmentRows.length === 0 && <div className="empty">No assessments have been run yet.</div>}
              {assessmentRows.map((assessment) => (
                <button className="row clickable" key={assessment.id} onClick={() => setSelectedAssessmentId(assessment.id)}>
                  <span><strong>{assessment.friendly_name}</strong><small>{assessment.id}</small></span>
                  <span>{assessment.target_name}<small>{assessment.model_name || assessment.target_type || "target metadata pending"}</small></span>
                  <span><StatusBadge status={assessment.status} /></span>
                  <span>{assessment.evidence_count} evidence / {assessment.finding_count} findings</span>
                  <span>{formatDate(assessment.completed_at)}</span>
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
              {loadingSections.frameworks && <div className="empty">Loading framework registry...</div>}
              {!loadingSections.frameworks && frameworks.length === 0 && <div className="empty">No framework workers are registered. Start the framework Docker profile and refresh.</div>}
              {frameworks.map((framework: any) => (
                <article className="card" key={framework.id}>
                  <strong>{framework.name}</strong>
                  <StatusBadge status={framework.health || "unknown"} />
                  <span>{framework.version || "version pending"}</span>
                  <span>{framework.enabled ? "enabled" : "disabled"}</span>
                  {framework.last_error && <details><summary>Technical details</summary><pre>{framework.last_error}</pre></details>}
                  <p>{capabilityNames(frameworkCapabilities[frameworkKey(framework)]).join(", ") || "Run capabilities check"}</p>
                </article>
              ))}
            </div>
            <div className="framework-runs">
              <h3>Recent multi-framework runs</h3>
              {frameworkAssessments.length === 0 && <div className="empty">No multi-framework runs yet.</div>}
              {frameworkAssessments.map((assessment) => (
                <button className="run-card" key={assessment.id} onClick={() => setSelectedAssessmentId(assessment.id)}>
                  <strong>{assessment.id}</strong>
                  <StatusBadge status={assessment.status} />
                  <span>{(assessment.frameworks || []).join(", ")}</span>
                  <span>{assessment.evidence || 0} evidence records</span>
                  <span>{assessment.errors || 0} errors</span>
                </button>
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
              {detail?.iso_mappings.map((mapping: any) => (
                <div className="row iso-row" key={mapping.id}>
                  <span><button className="textlink" onClick={() => openIsoEvidence(mapping)}>{mapping.finding_id}</button></span>
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
            {selectedAssessmentId?.startsWith("MFASM-") && <div className="empty">Multi-framework report export is not generated yet. Use the Evidence view for normalized framework evidence.</div>}
            {selectedAssessmentId && !selectedAssessmentId.startsWith("MFASM-") && (
              <div className="actions">
                <a className="buttonlike" href={`${API}/api/reports/${selectedAssessmentId}/markdown`} target="_blank">Markdown</a>
                <a className="buttonlike" href={`${API}/api/reports/${selectedAssessmentId}/html`} target="_blank">Professional HTML</a>
                <a className="buttonlike" href={`${API}/api/reports/${selectedAssessmentId}/json`} target="_blank">JSON</a>
                <a className="buttonlike" href={`${API}/api/reports/${selectedAssessmentId}/csv`} target="_blank">CSV</a>
              </div>
            )}
            <div className="table report-table">
              <div className="row report-head"><span>Report</span><span>Target</span><span>Findings</span><span>Completed</span><span>Open</span></div>
              {loadingSections.reports && <div className="empty">Loading previous reports...</div>}
              {!loadingSections.reports && reports.length === 0 && <div className="empty">No report artifacts are available yet.</div>}
              {reports.map((report) => (
                <div className="row report-row" key={report.id}>
                  <span><strong>{report.id}</strong><small>{report.mode}</small></span>
                  <span>{report.target || "Target"}</span>
                  <span>{report.findings || 0}</span>
                  <span>{formatDate(report.completed_at)}</span>
                  <span className="mini-actions">
                    <a href={`${API}/api/reports/${report.id}/html`} target="_blank">HTML</a>
                    <a href={`${API}/api/reports/${report.id}/markdown`} target="_blank">MD</a>
                    <a href={`${API}/api/reports/${report.id}/csv`} target="_blank">CSV</a>
                  </span>
                </div>
              ))}
            </div>
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
  const normalized = String(status || "unknown").toLowerCase();
  const good = ["ok", "healthy", "available", "enabled", "white_box", "grey_box", "black_box", "completed", "succeeded", "attack blocked", "control confirmed", "confirmed finding"].includes(normalized);
  return <span className={good ? "badge good" : "badge warn"}>{status}</span>;
}

function PanelTitle({ icon, title, subtitle }: { icon: React.ReactNode; title: string; subtitle: string }) {
  return <div className="panel-title">{icon}<div><h2>{title}</h2><p>{subtitle}</p></div></div>;
}

function ErrorSummary({ errors }: { errors: Record<string, string> }) {
  const entries = Object.entries(errors).filter(([, value]) => value);
  if (!entries.length) return null;
  return (
    <section className="error-panel">
      <strong>Some dashboard data could not load.</strong>
      <p>Healthy sections remain usable. Open technical details for the exact endpoint problem.</p>
      <details>
        <summary>Technical details</summary>
        <ul>
          {entries.map(([section, message]) => <li key={section}><strong>{section}</strong>: {message}</li>)}
        </ul>
      </details>
    </section>
  );
}

function normalizeAssessments(nativeRuns: Assessment[], frameworkRuns: any[], targets: Target[]): AssessmentSummary[] {
  const targetById = new Map(targets.map((target) => [target.id, target]));
  const native = nativeRuns.map((assessment) => ({
    id: assessment.id,
    assessment_type: "native" as const,
    friendly_name: "Native assessment",
    target_name: assessment.target || "Target",
    status: "completed",
    mode: assessment.mode,
    frameworks: ["native"],
    framework_count: 1,
    evidence_count: 0,
    finding_count: Number(assessment.findings || 0),
    confirmed_count: Number(assessment.findings || 0),
    candidate_count: 0,
    completed_at: assessment.completed_at,
    error_count: 0,
  }));
  const framework = frameworkRuns.map((assessment) => {
    const target = targetById.get(assessment.target_id);
    return {
      id: assessment.id,
      assessment_type: "multi_framework" as const,
      friendly_name: "Multi-framework assessment",
      target_id: assessment.target_id,
      target_name: target?.target_name || assessment.target_id || "Target",
      target_type: target?.target_type,
      model_name: target?.model_name,
      organization: target?.organization,
      environment: target?.environment,
      status: assessment.status || "unknown",
      mode: "authorized",
      frameworks: assessment.frameworks || [],
      framework_count: (assessment.frameworks || []).length,
      evidence_count: Number(assessment.evidence || 0),
      finding_count: Number(assessment.findings || 0),
      confirmed_count: Number(assessment.confirmed || 0),
      candidate_count: Number(assessment.candidates || 0),
      completed_at: assessment.completed_at || "",
      error_count: Number(assessment.errors || 0),
    };
  });
  return [...framework, ...native].sort((a, b) => String(b.completed_at).localeCompare(String(a.completed_at)));
}

function frameworkKey(framework: any) {
  return String(framework?.id || framework?.framework || framework?.name || "").toLowerCase();
}

function capabilityNames(entry: any): string[] {
  const items = Array.isArray(entry?.capabilities) ? entry.capabilities : [];
  return items
    .filter((item: any) => typeof item === "string" || item.supported !== false)
    .map((item: any) => typeof item === "string" ? item : item.name || item.detail)
    .filter(Boolean);
}

function formatDate(value: string | null | undefined) {
  if (!value) return "not completed";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function evidenceStatus(record: any) {
  const raw = String(record.status || record.outcome || record.result || "").toLowerCase();
  if (raw.includes("confirmed")) return "Confirmed finding";
  if (raw.includes("candidate")) return "Candidate finding";
  if (raw.includes("blocked")) return "Attack blocked";
  if (raw.includes("success") || record.success === true || record.attack_succeeded === true) return "Attack succeeded";
  if (record.error) return "Framework error";
  return "Test inconclusive";
}

function evidenceText(record: any, keys: string[]) {
  for (const key of keys) {
    const value = record?.[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return "";
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

function EvidenceView({ detail, executions }: { detail: any | null; executions: AssessmentDetail["executions"] }) {
  const normalizedEvidence = detail?.normalized_evidence || [];
  const frameworkSummaries = detail?.framework_summaries || [];
  return (
    <section className="panel">
      <PanelTitle icon={<ClipboardCheck />} title="Evidence Transcript" subtitle="Prompt, response, framework result, telemetry, and confidence from the selected assessment." />
      {!detail && <div className="empty">Select or run an assessment to view evidence.</div>}
      {detail && (
        <>
          {detail.assessment_type === "multi_framework" && (
            <div className="summary-band">
              <article><strong>{detail.status}</strong><span>Run status</span></article>
              <article><strong>{frameworkSummaries.length}</strong><span>Frameworks</span></article>
              <article><strong>{normalizedEvidence.length}</strong><span>Evidence records</span></article>
              <article><strong>{detail.errors?.length || 0}</strong><span>Errors</span></article>
            </div>
          )}
          {frameworkSummaries.length > 0 && (
            <div className="cards compact">
              {frameworkSummaries.map((summary: any) => (
                <article className="card" key={summary.framework}>
                  <strong>{summary.framework}</strong>
                  <StatusBadge status={summary.status || "completed"} />
                  <span>{summary.evidence_count || 0} evidence records</span>
                  <span>{summary.confirmed_count || 0} confirmed / {summary.candidate_count || 0} candidate</span>
                  <span>{summary.error_count || 0} errors</span>
                </article>
              ))}
            </div>
          )}
          <div className="finding-strip">
            {(detail.findings || []).map((finding: any) => (
              <article id={finding.id} key={finding.id}><strong>{finding.severity}</strong><span>{finding.category}</span><p>{finding.title}</p></article>
            ))}
            {!(detail.findings || []).length && normalizedEvidence.length > 0 && (
              <article><strong>Evidence captured</strong><span>Human review needed</span><p>No confirmed findings are stored yet. Review framework evidence and map findings manually.</p></article>
            )}
          </div>
          <div className="evidence-list">
            {executions.map((execution, index) => (
              <article className="evidence" id={execution.id} key={execution.id}>
                <div className="evidence-head">
                  <strong>Prompt {index + 1}</strong>
                  <StatusBadge status={evidenceStatus(execution)} />
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
            {normalizedEvidence.map((record: any, index: number) => {
              const prompt = evidenceText(record, ["prompt", "input", "attack_prompt", "payload", "test_case"]);
              const response = evidenceText(record, ["response", "output", "model_response", "actual_output"]);
              return (
                <article className="evidence" id={record.id || record.evidence_id || `framework-evidence-${index}`} key={record.id || record.evidence_id || index}>
                  <div className="evidence-head">
                    <strong>{record.framework || record.source || "Framework"} evidence {index + 1}</strong>
                    <StatusBadge status={evidenceStatus(record)} />
                    {record.risk_category && <span>{record.risk_category}</span>}
                  </div>
                  <pre>{prompt || "[prompt not provided by worker artifact]"}</pre>
                  <pre>{response || "[response not provided by worker artifact]"}</pre>
                  <details>
                    <summary>Technical details</summary>
                    <pre>{JSON.stringify(record, null, 2)}</pre>
                  </details>
                </article>
              );
            })}
          </div>
        </>
      )}
    </section>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
