import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { Activity, FileText, ShieldCheck, TriangleAlert } from "lucide-react";
import "./styles.css";

const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8080";

type Assessment = {
  id: string;
  target: string;
  mode: string;
  findings: number;
  completed_at: string;
};

function App() {
  const [health, setHealth] = useState<any>(null);
  const [assessments, setAssessments] = useState<Assessment[]>([]);
  const [running, setRunning] = useState(false);

  async function refresh() {
    const [healthRes, assessmentRes] = await Promise.all([
      fetch(`${API}/health`),
      fetch(`${API}/api/assessments`),
    ]);
    setHealth(await healthRes.json());
    setAssessments((await assessmentRes.json()).assessments || []);
  }

  async function run(mode: "vulnerable" | "hardened") {
    setRunning(true);
    try {
      await fetch(`${API}/api/assessments/demo`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ mode }),
      });
      await refresh();
    } finally {
      setRunning(false);
    }
  }

  useEffect(() => {
    refresh().catch(console.error);
  }, []);

  const totalFindings = assessments.reduce((sum, item) => sum + item.findings, 0);

  return (
    <main>
      <aside>
        <div className="brand">AI ISO</div>
        <a>Executive</a>
        <a>Systems</a>
        <a>Assessments</a>
        <a>Findings</a>
        <a>ISO Evidence</a>
        <a>Reports</a>
      </aside>
      <section className="workspace">
        <header>
          <div>
            <p className="eyebrow">Authorized laboratory assessment</p>
            <h1>AI Security Assessment and ISO/IEC 42001 Assurance Platform</h1>
            <p>
              Run controlled attacks against EnterpriseAssist, collect evidence, and map technical observations to ISO/IEC
              42001 assurance candidates without claiming certification.
            </p>
          </div>
        </header>

        <div className="metrics">
          <article><ShieldCheck /><strong>{health?.status || "loading"}</strong><span>API health</span></article>
          <article><Activity /><strong>{assessments.length}</strong><span>Assessments</span></article>
          <article><TriangleAlert /><strong>{totalFindings}</strong><span>Findings</span></article>
          <article><FileText /><strong>4</strong><span>Report formats</span></article>
        </div>

        <section className="panel">
          <div className="panel-head">
            <div>
              <p className="eyebrow">Demo workflow</p>
              <h2>EnterpriseAssist Controlled Assessment</h2>
            </div>
            <div className="actions">
              <button onClick={() => run("vulnerable")} disabled={running}>Run Vulnerable</button>
              <button onClick={() => run("hardened")} disabled={running}>Run Hardened</button>
              <button className="secondary" onClick={refresh}>Refresh</button>
            </div>
          </div>
          <div className="table">
            <div className="row head"><span>ID</span><span>Target</span><span>Mode</span><span>Findings</span><span>Report</span></div>
            {assessments.map((assessment) => (
              <div className="row" key={assessment.id}>
                <span>{assessment.id}</span>
                <span>{assessment.target}</span>
                <span>{assessment.mode}</span>
                <span>{assessment.findings}</span>
                <a href={`${API}/api/reports/${assessment.id}/markdown`} target="_blank">Markdown</a>
              </div>
            ))}
          </div>
        </section>

        <section className="panel">
          <p className="eyebrow">Adapter health</p>
          <div className="cards">
            {health && Object.entries(health.adapters).map(([name, value]: any) => (
              <article className="card" key={name}>
                <strong>{name}</strong>
                <span>{value.status}</span>
              </article>
            ))}
          </div>
        </section>
      </section>
    </main>
  );
}

createRoot(document.getElementById("root")!).render(<App />);
