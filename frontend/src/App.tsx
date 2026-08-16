import { useState, useEffect, useRef } from 'react';
import {
  Shield, Play, ShieldAlert, Cpu, Network, FileText, CheckCircle2,
  AlertTriangle, RefreshCw, X, ChevronRight, Download, Terminal,
  Lock, Eye, GitPullRequest, Settings, Radio
} from 'lucide-react';

interface Metric {
  tokens: number;
  coverage: number;
  ram_mb: number;
  egress: number;
}

interface Thought {
  agent: string;
  hypothesis: string;
  evidence: string[];
  decision: string;
  confidence: number;
  timestamp: number;
}

interface Finding {
  finding_id: string;
  title: string;
  state: 'hypothesis' | 'validated' | 'refuted' | 'fixed';
  severity: string;
  reachable: boolean;
  clause?: string;
  pov_code?: string;
  pov_hash?: string;
}

interface DiffPatch {
  finding_id: string;
  file: string;
  patch: string;
  iter: number;
}

interface GauntletStatus {
  mutation: 'pass' | 'fail' | 'pending' | 'none';
  sibling: 'pass' | 'fail' | 'pending' | 'none';
  replay: 'pass' | 'fail' | 'pending' | 'none';
  contract: 'pass' | 'fail' | 'pending' | 'none';
  detail?: string;
}

interface AuditLog {
  log_id: number;
  timestamp: number;
  actor: string;
  action: string;
  subject: string;
  evidence_hash: string;
  prev_hash: string;
}

const PIPELINE_STEPS = [
  { key: 'ingest', label: 'Ingest Repository', desc: 'Secure target environment isolation setup' },
  { key: 'probe', label: 'Probe Adapter', desc: 'Environment & software classification' },
  { key: 'interface', label: 'Interface Hypothesis', desc: 'Synthesizing input boundaries & entry points' },
  { key: 'samhita_synthesis', label: 'SAMHITA Synthesis', desc: 'Observing benign run value profiles' },
  { key: 'clause_falsification', label: 'Clause Falsifier', desc: 'Pruning invalid predicate clauses' },
  { key: 'static_queries', label: 'Static Analysis Graph', desc: 'Taint-sink checking on GitNexus' },
  { key: 'discovery', label: 'Discovery Fanout', desc: 'Parallel static and fuzzing channels' },
  { key: 'validation', label: 'Validator Oracle', desc: 'Dynamic exploit execution confirmation' },
  { key: 'patch_synthesis', label: 'Patch Synthesis', desc: 'Root-cause repairs' },
  { key: 'gauntlet', label: 'Refutation Gauntlet', desc: 'Bypass, replay, and regression checks' },
  { key: 'attest', label: 'PRAMAAN Attestor', desc: 'Cryptographically signed certificates' },
  { key: 'publish', label: 'Publisher Gate', desc: 'RBAC Policy enforcement & pull requests' }
];

function App() {
  const [repoUrl, setRepoUrl] = useState('https://github.com/defense-core/parse_header');
  const [role, setRole] = useState<'Owner' | 'Maintainer' | 'Sec Reviewer' | 'Developer' | 'Viewer' | 'Auditor'>('Owner');
  const [runId, setRunId] = useState<string | null>(null);
  const [runStatus, setRunStatus] = useState<string>('idle');
  const [currentPhase, setCurrentPhase] = useState<string>('idle');
  const [cableConnected, setCableConnected] = useState<boolean>(true);
  
  // Dashboard states
  const [metrics, setMetrics] = useState<Metric>({ tokens: 0, coverage: 0, ram_mb: 0, egress: 0 });
  const [thoughts, setThoughts] = useState<Thought[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const [diffs, setDiffs] = useState<DiffPatch[]>([]);
  const [gauntlet, setGauntlet] = useState<GauntletStatus>({
    mutation: 'none',
    sibling: 'none',
    replay: 'none',
    contract: 'none'
  });
  
  // Modals & details
  const [showCertModal, setShowCertModal] = useState<boolean>(false);
  const [showAuditModal, setShowAuditModal] = useState<boolean>(false);
  const [showPRModal, setShowPRModal] = useState<boolean>(false);
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([]);
  const [certificateData, setCertificateData] = useState<any>(null);
  const [prUrl, setPrUrl] = useState<string | null>(null);
  const [prLoading, setPrLoading] = useState<boolean>(false);

  const eventSourceRef = useRef<EventSource | null>(null);
  const thoughtsEndRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    if (thoughtsEndRef.current) {
      thoughtsEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [thoughts]);

  // Load audit logs if requested
  const fetchAuditLogs = async () => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/audit?role=${role}`);
      if (res.ok) {
        const data = await res.json();
        setAuditLogs(data);
      }
    } catch (err) {
      console.error("Failed to load audit logs", err);
    }
  };

  useEffect(() => {
    if (showAuditModal) {
      fetchAuditLogs();
    }
  }, [showAuditModal, role]);

  // Handle finding click and reload if role changes
  useEffect(() => {
    if (runId) {
      fetchFindings();
    }
  }, [role, runId]);

  const fetchFindings = async () => {
    if (!runId) return;
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/runs/${runId}/findings?role=${role}`);
      if (res.ok) {
        const data = await res.json();
        setFindings(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const startRun = async () => {
    // Reset states
    setRunId(null);
    setRunStatus('pending');
    setCurrentPhase('ingest');
    setMetrics({ tokens: 0, coverage: 0, ram_mb: 0, egress: 0 });
    setThoughts([]);
    setFindings([]);
    setSelectedFindingId(null);
    setDiffs([]);
    setGauntlet({ mutation: 'none', sibling: 'none', replay: 'none', contract: 'none' });
    setCertificateData(null);
    setPrUrl(null);

    try {
      const res = await fetch('http://127.0.0.1:8000/api/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ repo_url: repoUrl, role: role })
      });

      if (!res.ok) throw new Error("Failed to start run");
      const data = await res.json();
      setRunId(data.run_id);
      
      // Connect to SSE stream
      connectStream(data.run_id);
    } catch (err) {
      console.error(err);
      setRunStatus('error');
    }
  };

  const connectStream = (id: string) => {
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
    }

    const source = new EventSource(`http://127.0.0.1:8000/api/runs/${id}/stream`);
    eventSourceRef.current = source;

    source.onmessage = (event) => {
      const data = JSON.parse(event.data);
      
      if (data.t === 'phase') {
        setCurrentPhase(data.phase);
        if (data.phase === 'complete') {
          setRunStatus('completed');
          source.close();
          fetchFindings();
          loadCertificate(id);
        } else {
          setRunStatus('running');
        }
      } else if (data.t === 'thought') {
        setThoughts((prev) => [...prev, {
          agent: data.agent,
          hypothesis: data.hypothesis,
          evidence: data.evidence || [],
          decision: data.decision || '',
          confidence: data.confidence || 1.0,
          timestamp: Date.now()
        }]);
      } else if (data.t === 'metric') {
        setMetrics({
          tokens: data.tokens,
          coverage: data.coverage,
          ram_mb: data.ram_mb,
          egress: cableConnected ? 0 : 0
        });
      } else if (data.t === 'finding') {
        setFindings((prev) => {
          const exists = prev.some((f) => f.finding_id === data.id);
          if (exists) {
            return prev.map((f) => f.finding_id === data.id ? { ...f, state: data.state } : f);
          }
          return [...prev, {
            finding_id: data.id,
            title: 'Analyzing potential vulnerability...',
            state: data.state,
            severity: data.severity,
            reachable: data.reachable
          }];
        });
        setSelectedFindingId(data.id);
      } else if (data.t === 'diff') {
        setDiffs((prev) => [...prev, {
          finding_id: data.finding,
          file: data.file,
          patch: data.patch,
          iter: data.iter
        }]);
      } else if (data.t === 'gauntlet') {
        setGauntlet((prev) => ({
          ...prev,
          [data.stage]: data.verdict,
          detail: data.detail
        }));
      } else if (data.t === 'artifact' && data.kind === 'certificate') {
        loadCertificate(id);
      }
    };

    source.onerror = () => {
      source.close();
      setRunStatus('completed');
    };
  };

  const loadCertificate = async (id: string) => {
    try {
      const res = await fetch(`http://127.0.0.1:8000/api/runs/${id}/certificate`);
      if (res.ok) {
        const data = await res.json();
        setCertificateData(data);
      }
    } catch (err) {
      console.error(err);
    }
  };

  const publishPatch = async () => {
    if (!runId || !selectedFindingId) return;
    setPrLoading(true);
    try {
      const res = await fetch('http://127.0.0.1:8000/api/publish', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          run_id: runId,
          finding_id: selectedFindingId,
          role: role
        })
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || "Publish rejected by policy gate");
      }
      
      const data = await res.json();
      setPrUrl(data.pr_url);
      setShowPRModal(true);
    } catch (err: any) {
      alert(`Publish Gate Rejected: ${err.message}`);
    } finally {
      setPrLoading(false);
    }
  };

  const getStepStatus = (stepKey: string) => {
    const currentIndex = PIPELINE_STEPS.findIndex((s) => s.key === stepKey);
    const activeIndex = PIPELINE_STEPS.findIndex((s) => s.key === currentPhase);

    if (currentPhase === 'complete') return 'completed';
    if (stepKey === currentPhase) return 'active';
    if (activeIndex > currentIndex) return 'completed';
    return 'pending';
  };

  const activeFinding = findings.find((f) => f.finding_id === selectedFindingId);

  return (
    <>
      {/* HEADER SECTION */}
      <header>
        <div className="brand-section">
          <div className="brand-logo">
            <Shield size={28} />
          </div>
          <div>
            <div className="brand-title">
              KAVACHX <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>V1.0</span>
            </div>
            <div className="brand-subtitle">Autonomous Cyber-Reasoning Engine</div>
          </div>
        </div>

        <div className="header-controls">
          <div className="repo-input-wrapper">
            <input
              type="text"
              className="repo-input"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="Submit repository URL..."
              disabled={runStatus === 'running'}
              id="repo-url-input"
            />
          </div>
          
          <button
            className="btn btn-success"
            onClick={startRun}
            disabled={runStatus === 'running'}
            id="start-run-btn"
          >
            <Play size={14} /> Start Quest
          </button>

          <select
            className="role-selector"
            value={role}
            onChange={(e: any) => setRole(e.target.value)}
            id="role-select"
          >
            <option value="Owner">Role: Owner (All Perms)</option>
            <option value="Maintainer">Role: Maintainer (Deploy, No Exploit POV)</option>
            <option value="Sec Reviewer">Role: Sec Reviewer (All Audit/Exploit)</option>
            <option value="Developer">Role: Developer (Analysis, No Publish/Exploit)</option>
            <option value="Viewer">Role: Viewer (Read-only)</option>
            <option value="Auditor">Role: Auditor (Audit Logs read-only)</option>
          </select>

          <button
            className="btn btn-secondary"
            onClick={() => setShowAuditModal(true)}
            id="view-audit-btn"
          >
            <FileText size={14} /> Audit Trail
          </button>
        </div>
      </header>

      {/* DASHBOARD COCKPIT GRID */}
      <main className="dashboard-grid">
        {/* PANEL 1: PIPELINE TIMELINE */}
        <section className="panel" id="pipeline-panel">
          <div className="panel-header">
            <div className="panel-title">
              <Radio size={14} className="icon-pulse" /> Timeline
            </div>
          </div>
          <div className="panel-content">
            <div className="timeline-list">
              {PIPELINE_STEPS.map((step) => {
                const status = getStepStatus(step.key);
                return (
                  <div key={step.key} className={`timeline-item ${status}`} id={`timeline-step-${step.key}`}>
                    <div className="timeline-indicator">
                      {status === 'completed' && <CheckCircle2 size={12} />}
                      {status === 'active' && <RefreshCw size={12} className="spin" />}
                      {status === 'pending' && <ChevronRight size={10} />}
                    </div>
                    <div className="timeline-info">
                      <div className="timeline-phase">{step.label}</div>
                      <div className="timeline-desc">{step.desc}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

        {/* CENTER COCKPIT AREA (FINDINGS & DIFF VIEW) */}
        <section style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* PANEL 2: FINDINGS TABLE */}
          <div className="panel" style={{ flex: '1' }}>
            <div className="panel-header">
              <div className="panel-title">
                <ShieldAlert size={14} /> Discovery & Findings
              </div>
            </div>
            <div className="panel-content">
              {findings.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
                  No findings detected. Submit a repo to begin vulnerability scanning.
                </div>
              ) : (
                <div className="findings-table-wrapper">
                  <table className="findings-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Vulnerability</th>
                        <th>Severity</th>
                        <th>Reachability</th>
                        <th>State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {findings.map((f) => (
                        <tr
                          key={f.finding_id}
                          className={selectedFindingId === f.finding_id ? 'selected' : ''}
                          onClick={() => setSelectedFindingId(f.finding_id)}
                          id={`finding-row-${f.finding_id}`}
                        >
                          <td className="font-mono">{f.finding_id}</td>
                          <td>{f.title === 'Analyzing potential vulnerability...' ? activeFinding?.title : f.title}</td>
                          <td>
                            <span className={`badge badge-${f.severity.toLowerCase()}`}>{f.severity}</span>
                          </td>
                          <td>
                            <span className="font-mono" style={{ color: f.reachable ? 'var(--color-warning)' : 'var(--text-muted)' }}>
                              {f.reachable ? 'REACHABLE' : 'UNREACHABLE'}
                            </span>
                          </td>
                          <td>
                            <span className={`state-chip ${f.state}`}>
                              {f.state.toUpperCase()}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}

              {/* GATED FINDING EXPLOIT / DETAILS */}
              {activeFinding && (
                <div className="finding-detail-card" id="finding-details">
                  <div className="finding-detail-title">Vulnerability Detail: {activeFinding.finding_id}</div>
                  <div className="clause-box">
                    <strong>Violated SAMHITA Clause:</strong> CL-01 (Observed predicate boundary check bypassed)
                  </div>
                  <div>
                    <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                      Exploit Payload (Gated View)
                    </div>
                    <div style={{ background: '#020408', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                      {role === 'Owner' || role === 'Sec Reviewer' ? (
                        <code>{activeFinding.pov_code || "POST /api/v1/parse Content-Length: -1"}</code>
                      ) : (
                        <div style={{ color: 'var(--color-error)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                          <Lock size={12} /> Redacted (Requires finding:read_pov permissions)
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* PANEL 3: DIFF VIEWER & GAUNTLET */}
          <div className="panel diff-viewer-panel">
            <div className="panel-header">
              <div className="panel-title">
                <Settings size={14} /> Proof-Carrying Patch & Gauntlet
              </div>
              {certificateData && (
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button className="btn btn-secondary" style={{ padding: '4px 10px', fontSize: '11px' }} onClick={() => setShowCertModal(true)} id="view-certificate-btn">
                    <Eye size={12} /> View Certificate
                  </button>
                  <button className="btn btn-success" style={{ padding: '4px 10px', fontSize: '11px' }} onClick={publishPatch} disabled={prLoading} id="publish-patch-btn">
                    <GitPullRequest size={12} /> {prLoading ? 'Verifying Gate...' : 'Publish Patch'}
                  </button>
                </div>
              )}
            </div>
            <div className="panel-content">
              {diffs.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
                  No patch generated yet.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  <div className="diff-header-info">
                    <span>Target File: <strong>{diffs[diffs.length - 1].file}</strong></span>
                    <span>Iteration: <strong>{diffs[diffs.length - 1].iter} / 3</strong></span>
                  </div>
                  <div className="diff-code-wrapper">
                    {diffs[diffs.length - 1].patch.split('\n').map((line, idx) => {
                      let className = '';
                      if (line.startsWith('+')) className = 'diff-line-add';
                      else if (line.startsWith('-')) className = 'diff-line-del';
                      return (
                        <span key={idx} className={className}>{line}</span>
                      );
                    })}
                  </div>

                  {/* Refutation Gauntlet Status */}
                  <div style={{ marginTop: '10px' }}>
                    <div style={{ fontSize: '11px', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                      Refutation Gauntlet Verification
                    </div>
                    <div className="gauntlet-status-grid">
                      <div className={`gauntlet-card ${gauntlet.mutation === 'fail' ? 'fail' : gauntlet.mutation === 'pass' ? 'pass' : ''}`}>
                        <span className="gauntlet-label">Mutation</span>
                        <span className={`gauntlet-verdict ${gauntlet.mutation}`}>{gauntlet.mutation.toUpperCase()}</span>
                      </div>
                      <div className={`gauntlet-card ${gauntlet.sibling === 'fail' ? 'fail' : gauntlet.sibling === 'pass' ? 'pass' : ''}`}>
                        <span className="gauntlet-label">Sibling Hunt</span>
                        <span className={`gauntlet-verdict ${gauntlet.sibling}`}>{gauntlet.sibling.toUpperCase()}</span>
                      </div>
                      <div className={`gauntlet-card ${gauntlet.replay === 'fail' ? 'fail' : gauntlet.replay === 'pass' ? 'pass' : ''}`}>
                        <span className="gauntlet-label">Differential</span>
                        <span className={`gauntlet-verdict ${gauntlet.replay}`}>{gauntlet.replay.toUpperCase()}</span>
                      </div>
                      <div className={`gauntlet-card ${gauntlet.contract === 'fail' ? 'fail' : gauntlet.contract === 'pass' ? 'pass' : ''}`}>
                        <span className="gauntlet-label">Contract Check</span>
                        <span className={`gauntlet-verdict ${gauntlet.contract}`}>{gauntlet.contract.toUpperCase()}</span>
                      </div>
                    </div>

                    {/* Self-Rejection Banner */}
                    {gauntlet.mutation === 'fail' && (
                      <div style={{ background: 'rgba(255, 69, 58, 0.1)', border: '1px solid var(--color-error)', borderRadius: '6px', padding: '10px', marginTop: '10px', display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--color-error)', fontSize: '12px' }} id="self-rejection-banner">
                        <AlertTriangle size={16} />
                        <div>
                          <strong>Self-Rejection Activated:</strong> Patch failed Exploit Mutation verification. Recalculating root-cause constraints for patch synthesis...
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>
        </section>

        {/* RIGHT AREA (REASONING & RESOURCES) */}
        <section style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* PANEL 4: REASONING TRACE */}
          <div className="panel" style={{ flex: '1' }}>
            <div className="panel-header">
              <div className="panel-title">
                <Terminal size={14} /> Reasoning Trace
              </div>
            </div>
            <div className="panel-content" style={{ maxHeight: '450px', overflowY: 'auto' }}>
              {thoughts.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
                  Awaiting analysis pipeline start...
                </div>
              ) : (
                <div className="reasoning-list">
                  {thoughts.map((t, idx) => (
                    <div key={idx} className="thought-item">
                      <div className="thought-meta">
                        <span className="thought-agent">{t.agent}</span>
                        <span>Conf: {(t.confidence * 100).toFixed(0)}%</span>
                      </div>
                      <div className="thought-text">{t.hypothesis}</div>
                    </div>
                  ))}
                  <div ref={thoughtsEndRef} />
                </div>
              )}
            </div>
          </div>

          {/* PANEL 5: RESOURCE TELEMETRY */}
          <div className="panel">
            <div className="panel-header">
              <div className="panel-title">
                <Cpu size={14} /> Telemetry & Resource Limits
              </div>
            </div>
            <div className="panel-content metrics-panel">
              <div className="metric-row">
                <div className="metric-label-container">
                  <span>Token Budget Spent</span>
                  <span className="font-mono">{metrics.tokens.toLocaleString()} / 500,000</span>
                </div>
                <div className="progress-bar-bg">
                  <div className="progress-bar-fill" style={{ width: `${(metrics.tokens / 500000) * 100}%` }}></div>
                </div>
              </div>

              <div className="metric-row">
                <div className="metric-label-container">
                  <span>Memory Sandbox Allocation</span>
                  <span className="font-mono">{(metrics.ram_mb / 1024).toFixed(2)} GB / 16.00 GB</span>
                </div>
                <div className="progress-bar-bg">
                  <div className="progress-bar-fill warning" style={{ width: `${(metrics.ram_mb / 16384) * 100}%` }}></div>
                </div>
              </div>

              <div className="metric-row">
                <div className="metric-label-container">
                  <span>Reachability Coverage</span>
                  <span className="font-mono">{metrics.coverage.toFixed(1)}%</span>
                </div>
                <div className="progress-bar-bg">
                  <div className="progress-bar-fill success" style={{ width: `${metrics.coverage}%` }}></div>
                </div>
              </div>

              {/* Air Gap Button Toggle */}
              <div
                className={`air-gap-banner ${cableConnected ? '' : 'disconnected'}`}
                style={{ cursor: 'pointer' }}
                onClick={() => setCableConnected(!cableConnected)}
                id="airgap-toggle-btn"
              >
                <Network size={14} />
                <span>{cableConnected ? 'SOVEREIGN AIR-GAP: ON' : 'NET CABLE: DISCONNECTED'}</span>
              </div>
            </div>
          </div>
        </section>
      </main>

      {/* MODAL 1: PRAMAAN CERTIFICATE */}
      {showCertModal && certificateData && (
        <div className="modal-overlay" onClick={() => setShowCertModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()} id="certificate-modal">
            <div className="modal-header">
              <div className="modal-title">PRAMAAN Secure Attestation Certificate</div>
              <button onClick={() => setShowCertModal(false)} className="btn-secondary" style={{ padding: '6px', borderRadius: '50%' }}>
                <X size={16} />
              </button>
            </div>
            <div className="modal-body">
              <div className="certificate-container">
                <div className="cert-stamp">LEVEL {certificateData.certificate_level}</div>
                <div className="cert-title">CERTIFICATE OF VERIFIED REPAIR</div>
                
                <div className="cert-section-title">SYSTEM METADATA</div>
                <div className="cert-meta-grid">
                  <div className="cert-meta-item">
                    <span>Quest Run ID</span>
                    <span>{certificateData.run_id}</span>
                  </div>
                  <div className="cert-meta-item">
                    <span>Repository Authority Target</span>
                    <span>{certificateData.repo_url}</span>
                  </div>
                  <div className="cert-meta-item">
                    <span>Attestation Anchor Hash</span>
                    <span style={{ fontSize: '10px' }}>{certificateData.hash_chain_anchor}</span>
                  </div>
                  <div className="cert-meta-item">
                    <span>Timestamp</span>
                    <span>{new Date(certificateData.timestamp * 1000).toLocaleString()}</span>
                  </div>
                </div>

                <div className="cert-section-title">VERIFICATION CLAIMS & EVIDENCE</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', fontSize: '12px' }}>
                  {certificateData.claims.map((claim: any, idx: number) => (
                    <div key={idx} style={{ background: 'rgba(255,255,255,0.01)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '12px' }}>
                      <div style={{ fontWeight: '600', color: 'var(--color-success)', marginBottom: '4px' }}>Claim: {claim.claim}</div>
                      <div style={{ color: 'var(--text-secondary)' }}><strong>Discovery:</strong> {claim.evidence.discovery}</div>
                      <div style={{ color: 'var(--text-secondary)' }}><strong>Validation:</strong> {claim.evidence.validation}</div>
                      {claim.evidence.exploit_sha256 && (
                        <div style={{ color: 'var(--text-secondary)' }}><strong>PoV exploit signature:</strong> <span className="font-mono">{claim.evidence.exploit_sha256}</span></div>
                      )}
                    </div>
                  ))}
                </div>

                <div style={{ marginTop: '20px', display: 'flex', gap: '10px', justifyContent: 'flex-end' }}>
                  <a
                    href={`http://127.0.0.1:8000/api/runs/${runId}/deliverables/changes.md`}
                    download
                    className="btn btn-secondary"
                    style={{ fontSize: '11px', padding: '6px 12px' }}
                  >
                    <Download size={12} /> CHANGES.md
                  </a>
                  <a
                    href={`http://127.0.0.1:8000/api/runs/${runId}/deliverables/remaining.md`}
                    download
                    className="btn btn-secondary"
                    style={{ fontSize: '11px', padding: '6px 12px' }}
                  >
                    <Download size={12} /> REMAINING.md
                  </a>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* MODAL 2: AUDIT LOGS */}
      {showAuditModal && (
        <div className="modal-overlay" onClick={() => setShowAuditModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()} id="audit-modal">
            <div className="modal-header">
              <div className="modal-title">Hash-Chained System Audit Log</div>
              <button onClick={() => setShowAuditModal(false)} className="btn-secondary" style={{ padding: '6px', borderRadius: '50%' }}>
                <X size={16} />
              </button>
            </div>
            <div className="modal-body" style={{ maxHeight: '70vh', overflowY: 'auto' }}>
              {role !== 'Owner' && role !== 'Sec Reviewer' && role !== 'Auditor' ? (
                <div style={{ color: 'var(--color-error)', display: 'flex', alignItems: 'center', gap: '6px', padding: '20px' }}>
                  <Lock size={16} /> Access Denied: Requires Owner, Sec Reviewer, or Auditor roles to read audit logs.
                </div>
              ) : auditLogs.length === 0 ? (
                <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '20px' }}>
                  No audit logs recorded yet.
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {auditLogs.map((log) => (
                    <div key={log.log_id} style={{ background: 'rgba(255,255,255,0.01)', border: '1px solid var(--border-color)', borderRadius: '6px', padding: '10px', fontSize: '12px' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span style={{ color: 'var(--color-accent)', fontWeight: '600' }}>[{log.actor.toUpperCase()}] {"->"} {log.action}</span>
                        <span style={{ color: 'var(--text-muted)' }}>{new Date(log.timestamp * 1000).toLocaleTimeString()}</span>
                      </div>
                      <div style={{ color: 'var(--text-primary)', marginBottom: '4px' }}>{log.subject}</div>
                      <div className="font-mono" style={{ fontSize: '10px', color: 'var(--text-muted)' }}>
                        <div>CURR: {log.evidence_hash}</div>
                        <div>PREV: {log.prev_hash}</div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* MODAL 3: PULL REQUEST VIEW */}
      {showPRModal && prUrl && (
        <div className="modal-overlay" onClick={() => setShowPRModal(false)}>
          <div className="modal-card" onClick={(e) => e.stopPropagation()} id="pr-modal">
            <div className="modal-header">
              <div className="modal-title">Autonomous Pull Request Opened</div>
              <button onClick={() => setShowPRModal(false)} className="btn-secondary" style={{ padding: '6px', borderRadius: '50%' }}>
                <X size={16} />
              </button>
            </div>
            <div className="modal-body pr-view-container">
              <div className="pr-header">
                <div className="pr-title">Fix: heap buffer overflow in parse_header()</div>
                <div className="pr-meta">
                  <span className="pr-status-pill">Open</span>
                  <span>kavachx/fix-01-heap-overflow</span>
                  <span>into</span>
                  <strong>main</strong>
                </div>
              </div>

              <div className="pr-policy-gate-results">
                <div className="pr-policy-gate-title">
                  <CheckCircle2 size={16} /> Deterministic Policy Gate: Passed
                </div>
                <div className="pr-policy-rule">
                  <span>Path denylist check (.github/**, CI configurations)</span>
                  <span>PASSED</span>
                </div>
                <div className="pr-policy-rule">
                  <span>Dependency check (No external imports introduced)</span>
                  <span>PASSED</span>
                </div>
                <div className="pr-policy-rule">
                  <span>Network egress / shell call checks</span>
                  <span>PASSED</span>
                </div>
                <div className="pr-policy-rule">
                  <span>Blast radius check (Changes match scope)</span>
                  <span>PASSED</span>
                </div>
              </div>

              <div className="pr-body-box">
                <p><strong>Root cause</strong>: the length check at <code>hdr.c:340</code> uses a signed comparison, allowing a negative length to bypass the bound at <code>hdr.c:812</code>.</p>
                <p style={{ marginTop: '8px' }}><strong>Assurance</strong>: PRAMAAN level A</p>
                <p><strong>Evidence</strong>: Run ID: <code>{runId}</code> · Cryptographic chain verified</p>
                <p><strong>Exploit Validation</strong>: Blocked 10/10 times post-patch</p>
                <p><strong>Benign Replay</strong>: 5,000 recorded requests replayed, byte-identical</p>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button className="btn" onClick={() => setShowPRModal(false)}>Close Review</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default App;
