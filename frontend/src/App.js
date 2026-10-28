import React, { useState, useEffect, useCallback } from 'react';
import { get, post } from './api';
import './styles.css';

// ─── Utilities ─────────────────────────────────────────────────────────
const SEVERITY_COLOR = { critical: '#ff4d4f', high: '#fa8c16', medium: '#fadb14', low: '#52c41a', info: '#1890ff' };
const STATUS_ICON = {
  confirmed_failure: '🔴', attack_blocked: '🟢', legitimate_success: '✅',
  mitigated: '🟡', inconclusive: '⚪', running: '⏳', completed: '✅', error: '❌',
};

// ─── Components ────────────────────────────────────────────────────────

function Badge({ text, color }) {
  return (
    <span style={{
      background: color || '#1f6feb', color: '#fff',
      padding: '2px 10px', borderRadius: 999, fontSize: 12, fontWeight: 600,
    }}>{text}</span>
  );
}

function Card({ title, children, accent }) {
  return (
    <div style={{
      background: '#161b22', border: `1px solid ${accent || '#30363d'}`,
      borderRadius: 10, padding: 20, marginBottom: 16,
    }}>
      {title && <h3 style={{ marginBottom: 12, color: accent || '#e6edf3', fontSize: 15 }}>{title}</h3>}
      {children}
    </div>
  );
}

// ─── Pages ─────────────────────────────────────────────────────────────

function Overview({ scans, onSelectScan, onStartScan, loading }) {
  const [mode, setMode] = useState('baseline');
  return (
    <div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
        <div>
          <h2 style={{ fontSize: 22, marginBottom: 4 }}>🛡️ AI Protector</h2>
          <p style={{ color: '#8b949e', fontSize: 14 }}>Find the attack path. Fix the failure. Prove the defense.</p>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 10, alignItems: 'center' }}>
          <select
            value={mode}
            onChange={e => setMode(e.target.value)}
            style={{ background: '#0d1117', color: '#e6edf3', border: '1px solid #30363d', borderRadius: 6, padding: '6px 12px' }}
          >
            <option value="baseline">⚠️ Baseline (vulnerable)</option>
            <option value="protected">🔒 Protected mode</option>
          </select>
          <button
            onClick={() => onStartScan(mode)}
            disabled={loading}
            style={{
              background: '#238636', color: '#fff', border: 'none',
              borderRadius: 8, padding: '10px 22px', cursor: loading ? 'not-allowed' : 'pointer',
              fontWeight: 700, fontSize: 14,
            }}
          >
            {loading ? '⏳ Starting…' : '▶ Start Scan'}
          </button>
        </div>
      </div>

      {scans.length === 0 && (
        <Card title="No scans yet">
          <p style={{ color: '#8b949e' }}>Click <strong>Start Scan</strong> to run the first attack sequence against the demo agent.</p>
        </Card>
      )}

      {scans.map(s => (
        <div
          key={s.id}
          onClick={() => onSelectScan(s.id)}
          style={{
            background: '#161b22', border: '1px solid #30363d', borderRadius: 10,
            padding: '16px 20px', marginBottom: 10, cursor: 'pointer',
            display: 'flex', alignItems: 'center', gap: 12,
          }}
        >
          <span style={{ fontSize: 20 }}>{STATUS_ICON[s.status] || '⚪'}</span>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600 }}>Scan #{s.id}</div>
            <div style={{ color: '#8b949e', fontSize: 13 }}>{s.description}</div>
          </div>
          <Badge text={s.status} color={s.status === 'completed' ? '#238636' : s.status === 'running' ? '#9e6a03' : '#da3633'} />
        </div>
      ))}
    </div>
  );
}

function ScanDetail({ scanId, onBack }) {
  const [scan, setScan] = useState(null);
  const [events, setEvents] = useState([]);
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState(null);
  const [analysis, setAnalysis] = useState(null);
  const [remediating, setRemediating] = useState(null);
  const [tab, setTab] = useState('findings');

  const load = useCallback(async () => {
    try {
      const [s, ev, fi] = await Promise.all([
        get(`/scan/${scanId}`),
        get(`/scan/${scanId}/events`),
        get(`/scan/${scanId}/findings`),
      ]);
      setScan(s); setEvents(ev); setFindings(fi);
    } catch (e) { console.error(e); }
  }, [scanId]);

  useEffect(() => { load(); const t = setInterval(load, 3000); return () => clearInterval(t); }, [load]);

  const fetchReport = async () => {
    const r = await get(`/report/${scanId}`);
    setReport(r);
    setTab('report');
  };

  const fetchAnalysis = async () => {
    const a = await get(`/scan/${scanId}/ai-analysis`);
    setAnalysis(a);
    setTab('analysis');
  };

  const remediate = async (findingId) => {
    setRemediating(findingId);
    try { await post(`/findings/${findingId}/remediate`); await load(); }
    finally { setRemediating(null); }
  };

  if (!scan) return <div style={{ color: '#8b949e', padding: 20 }}>Loading scan…</div>;

  const confirmed = findings.filter(f => f.status === 'confirmed_failure');
  const blocked   = findings.filter(f => f.status === 'attack_blocked');
  const legit     = findings.filter(f => f.status === 'legitimate_success');

  const TABS = ['findings', 'chain', 'report', 'analysis'];

  return (
    <div>
      <button onClick={onBack} style={{ background: 'none', border: '1px solid #30363d', color: '#e6edf3', borderRadius: 6, padding: '6px 14px', cursor: 'pointer', marginBottom: 16 }}>← Back</button>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <h2>Scan #{scanId} — {scan.description}</h2>
          <p style={{ color: '#8b949e', fontSize: 13, marginTop: 4 }}>Status: {STATUS_ICON[scan.status]} {scan.status}</p>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={fetchReport} style={btnStyle('#1f6feb')}>📄 Report</button>
          <button onClick={fetchAnalysis} style={btnStyle('#6e40c9')}>🤖 AI Analysis</button>
        </div>
      </div>

      {/* Stats row */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 20 }}>
        <StatBox label="Confirmed Failures" value={confirmed.length} color="#ff4d4f" />
        <StatBox label="Attacks Blocked" value={blocked.length} color="#52c41a" />
        <StatBox label="Legit Tests OK" value={legit.length} color="#1890ff" />
        <StatBox label="Total Events" value={events.length} color="#8b949e" />
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 16, borderBottom: '1px solid #30363d' }}>
        {TABS.map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            background: tab === t ? '#1f6feb' : 'none',
            color: tab === t ? '#fff' : '#8b949e',
            border: 'none', padding: '8px 20px', cursor: 'pointer',
            borderBottom: tab === t ? '2px solid #58a6ff' : '2px solid transparent',
            textTransform: 'capitalize', fontWeight: tab === t ? 700 : 400,
          }}>{t}</button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'findings' && (
        <div>
          {findings.length === 0 && <p style={{ color: '#8b949e' }}>No findings yet — scan may still be running.</p>}
          {findings.map(f => (
            <Card key={f.id} accent={SEVERITY_COLOR[f.severity] || '#30363d'}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 4 }}>
                    {STATUS_ICON[f.status] || '⚪'} {f.title}
                  </div>
                  <div style={{ color: '#8b949e', fontSize: 13, marginBottom: 8 }}>{f.description}</div>
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    <Badge text={f.severity.toUpperCase()} color={SEVERITY_COLOR[f.severity]} />
                    <Badge text={f.status} color="#30363d" />
                    <span style={{ color: '#8b949e', fontSize: 12 }}>Events: {f.evidence_event_ids}</span>
                  </div>
                </div>
                {(f.status === 'confirmed_failure') && (
                  <button
                    onClick={() => remediate(f.id)}
                    disabled={remediating === f.id}
                    style={btnStyle('#388bfd')}
                  >
                    {remediating === f.id ? '⏳ Fixing…' : '🔧 Remediate'}
                  </button>
                )}
              </div>
            </Card>
          ))}
        </div>
      )}

      {tab === 'chain' && (
        <div>
          <p style={{ color: '#8b949e', fontSize: 13, marginBottom: 16 }}>
            Attack-chain event timeline — each row is a recorded event in execution order.
          </p>
          {events.length === 0 && <p style={{ color: '#8b949e' }}>No events recorded yet.</p>}
          <div style={{ fontFamily: 'monospace', fontSize: 13 }}>
            {events.map(ev => (
              <div key={ev.id} style={{
                display: 'flex', gap: 12, padding: '10px 0',
                borderBottom: '1px solid #21262d', alignItems: 'flex-start',
              }}>
                <span style={{ color: '#8b949e', minWidth: 30 }}>#{ev.id}</span>
                <span style={{ minWidth: 140, color: EVENT_COLOR(ev.type) }}>{ev.type}</span>
                <div style={{ flex: 1, color: '#e6edf3', wordBreak: 'break-all' }}>
                  {renderEventSummary(ev)}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {tab === 'report' && (
        <div>
          {!report && <p style={{ color: '#8b949e' }}>Click <strong>📄 Report</strong> to generate the report.</p>}
          {report && (
            <pre style={{
              background: '#0d1117', border: '1px solid #30363d', borderRadius: 8,
              padding: 20, fontSize: 12, overflowX: 'auto', whiteSpace: 'pre-wrap', color: '#e6edf3',
            }}>{report}</pre>
          )}
        </div>
      )}

      {tab === 'analysis' && (
        <div>
          {!analysis && <p style={{ color: '#8b949e' }}>Click <strong>🤖 AI Analysis</strong> to run the NVIDIA Nemotron model analysis.</p>}
          {analysis && (
            <Card accent="#6e40c9">
              <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 12 }}>
                <Badge text={analysis.source === 'model' ? '🤖 NVIDIA Nemotron via Nebius' : analysis.source === 'simulated' ? '⚠️ Simulated (no API key)' : '❌ Error'} color="#6e40c9" />
                {analysis.model && <span style={{ color: '#8b949e', fontSize: 12 }}>Model: {analysis.model}</span>}
              </div>
              <pre style={{ whiteSpace: 'pre-wrap', fontSize: 13, color: '#e6edf3' }}>{analysis.analysis}</pre>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function AttackLibrary() {
  const [attacks, setAttacks] = useState([]);
  useEffect(() => { get('/attacks').then(setAttacks).catch(console.error); }, []);

  const CATEGORY_COLOR = {
    direct_prompt_injection: '#ff4d4f', indirect_prompt_injection: '#fa8c16',
    unauthorized_tool_use: '#fadb14', multi_step_chain: '#722ed1',
    legitimate_control: '#52c41a',
  };

  return (
    <div>
      <h2 style={{ marginBottom: 16 }}>⚔️ Attack Library</h2>
      <p style={{ color: '#8b949e', marginBottom: 20, fontSize: 14 }}>
        Predefined test cases covering prompt injection, unauthorized tool use, multi-step chains, and benign controls.
      </p>
      {attacks.map(a => (
        <Card key={a.id} accent={CATEGORY_COLOR[a.category] || '#30363d'}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
            <span style={{ minWidth: 70, color: '#8b949e', fontSize: 13, paddingTop: 2 }}>{a.id}</span>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontWeight: 700 }}>{a.title}</span>
                <Badge text={a.category.replace(/_/g, ' ')} color={CATEGORY_COLOR[a.category]} />
                {a.is_multi_step && <Badge text="multi-step" color="#722ed1" />}
                {a.is_control && <Badge text="control" color="#238636" />}
              </div>
              <p style={{ color: '#8b949e', fontSize: 13, marginBottom: 6 }}>{a.description}</p>
              <div style={{ background: '#0d1117', borderRadius: 6, padding: '8px 12px', fontFamily: 'monospace', fontSize: 12, color: '#79c0ff', marginBottom: 4 }}>
                💬 {a.attack_input}
              </div>
              {a.injected_document && (
                <div style={{ background: '#161b22', border: '1px solid #da3633', borderRadius: 6, padding: '6px 10px', fontSize: 12, color: '#ffa198', marginTop: 4 }}>
                  📄 Injected document: {a.injected_document.slice(0, 80)}…
                </div>
              )}
              <p style={{ color: '#3fb950', fontSize: 12, marginTop: 6 }}>✅ Expected: {a.expected_secure_behavior}</p>
            </div>
          </div>
        </Card>
      ))}
    </div>
  );
}

// ─── Helpers ────────────────────────────────────────────────────────────
function StatBox({ label, value, color }) {
  return (
    <div style={{
      background: '#161b22', border: `1px solid ${color}33`,
      borderRadius: 10, padding: '14px 20px', flex: 1, textAlign: 'center',
    }}>
      <div style={{ fontSize: 28, fontWeight: 800, color }}>{value}</div>
      <div style={{ color: '#8b949e', fontSize: 12, marginTop: 4 }}>{label}</div>
    </div>
  );
}

function btnStyle(bg) {
  return {
    background: bg, color: '#fff', border: 'none', borderRadius: 8,
    padding: '8px 16px', cursor: 'pointer', fontWeight: 600, fontSize: 13,
  };
}

function EVENT_COLOR(type) {
  return { prompt: '#79c0ff', model_response: '#d2a8ff', tool_request: '#ffa657', auth_decision: '#ff7b72', tool_result: '#3fb950' }[type] || '#8b949e';
}

function renderEventSummary(ev) {
  const p = ev.payload;
  if (ev.type === 'prompt') return <span><strong>attack={p.attack_id}</strong> input: {(p.input || '').slice(0, 100)}</span>;
  if (ev.type === 'model_response') {
    const ar = p.agent_result || {};
    return <span>type={ar.type} {ar.content ? `content: ${ar.content.slice(0, 80)}` : ''} {ar.tool ? `tool: ${ar.tool}` : ''}</span>;
  }
  if (ev.type === 'auth_decision') return <span style={{ color: p.allowed ? '#3fb950' : '#ff4d4f' }}>{p.allowed ? '✅ ALLOWED' : '🚫 BLOCKED'} — {p.tool} — {p.reason}</span>;
  if (ev.type === 'tool_request') return <span>tool: {p.tool} args: {JSON.stringify(p.args)}</span>;
  if (ev.type === 'tool_result') return <span>{p.executed ? `✅ Executed → ${JSON.stringify(p.result).slice(0, 60)}` : `🚫 Blocked: ${p.blocked_reason}`}</span>;
  return <span>{JSON.stringify(p).slice(0, 100)}</span>;
}

// ─── App ────────────────────────────────────────────────────────────────
export default function App() {
  const [page, setPage] = useState('overview');
  const [scans, setScans] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [scanLoading, setScanLoading] = useState(false);

  const loadScans = useCallback(async () => {
    try { setScans(await get('/scan')); } catch (e) { console.error(e); }
  }, []);

  useEffect(() => {
    loadScans();
    const t = setInterval(loadScans, 5000);
    return () => clearInterval(t);
  }, [loadScans]);

  const startScan = async (mode) => {
    setScanLoading(true);
    try {
      const res = await post(`/scan/run?mode=${mode}&description=${encodeURIComponent('Demo scan')}`);
      await loadScans();
      setSelectedScan(res.scan_id);
      setPage('scan-detail');
    } catch (e) { alert('Failed to start scan: ' + e.message); }
    finally { setScanLoading(false); }
  };

  const selectScan = (id) => { setSelectedScan(id); setPage('scan-detail'); };

  const NAV = [
    { id: 'overview', label: '🏠 Overview' },
    { id: 'attacks', label: '⚔️ Attacks' },
  ];

  return (
    <div style={{ display: 'flex', minHeight: '100vh' }}>
      {/* Sidebar */}
      <div style={{ width: 200, background: '#0d1117', borderRight: '1px solid #21262d', padding: '20px 0', flexShrink: 0 }}>
        <div style={{ padding: '0 20px 20px', borderBottom: '1px solid #21262d' }}>
          <div style={{ fontWeight: 800, fontSize: 16, color: '#58a6ff' }}>🛡️ AI Protector</div>
          <div style={{ color: '#8b949e', fontSize: 11, marginTop: 2 }}>Security Lab</div>
        </div>
        {NAV.map(n => (
          <div key={n.id}
            onClick={() => setPage(n.id)}
            style={{
              padding: '12px 20px', cursor: 'pointer',
              background: page === n.id ? '#161b22' : 'transparent',
              borderLeft: page === n.id ? '3px solid #58a6ff' : '3px solid transparent',
              color: page === n.id ? '#e6edf3' : '#8b949e', fontSize: 14,
            }}>{n.label}</div>
        ))}
        {scans.length > 0 && (
          <>
            <div style={{ padding: '12px 20px 4px', color: '#8b949e', fontSize: 11, textTransform: 'uppercase', letterSpacing: 1 }}>Recent Scans</div>
            {scans.slice(0, 5).map(s => (
              <div key={s.id}
                onClick={() => selectScan(s.id)}
                style={{
                  padding: '8px 20px', cursor: 'pointer',
                  background: page === 'scan-detail' && selectedScan === s.id ? '#161b22' : 'transparent',
                  borderLeft: page === 'scan-detail' && selectedScan === s.id ? '3px solid #58a6ff' : '3px solid transparent',
                  color: '#8b949e', fontSize: 13,
                }}>#{s.id} {STATUS_ICON[s.status]}</div>
            ))}
          </>
        )}
      </div>

      {/* Main content */}
      <div style={{ flex: 1, padding: '32px 40px', overflowY: 'auto' }}>
        {page === 'overview' && <Overview scans={scans} onSelectScan={selectScan} onStartScan={startScan} loading={scanLoading} />}
        {page === 'attacks' && <AttackLibrary />}
        {page === 'scan-detail' && selectedScan && <ScanDetail scanId={selectedScan} onBack={() => setPage('overview')} />}
      </div>
    </div>
  );
}

