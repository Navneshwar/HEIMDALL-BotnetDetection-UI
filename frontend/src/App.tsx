import { ChangeEvent, DragEvent, ReactNode, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  CheckCircle2,
  ChevronDown,
  Clock3,
  FileSearch,
  FileUp,
  Filter,
  Fingerprint,
  Network,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  SlidersHorizontal,
  UploadCloud,
  X,
} from 'lucide-react';

type Health = {
  status: string;
  model_ready: boolean;
  model_message: string;
  missing_artifact_count: number;
};

type Flow = {
  flow_id: number;
  protocol: string;
  source_ip: string;
  destination_ip: string;
  source_port: number;
  destination_port: number;
  packet_count: number;
  total_bytes: number;
  flow_duration: number;
  anomaly_score: number;
  risk_level: 'NORMAL' | 'LOW' | 'MEDIUM' | 'HIGH';
  attribution: string;
  attribution_similarity: number;
  is_anomalous: boolean;
  actions: string[];
};

type Analysis = {
  file_name: string;
  file_size_bytes: number;
  packets_seen: number;
  packets_used: number;
  packets_ignored: number;
  flow_count: number;
  flagged_flow_count: number;
  flagged_flow_percentage: number;
  verdict: 'BOTNET_ACTIVITY_DETECTED' | 'NO_BOTNET_INDICATORS_DETECTED';
  verdict_rule: string;
  risk_distribution: Record<string, number>;
  attribution_distribution: Record<string, number>;
  flows: Flow[];
};

type RiskFilter = 'ALL' | Flow['risk_level'];

const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;
const RISK_ORDER: Flow['risk_level'][] = ['HIGH', 'MEDIUM', 'LOW', 'NORMAL'];

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function formatNumber(value: number): string {
  return new Intl.NumberFormat('en-US').format(value);
}

function formatScore(value: number): string {
  return value.toFixed(5);
}

function percent(value: number): string {
  return `${value.toFixed(1)}%`;
}

function csvEscape(value: string | number | boolean): string {
  const text = String(value);
  return `"${text.replaceAll('"', '""')}"`;
}

function App() {
  const inputRef = useRef<HTMLInputElement>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);
  const [file, setFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState('');
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [riskFilter, setRiskFilter] = useState<RiskFilter>('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const checkHealth = useCallback(async () => {
    setHealthLoading(true);
    try {
      const response = await fetch('/api/health');
      if (!response.ok) throw new Error('The analysis service could not be reached.');
      const data = (await response.json()) as Health;
      setHealth(data);
    } catch {
      setHealth({
        status: 'offline',
        model_ready: false,
        model_message: 'Backend unavailable. Start the Python API and refresh this status.',
        missing_artifact_count: 0,
      });
    } finally {
      setHealthLoading(false);
    }
  }, []);

  useEffect(() => {
    void checkHealth();
  }, [checkHealth]);

  const acceptFile = useCallback((candidate?: File) => {
    if (!candidate) return;
    setError('');
    setAnalysis(null);
    setRiskFilter('ALL');
    setSearchTerm('');
    const extension = candidate.name.split('.').pop()?.toLowerCase();
    if (!['pcap', 'pcapng', 'cap'].includes(extension || '')) {
      setFile(null);
      setError('Choose a PCAP, PCAPNG, or CAP capture file.');
      return;
    }
    if (candidate.size <= 0) {
      setFile(null);
      setError('The selected file is empty.');
      return;
    }
    if (candidate.size > MAX_UPLOAD_BYTES) {
      setFile(null);
      setError('The maximum upload size is 100 MB.');
      return;
    }
    setFile(candidate);
  }, []);

  const onInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    acceptFile(event.target.files?.[0]);
    event.target.value = '';
  };

  const onDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    acceptFile(event.dataTransfer.files?.[0]);
  };

  const runAnalysis = async () => {
    if (!file || !health?.model_ready || isAnalyzing) return;
    setIsAnalyzing(true);
    setError('');
    setAnalysis(null);
    try {
      const body = new FormData();
      body.append('file', file);
      const response = await fetch('/api/analyze', { method: 'POST', body });
      const payload = await response.json();
      if (!response.ok) {
        throw new Error(payload.detail || 'Capture analysis failed.');
      }
      setAnalysis(payload as Analysis);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Capture analysis failed.');
      void checkHealth();
    } finally {
      setIsAnalyzing(false);
    }
  };

  const filteredFlows = useMemo(() => {
    if (!analysis) return [];
    const query = searchTerm.trim().toLowerCase();
    return analysis.flows.filter((flow) => {
      const matchesRisk = riskFilter === 'ALL' || flow.risk_level === riskFilter;
      const haystack = [
        flow.source_ip,
        flow.destination_ip,
        flow.protocol,
        flow.attribution,
        String(flow.source_port),
        String(flow.destination_port),
      ].join(' ').toLowerCase();
      return matchesRisk && (!query || haystack.includes(query));
    });
  }, [analysis, riskFilter, searchTerm]);

  const exportCsv = () => {
    if (!analysis) return;
    const columns = [
      'flow_id', 'protocol', 'source_ip', 'source_port', 'destination_ip',
      'destination_port', 'packet_count', 'total_bytes', 'flow_duration',
      'anomaly_score', 'risk_level', 'attribution', 'attribution_similarity', 'is_anomalous',
    ];
    const rows = analysis.flows.map((flow) => columns.map((key) => csvEscape(flow[key as keyof Flow] as string | number | boolean)));
    const content = [columns.join(','), ...rows.map((row) => row.join(','))].join('\n');
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `${analysis.file_name.replace(/\.[^.]+$/, '')}_heimdall_results.csv`;
    anchor.click();
    URL.revokeObjectURL(url);
  };

  const clearAnalysis = () => {
    setAnalysis(null);
    setFile(null);
    setError('');
    setRiskFilter('ALL');
    setSearchTerm('');
  };

  const isSuspicious = analysis?.verdict === 'BOTNET_ACTIVITY_DETECTED';
  const modelReady = Boolean(health?.model_ready);
  const topAttributions: [string, number][] = analysis
    ? (Object.entries(analysis.attribution_distribution) as [string, number][]).sort((left, right) => right[1] - left[1]).slice(0, 4)
    : [];

  return (
    <div className="app-shell">
      <header className="topbar">
        <a className="brand" href="#top" aria-label="HEIMDALL home">
          <span className="brand-mark"><Shield size={20} strokeWidth={2.2} /></span>
          <span className="brand-copy">
            <strong>HEIMDALL</strong>
            <small>NETWORK INTELLIGENCE</small>
          </span>
        </a>
        <div className="topbar-right">
          <div className={`system-state ${modelReady ? 'is-ready' : 'is-not-ready'}`}>
            <span className="state-dot" />
            {healthLoading ? 'Checking model' : modelReady ? 'Model online' : 'Model not configured'}
          </div>
          <button className="icon-button" onClick={() => void checkHealth()} title="Refresh service status" aria-label="Refresh service status">
            <RefreshCw size={16} className={healthLoading ? 'spin' : ''} />
          </button>
          <div className="topbar-divider" />
          <span className="environment-label">LOCAL ANALYSIS</span>
        </div>
      </header>

      <main id="top" className="main-content">
        <section className="page-heading">
          <div>
            <div className="eyebrow"><span className="eyebrow-line" /> SECURITY OPERATIONS / CAPTURE REVIEW</div>
            <h1>PCAP analysis</h1>
            <p className="page-subtitle">Inspect network traffic and identify flows that may indicate botnet activity.</p>
          </div>
          {analysis && (
            <button className="button button-secondary new-analysis" onClick={clearAnalysis}>
              <FileSearch size={16} /> New analysis
            </button>
          )}
        </section>

        <section className="workspace-grid">
          <div className="panel upload-panel">
            <div className="panel-heading">
              <div>
                <div className="section-kicker">INPUT</div>
                <h2>Upload network capture</h2>
                <p>Select a packet capture file to begin inspection.</p>
              </div>
              <div className="heading-icon"><FileUp size={19} /></div>
            </div>

            <div
              className={`dropzone ${isDragging ? 'is-dragging' : ''} ${file ? 'has-file' : ''}`}
              onDragOver={(event) => { event.preventDefault(); setIsDragging(true); }}
              onDragLeave={(event) => { event.preventDefault(); setIsDragging(false); }}
              onDrop={onDrop}
              onClick={() => inputRef.current?.click()}
              role="button"
              tabIndex={0}
              onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') inputRef.current?.click(); }}
            >
              <input ref={inputRef} type="file" accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap" onChange={onInputChange} hidden />
              <span className="dropzone-icon"><UploadCloud size={25} /></span>
              <strong>{file ? 'Capture file selected' : 'Drop your capture file here'}</strong>
              <span className="dropzone-secondary">or <span className="browse-link">browse files</span></span>
              <span className="file-spec">PCAP · PCAPNG · CAP <span className="spec-separator">/</span> UP TO 100 MB</span>
            </div>

            {file && (
              <div className="selected-file">
                <div className="file-type-icon"><Network size={18} /></div>
                <div className="selected-file-info">
                  <strong title={file.name}>{file.name}</strong>
                  <span>{formatBytes(file.size)} <span className="file-meta-separator">·</span> Ready for analysis</span>
                </div>
                <button className="icon-button remove-file" title="Remove selected file" aria-label="Remove selected file" onClick={(event) => { event.stopPropagation(); setFile(null); setAnalysis(null); setError(''); }}>
                  <X size={16} />
                </button>
              </div>
            )}

            {error && (
              <div className="inline-error" role="alert"><AlertCircle size={16} /> <span>{error}</span></div>
            )}

            {!modelReady && (
              <div className="model-notice">
                <AlertTriangle size={17} />
                <div>
                  <strong>Inference model unavailable</strong>
                  <p>{health?.model_message || 'The trained model bundle has not been loaded.'}</p>
                </div>
              </div>
            )}

            <button className="button button-primary analyze-button" disabled={!file || !modelReady || isAnalyzing} onClick={() => void runAnalysis()}>
              {isAnalyzing ? <span className="button-spinner" /> : <Activity size={17} />}
              {isAnalyzing ? 'Analysing capture...' : 'Analyse capture'}
              {!isAnalyzing && <ArrowRight size={16} />}
            </button>
            <div className="upload-footnote"><ShieldCheck size={14} /> Captures are processed locally and removed after analysis.</div>
          </div>

          <div className="panel status-panel">
            <div className="panel-heading status-heading">
              <div>
                <div className="section-kicker">SYSTEM STATUS</div>
                <h2>Inference service</h2>
                <p>Current availability of the analysis engine.</p>
              </div>
              <div className={`status-icon ${modelReady ? 'status-icon-good' : 'status-icon-warn'}`}>
                {modelReady ? <ShieldCheck size={20} /> : <ShieldAlert size={20} />}
              </div>
            </div>
            <div className="status-summary">
              <div className="status-summary-copy">
                <span className="status-label">MODEL STATUS</span>
                <strong>{healthLoading ? 'Checking...' : modelReady ? 'Ready for inference' : 'Awaiting model bundle'}</strong>
              </div>
              <span className={`status-pill ${modelReady ? 'pill-ready' : 'pill-pending'}`}>
                <span className="state-dot" /> {modelReady ? 'Operational' : 'Offline'}
              </span>
            </div>
            <div className="status-facts">
              <div className="status-fact"><span>Input format</span><strong>PCAP / PCAPNG</strong></div>
              <div className="status-fact"><span>Analysis mode</span><strong>Flow-level inspection</strong></div>
              <div className="status-fact"><span>Processing</span><strong>Local backend</strong></div>
            </div>
            <div className="service-footer">
              <span><span className={`service-indicator ${modelReady ? 'good' : ''}`} /> API connection</span>
              <span>{healthLoading ? 'Verifying' : health?.status === 'offline' ? 'Unavailable' : 'Checked'}</span>
            </div>
          </div>
        </section>

        {isAnalyzing && (
          <section className="analysis-progress panel">
            <div className="progress-mark"><Activity size={19} /></div>
            <div className="progress-copy">
              <strong>Analysing {file?.name}</strong>
              <span>Reading packets, building flows and evaluating network activity.</span>
            </div>
            <span className="progress-indicator" />
          </section>
        )}

        {analysis && (
          <section className="results-section" aria-live="polite">
            <div className={`verdict-banner ${isSuspicious ? 'verdict-alert' : 'verdict-clear'}`}>
              <div className="verdict-icon">{isSuspicious ? <ShieldAlert size={23} /> : <ShieldCheck size={23} />}</div>
              <div className="verdict-copy">
                <span className="section-kicker">CAPTURE ASSESSMENT</span>
                <h2>{isSuspicious ? 'Potential botnet activity detected' : 'No botnet indicators detected'}</h2>
                <p>{isSuspicious ? `${formatNumber(analysis.flagged_flow_count)} of ${formatNumber(analysis.flow_count)} flows exceeded the configured anomaly threshold.` : `No flows exceeded the configured anomaly threshold across ${formatNumber(analysis.flow_count)} analysed flows.`}</p>
              </div>
              <div className="verdict-meta">
                <span>FLAGGED FLOWS</span>
                <strong>{percent(analysis.flagged_flow_percentage)}</strong>
              </div>
            </div>

            <div className="result-file-line">
              <div className="result-file-name"><Network size={16} /><strong>{analysis.file_name}</strong><span>{formatBytes(analysis.file_size_bytes)}</span></div>
              <div className="result-actions">
                <span><Clock3 size={14} /> Analysis complete</span>
                <button className="button button-secondary export-button" onClick={exportCsv}><ArrowDownToLine size={15} /> Export CSV</button>
              </div>
            </div>

            <div className="metric-grid">
              <MetricCard label="Flows analysed" value={formatNumber(analysis.flow_count)} detail={`${formatNumber(analysis.packets_used)} packets included`} icon={<Network size={17} />} />
              <MetricCard label="Flagged flows" value={formatNumber(analysis.flagged_flow_count)} detail={`${percent(analysis.flagged_flow_percentage)} of total flows`} icon={<AlertTriangle size={17} />} accent={analysis.flagged_flow_count > 0 ? 'warn' : 'good'} />
              <MetricCard label="Packets inspected" value={formatNumber(analysis.packets_seen)} detail={`${formatNumber(analysis.packets_ignored)} not used`} icon={<Activity size={17} />} />
              <MetricCard label="Attribution classes" value={formatNumber(Object.keys(analysis.attribution_distribution).length)} detail="Among flagged flows" icon={<Fingerprint size={17} />} />
            </div>

            <div className="insight-grid">
              <div className="panel insight-panel">
                <div className="insight-heading">
                  <div><div className="section-kicker">RISK OVERVIEW</div><h3>Flow risk distribution</h3></div>
                  <SlidersHorizontal size={17} className="muted-icon" />
                </div>
                <div className="risk-chart">
                  {RISK_ORDER.map((level) => {
                    const count = analysis.risk_distribution[level] || 0;
                    const width = analysis.flow_count ? Math.max((count / analysis.flow_count) * 100, count > 0 ? 1.5 : 0) : 0;
                    return (
                      <div className="risk-row" key={level}>
                        <div className="risk-label"><span className={`risk-dot risk-${level.toLowerCase()}`} />{level}</div>
                        <div className="risk-track"><div className={`risk-fill risk-fill-${level.toLowerCase()}`} style={{ width: `${width}%` }} /></div>
                        <strong>{formatNumber(count)}</strong>
                      </div>
                    );
                  })}
                </div>
                <div className="chart-footnote">Counts are based on per-flow model risk levels.</div>
              </div>

              <div className="panel insight-panel attribution-panel">
                <div className="insight-heading">
                  <div><div className="section-kicker">MODEL ATTRIBUTION</div><h3>Flagged flow profiles</h3></div>
                  <Fingerprint size={18} className="muted-icon" />
                </div>
                {topAttributions.length > 0 ? (
                  <div className="attribution-list">
                    {topAttributions.map(([name, count]) => (
                      <div className="attribution-row" key={name}>
                        <div className="attribution-name"><span className="attribution-marker" /> <strong>{name}</strong></div>
                        <div className="attribution-count"><strong>{formatNumber(count)}</strong><span>{analysis.flagged_flow_count ? percent((count / analysis.flagged_flow_count) * 100) : '0%'}</span></div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-attribution"><CheckCircle2 size={22} /><strong>No flagged profiles</strong><span>There are no anomalous flows to attribute.</span></div>
                )}
                <div className="chart-footnote">Similarity scores are comparative signals, not probabilities.</div>
              </div>
            </div>

            <div className="panel flows-panel">
              <div className="flows-heading">
                <div><div className="section-kicker">DETAILED INSPECTION</div><h3>Flow-level results <span className="flow-total">{formatNumber(analysis.flow_count)}</span></h3></div>
                <div className="flow-controls">
                  <div className="search-box"><Search size={15} /><input value={searchTerm} onChange={(event) => setSearchTerm(event.target.value)} placeholder="Search IP, port, protocol" aria-label="Search flows" /></div>
                  <div className="filter-select-wrap"><Filter size={14} /><select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value as RiskFilter)} aria-label="Filter flows by risk"><option value="ALL">All risk levels</option><option value="HIGH">High</option><option value="MEDIUM">Medium</option><option value="LOW">Low</option><option value="NORMAL">Normal</option></select><ChevronDown size={14} /></div>
                </div>
              </div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>FLOW</th><th>SOURCE</th><th>DESTINATION</th><th>PROTO</th><th>PACKETS</th><th>ANOMALY SCORE</th><th>RISK</th><th>ATTRIBUTION</th></tr></thead>
                  <tbody>
                    {filteredFlows.slice(0, 500).map((flow) => (
                      <tr key={flow.flow_id}>
                        <td><span className="flow-id">#{String(flow.flow_id).padStart(4, '0')}</span></td>
                        <td><span className="ip-cell">{flow.source_ip}</span><small>:{flow.source_port}</small></td>
                        <td><span className="ip-cell">{flow.destination_ip}</span><small>:{flow.destination_port}</small></td>
                        <td><span className="protocol-chip">{flow.protocol}</span></td>
                        <td className="numeric-cell">{formatNumber(flow.packet_count)}</td>
                        <td className="numeric-cell score-cell">{formatScore(flow.anomaly_score)}</td>
                        <td><RiskBadge level={flow.risk_level} /></td>
                        <td><span className="attribution-cell">{flow.attribution}</span></td>
                      </tr>
                    ))}
                    {filteredFlows.length === 0 && <tr><td colSpan={8} className="no-rows">No flows match the current filters.</td></tr>}
                  </tbody>
                </table>
              </div>
              <div className="table-footer">
                <span>Showing {formatNumber(Math.min(filteredFlows.length, 500))} of {formatNumber(filteredFlows.length)} matching flows</span>
                {filteredFlows.length > 500 && <span>Export the CSV to access the complete result set.</span>}
              </div>
            </div>

            <div className="result-disclaimer"><AlertCircle size={15} /><span>File-level verdict rule: one or more flows above the configured model threshold marks the capture for investigation. This is a triage signal and does not establish compromise or guarantee that undetected traffic is benign.</span></div>
          </section>
        )}

        {!analysis && !isAnalyzing && (
          <section className="overview-section">
            <div className="overview-title"><div className="section-kicker">WORKFLOW</div><h2>From packet capture to security insight</h2><p>A focused analysis workflow for reviewing network activity.</p></div>
            <div className="workflow-grid">
              <WorkflowCard number="01" icon={<FileSearch size={19} />} title="Capture ingestion" description="Load a packet capture from a network segment or test environment." />
              <WorkflowCard number="02" icon={<Network size={19} />} title="Flow extraction" description="Organise supported traffic into bidirectional communication flows." />
              <WorkflowCard number="03" icon={<Activity size={19} />} title="Model assessment" description="Review file-level findings, risk distribution and per-flow results." />
            </div>
          </section>
        )}

        <footer className="app-footer">
          <span>HEIMDALL <span className="footer-divider">/</span> Capture Analysis</span>
          <span>For network security triage and analyst review</span>
        </footer>
      </main>
    </div>
  );
}

function MetricCard({ label, value, detail, icon, accent }: { label: string; value: string; detail: string; icon: ReactNode; accent?: 'warn' | 'good' }) {
  return (
    <div className="panel metric-card">
      <div className={`metric-icon ${accent === 'warn' ? 'metric-warn' : accent === 'good' ? 'metric-good' : ''}`}>{icon}</div>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  );
}

function RiskBadge({ level }: { level: Flow['risk_level'] }) {
  return <span className={`risk-badge badge-${level.toLowerCase()}`}><span className="risk-dot" />{level}</span>;
}

function WorkflowCard({ number, icon, title, description }: { number: string; icon: ReactNode; title: string; description: string }) {
  return (
    <div className="panel workflow-card">
      <div className="workflow-top"><span className="workflow-number">{number}</span><span className="workflow-icon">{icon}</span></div>
      <h3>{title}</h3>
      <p>{description}</p>
      <div className="workflow-bottom"><span>HEIMDALL ANALYSIS</span><ArrowRight size={14} /></div>
    </div>
  );
}

export default App;
