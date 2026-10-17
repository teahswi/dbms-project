import { useEffect, useState } from 'react'
import { Activity, Bot, ClipboardCheck, FileClock, FileText, Flame, Plus, RefreshCw, Search, ShieldCheck, SlidersHorizontal, Users2 } from 'lucide-react'
import { api } from '../services/api'

type PageType = 'incidents' | 'risks' | 'compliance' | 'assistant' | 'reports' | 'audit' | 'users'
const config: Record<PageType, { title: string; description: string; icon: typeof Activity; endpoint: () => Promise<any> }> = {
  incidents: { title: 'Incident investigation', description: 'Coordinate evidence, response tasks, and resolution records.', icon: Flame, endpoint: () => api.getIncidents() },
  risks: { title: 'Risk register', description: 'Assess likelihood, impact, ownership, and treatment progress.', icon: SlidersHorizontal, endpoint: () => api.getRisks() },
  compliance: { title: 'Compliance & audits', description: 'Track controls, assessments, evidence, and corrective actions.', icon: ClipboardCheck, endpoint: () => api.getAuditPlans() },
  assistant: { title: 'AI investigation assistant', description: 'Evidence-grounded analysis that separates observed facts from hypotheses.', icon: Bot, endpoint: () => api.getIncidents() },
  reports: { title: 'Reports & audit history', description: 'Exportable posture views and traceable records of important actions.', icon: FileText, endpoint: () => api.getExecutiveReport() },
  audit: { title: 'Application audit logs', description: 'Immutable records of security operations and approvals.', icon: FileClock, endpoint: () => api.getAuditLogs({ limit: 50 }) },
  users: { title: 'Access control & RBAC', description: 'Review enterprise users and role permissions.', icon: Users2, endpoint: () => api.getUsers() },
}

export function OperationsPage({ type }: { type: PageType }) {
  const page = config[type]
  const Icon = page.icon
  const [data, setData] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [query, setQuery] = useState('')
  const [error, setError] = useState('')

  useEffect(() => { page.endpoint().then((response) => { const next = response.data; setData(Array.isArray(next) ? next : next ? [next] : []) }).catch((reason: Error) => setError(reason.message)).finally(() => setLoading(false)) }, [type])
  const filtered = data.filter((item) => JSON.stringify(item).toLowerCase().includes(query.toLowerCase()))

  if (type === 'assistant') return <AssistantPage />
  return <section className="operation-page">
    <div className="page-heading"><div><div className="eyebrow">Operations workspace</div><h1><Icon size={25} />{page.title}</h1><p>{page.description}</p></div><button className="button-primary"><Plus size={15} /> Create record</button></div>
    <div className="operation-toolbar"><div className="search-field"><Search size={16} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search records..." /></div><button className="toolbar-button"><RefreshCw size={15} /> Refresh</button><button className="toolbar-button"><SlidersHorizontal size={15} /> Filters</button></div>
    {error && <div className="state-card error-state"><ShieldCheck size={20} /><div><strong>Live data unavailable</strong><p>{error}. Connect the Flask API to load this workspace.</p></div></div>}
    {loading ? <div className="state-card"><RefreshCw className="spin" size={20} /> Loading operational records...</div> : !error && <div className="record-grid">{filtered.length ? filtered.slice(0, 12).map((item, index) => <article className="record-card" key={item.id || item.incident_id || item.risk_id || index}><div className="record-card-top"><span className="record-id">RECORD {String(index + 1).padStart(2, '0')}</span><span className="record-status">{item.status || item.role || 'ACTIVE'}</span></div><h3>{item.title || item.name || item.email || item.framework_name || 'Executive posture report'}</h3><p>{item.description || item.threat_description || item.action || 'Evidence-linked operational record available for review.'}</p><div className="record-meta"><span>{item.severity || item.owner_name || 'CyberShield'}</span><span>{item.created_at ? new Date(item.created_at).toLocaleDateString() : 'Demo record'}</span></div></article>) : <div className="state-card">No records match this search.</div>}</div>}
  </section>
}

function AssistantPage() {
  return <section className="operation-page assistant-page"><div className="page-heading"><div><div className="eyebrow">Evidence-grounded analysis · Demo mode</div><h1><Bot size={25} />AI investigation assistant</h1><p>Review evidence, challenge assumptions, and choose the next verification step.</p></div><span className="demo-badge">DEMO MODE · NO AUTOMATIC ACTIONS</span></div><div className="assistant-grid"><div className="assistant-panel"><div className="panel-label">Investigation brief</div><h2>Suspicious authentication activity on Finance VPN</h2><p className="muted">The assistant has assembled 8 related alerts, 2 asset records, and 1 analyst note. Conclusions below are limited to the supplied evidence.</p><div className="evidence-list"><div><span className="evidence-dot observed" />Observed fact <p>7 failed logins from an unfamiliar ASN within 11 minutes.</p></div><div><span className="evidence-dot hypothesis" />Working hypothesis <p>Credential stuffing is possible, but no successful session is confirmed.</p></div><div><span className="evidence-dot missing" />Missing evidence <p>Verify MFA challenge outcome and VPN session logs before escalating.</p></div></div></div><div className="assistant-panel next-steps"><div className="panel-label">Suggested next steps</div>{['Confirm whether the account completed MFA.', 'Compare source ASN against approved vendor ranges.', 'Review endpoint telemetry for a post-authentication process.'].map((step, index) => <button key={step}><span>0{index + 1}</span>{step}<span>›</span></button>)}<div className="assistant-note"><Activity size={16} /><span>Suggestions are advisory. An analyst must verify evidence and initiate any production action.</span></div></div></div></section>
}
