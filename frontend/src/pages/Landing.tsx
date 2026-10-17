import { ArrowRight, Check, ChevronRight, CircleDot, Network, Shield, Sparkles, Waypoints } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

const features = [
  ['Asset intelligence', 'Build a living map of your infrastructure, owners, dependencies, and business criticality.'],
  ['Vulnerability operations', 'Turn CVEs into accountable work with prioritization, SLAs, and verified remediation.'],
  ['Incident response', 'Correlate alerts into an investigation timeline with evidence, tasks, and resolution records.'],
  ['Risk & compliance', 'Connect controls, risks, evidence, and corrective actions in one traceable system.'],
]

export function Landing() {
  const navigate = useNavigate()
  return <div className="landing">
    <nav className="landing-nav">
      <button className="brand-mark" onClick={() => window.scrollTo({ top: 0, behavior: 'smooth' })}><span><Shield size={18} /></span>Cyber<span className="brand-accent">Shield</span></button>
      <div className="landing-links"><a href="#platform">Platform</a><a href="#capabilities">Capabilities</a><a href="#how-it-works">How it works</a></div>
      <div className="landing-actions"><button className="text-button" onClick={() => navigate('/login')}>Sign in</button><button className="button-primary" onClick={() => navigate('/login')}>Explore live demo <ArrowRight size={15} /></button></div>
    </nav>

    <main>
      <section className="landing-hero" id="platform">
        <div className="hero-copy">
          <div className="eyebrow"><span className="pulse-dot" /> Security operations, with context</div>
          <h1>See your security posture.<br /><em>Understand your risks.</em></h1>
          <p>CyberShield connects assets, vulnerabilities, incidents, risks, and compliance into one clear operating picture for modern IT teams.</p>
          <div className="hero-actions"><button className="button-primary button-large" onClick={() => navigate('/login')}>Open the live demo <ArrowRight size={17} /></button><a href="#how-it-works" className="inline-link">See how it works <ChevronRight size={15} /></a></div>
          <div className="hero-proof"><span><Check size={13} /> Evidence-linked workflows</span><span><Check size={13} /> Role-aware operations</span></div>
        </div>
        <NetworkVisual />
      </section>

      <section className="workflow-section" id="how-it-works">
        <div className="section-intro"><span className="eyebrow">One connected workflow</span><h2>From signal to decision.</h2><p>Give every team the same trusted source of security truth, without losing the detail needed to act.</p></div>
        <div className="workflow-steps">{['Discover assets', 'Identify vulnerabilities', 'Investigate incidents', 'Reduce risk'].map((step, index) => <div className="workflow-step" key={step}><span className="step-number">0{index + 1}</span><CircleDot size={18} /><h3>{step}</h3><p>{['Know what you own and why it matters.', 'Prioritize exposure by business impact.', 'Follow evidence through a defensible timeline.', 'Prove progress to leadership and auditors.'][index]}</p>{index < 3 && <div className="step-line" />}</div>)}</div>
      </section>

      <section className="capabilities-section" id="capabilities">
        <div className="section-intro"><span className="eyebrow">Built for the whole security program</span><h2>Clarity at every layer.</h2></div>
        <div className="feature-grid">{features.map(([title, description], index) => { const FeatureIcon = [Network, Waypoints, Shield, Sparkles][index]; return <article className="feature-card" key={title}><div className="feature-icon"><FeatureIcon size={20} /></div><span className="feature-index">0{index + 1}</span><h3>{title}</h3><p>{description}</p><a href="#how-it-works">Explore capability <ArrowRight size={14} /></a></article> })}</div>
      </section>

      <section className="landing-cta"><div><span className="eyebrow">Make security easier to explain</span><h2>Your next security decision starts with a clearer picture.</h2></div><button className="button-primary button-large" onClick={() => navigate('/login')}>Enter CyberShield <ArrowRight size={17} /></button></section>
    </main>
    <footer className="landing-footer"><div className="brand-mark"><span><Shield size={18} /></span>Cyber<span className="brand-accent">Shield</span></div><span>Security posture, made actionable.</span><span>© 2026 CyberShield</span></footer>
  </div>
}

function NetworkVisual() {
  const nodes = [{ x: '22%', y: '24%', label: 'Identity' }, { x: '69%', y: '17%', label: 'Cloud' }, { x: '78%', y: '67%', label: 'Data' }, { x: '18%', y: '74%', label: 'Endpoint' }, { x: '48%', y: '47%', label: 'Posture' }]
  return <div className="network-visual"><div className="visual-glow" /><div className="network-lines"><i /><i /><i /><i /><i /></div>{nodes.map((node, index) => <div className={`network-node node-${index}`} style={{ left: node.x, top: node.y }} key={node.label}><span /><b>{node.label}</b></div>)}<div className="visual-caption"><span className="pulse-dot" /> Live security graph <small>Updated moments ago</small></div></div>
}
