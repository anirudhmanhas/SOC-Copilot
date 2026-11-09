import React, { useState } from "react"
import { Link } from "react-router-dom"
import {
  Shield,
  Bot,
  Terminal,
  Zap,
  Cpu,
  Layers,
  ArrowRight,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Flame,
  Globe,
  Database,
  Lock,
  Sparkles,
  ExternalLink,
  Code,
  Copy,
  Check,
} from "lucide-react"

export default function Showcase() {
  const [copiedCmd, setCopiedCmd] = useState(false)
  const [activeTab, setActiveTab] = useState("overview")

  const copyDockerCommand = () => {
    navigator.clipboard.writeText("docker compose up --build")
    setCopiedCmd(true)
    setTimeout(() => setCopiedCmd(false), 2000)
  }

  return (
    <div className="space-y-16 py-4">
      {/* 1. Hero Section */}
      <section className="relative overflow-hidden rounded-3xl border border-blue-500/20 bg-gradient-to-b from-blue-950/20 via-gray-900/60 to-[#0B0F17] p-8 md:p-14 text-center shadow-2xl">
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_var(--tw-gradient-stops))] from-blue-600/10 via-transparent to-transparent pointer-events-none" />

        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400 text-xs font-semibold uppercase tracking-wider mb-6">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Autonomous AI Cyber Defense Platform</span>
        </div>

        <h1 className="text-4xl md:text-6xl font-extrabold text-white tracking-tight leading-tight max-w-4xl mx-auto">
          Enterprise SOC Defense <br />
          <span className="bg-gradient-to-r from-blue-400 via-indigo-300 to-cyan-400 bg-clip-text text-transparent">
            Without the Enterprise Price Tag
          </span>
        </h1>

        <p className="mt-6 text-gray-300 text-base md:text-lg max-w-2xl mx-auto leading-relaxed">
          SOC Copilot ingests multi-source telemetry, correlates multi-stage breaches across the
          MITRE ATT&CK framework, generates executive triage using Google Gemini 3.5 Flash, and enforces
          safe 1-click human-in-the-loop containment.
        </p>

        {/* CTA Buttons */}
        <div className="mt-8 flex flex-wrap items-center justify-center gap-4">
          <Link
            to="/"
            className="flex items-center space-x-2 px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-all shadow-lg shadow-blue-600/25 hover:shadow-blue-500/40"
          >
            <span>Launch Operations Center</span>
            <ArrowRight className="w-4 h-4" />
          </Link>

          <Link
            to="/incidents"
            className="flex items-center space-x-2 px-6 py-3 rounded-xl bg-gray-800/80 hover:bg-gray-700/80 text-gray-200 border border-gray-700 font-medium text-sm transition-all"
          >
            <Flame className="w-4 h-4 text-rose-400" />
            <span>View Active Incidents</span>
          </Link>

          <a
            href="https://github.com"
            target="_blank"
            rel="noreferrer"
            className="flex items-center space-x-2 px-5 py-3 rounded-xl bg-gray-900 hover:bg-gray-800 text-gray-400 hover:text-white border border-gray-800 text-sm font-medium transition-colors"
          >
            <Code className="w-4 h-4" />
            <span>GitHub Repository</span>
            <ExternalLink className="w-3 h-3" />
          </a>
        </div>

        {/* Live Metrics Row */}
        <div className="mt-12 pt-8 border-t border-gray-800/80 grid grid-cols-2 md:grid-cols-4 gap-6 max-w-3xl mx-auto text-center">
          <div>
            <div className="text-2xl md:text-3xl font-extrabold text-blue-400">85%+</div>
            <div className="text-xs text-gray-400 mt-1">Alert Noise Reduction</div>
          </div>
          <div>
            <div className="text-2xl md:text-3xl font-extrabold text-emerald-400">&lt; 3s</div>
            <div className="text-xs text-gray-400 mt-1">Gemini AI Triage Time</div>
          </div>
          <div>
            <div className="text-2xl md:text-3xl font-extrabold text-purple-400">14</div>
            <div className="text-xs text-gray-400 mt-1">MITRE Tactics Covered</div>
          </div>
          <div>
            <div className="text-2xl md:text-3xl font-extrabold text-amber-400">1-Click</div>
            <div className="text-xs text-gray-400 mt-1">Human-in-the-Loop Active Response</div>
          </div>
        </div>
      </section>

      {/* 2. The Core Problem vs. Our Solution */}
      <section className="space-y-8">
        <div className="text-center max-w-3xl mx-auto space-y-3">
          <h2 className="text-xs font-bold text-blue-400 uppercase tracking-widest">The Core Crisis</h2>
          <h3 className="text-2xl md:text-3xl font-bold text-white tracking-tight">
            Why Modern Security Operations Centers Are Broken
          </h3>
          <p className="text-sm text-gray-400">
            Defenders face an asymmetric battle. Traditional SIEM and SOAR platforms were designed for
            compliance checklists, not rapid adversarial containment.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1 */}
          <div className="rounded-2xl border border-rose-500/20 bg-gray-900/40 p-6 space-y-4">
            <div className="w-10 h-10 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400 font-bold">
              $
            </div>
            <h4 className="text-base font-bold text-white">The $100k+ Pricing Trap</h4>
            <p className="text-xs text-gray-400 leading-relaxed">
              Splunk, Sentinel, and CrowdStrike charge exorbitant per-gigabyte ingestion fees ranging from
              $50,000 to over $250,000 annually. Small teams and startups are economically locked out of
              enterprise defense.
            </p>
          </div>

          {/* Card 2 */}
          <div className="rounded-2xl border border-amber-500/20 bg-gray-900/40 p-6 space-y-4">
            <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center text-amber-400 font-bold">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <h4 className="text-base font-bold text-white">80% False Positive Fatigue</h4>
            <p className="text-xs text-gray-400 leading-relaxed">
              Security analysts receive over 10,000 disconnected alerts daily. Tier-1 analysts spend 70% of
              their shifts manually copying IPs, searching reputation feeds, and writing repetitive notes.
            </p>
          </div>

          {/* Card 3 */}
          <div className="rounded-2xl border border-purple-500/20 bg-gray-900/40 p-6 space-y-4">
            <div className="w-10 h-10 rounded-xl bg-purple-500/10 border border-purple-500/20 flex items-center justify-center text-purple-400 font-bold">
              <Bot className="w-5 h-5" />
            </div>
            <h4 className="text-base font-bold text-white">The Danger of Black-Box AI</h4>
            <p className="text-xs text-gray-400 leading-relaxed">
              Autonomous SOAR bots that take actions without human validation risk knocking mission-critical
              production servers or executive identities offline when language models hallucinate.
            </p>
          </div>
        </div>
      </section>

      {/* 3. The 4 Pillars of SOC Copilot */}
      <section className="space-y-8">
        <div className="text-center max-w-3xl mx-auto space-y-3">
          <h2 className="text-xs font-bold text-emerald-400 uppercase tracking-widest">Platform Capabilities</h2>
          <h3 className="text-2xl md:text-3xl font-bold text-white tracking-tight">
            How SOC Copilot Levels the Defense Playing Field
          </h3>
          <p className="text-sm text-gray-400">
            An integrated, end-to-end detection, correlation, and response engine built for speed, safety, and transparency.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Pillar 1 */}
          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/60 space-y-4 hover:border-blue-500/40 transition-colors">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <Layers className="w-5 h-5" />
              </div>
              <h4 className="text-base font-bold text-white">Multi-Source Ingestion & Active Drop</h4>
            </div>
            <p className="text-xs text-gray-300 leading-relaxed">
              Ingests raw telemetry across perimeter firewalls (KV), Nginx web logs (Combined format), and Linux
              authentication files. Enforces **Active Perimeter Containment**: subsequent packets from blocked IPs
              are dropped immediately at the ingestion boundary.
            </p>
            <div className="flex flex-wrap gap-2 pt-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Perimeter Firewall (KV)
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Nginx Web Server
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                Linux auth.log
              </span>
            </div>
          </div>

          {/* Pillar 2 */}
          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/60 space-y-4 hover:border-indigo-500/40 transition-colors">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                <Cpu className="w-5 h-5" />
              </div>
              <h4 className="text-base font-bold text-white">MITRE Kill-Chain Correlation Engine</h4>
            </div>
            <p className="text-xs text-gray-300 leading-relaxed">
              Uses sliding 10-minute temporal windows and IP/user pivot clustering to aggregate dozens of atomic
              signals into **a single unified incident campaign**, automatically escalating severity from Medium to
              Critical as the breach advances along the cyber kill chain.
            </p>
            <div className="flex flex-wrap gap-2 pt-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                10-Min Sliding Window
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                Pivot Clustering
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                Dynamic Titles
              </span>
            </div>
          </div>

          {/* Pillar 3 */}
          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/60 space-y-4 hover:border-emerald-500/40 transition-colors">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Bot className="w-5 h-5" />
              </div>
              <h4 className="text-base font-bold text-white">Gemini 3.5 Flash AI Triage (RAG)</h4>
            </div>
            <p className="text-xs text-gray-300 leading-relaxed">
              Injects the incident kill-chain graph and curated MITRE ATT&CK technique descriptions into
              Google Gemini 3.5 Flash. Delivers an executive summary, confidence rating, attacker goal analysis,
              and recommended containment actions in under 3 seconds.
            </p>
            <div className="flex flex-wrap gap-2 pt-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                RAG MITRE Knowledge
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Strict JSON Output
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Rotational Fallback
              </span>
            </div>
          </div>

          {/* Pillar 4 */}
          <div className="p-6 rounded-2xl border border-gray-800 bg-gray-900/60 space-y-4 hover:border-rose-500/40 transition-colors">
            <div className="flex items-center space-x-3">
              <div className="p-2.5 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/20">
                <Lock className="w-5 h-5" />
              </div>
              <h4 className="text-base font-bold text-white">Human-in-the-Loop Safe Containment</h4>
            </div>
            <p className="text-xs text-gray-300 leading-relaxed">
              AI provides recommendations, but execution strictly requires operator confirmation. Analysts review
              the operational justification in a confirmation modal before triggering 1-click firewall IP drops,
              identity revocation, or ticketing. Every action records an immutable audit log.
            </p>
            <div className="flex flex-wrap gap-2 pt-2">
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                1-Click Execution
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                Mandatory Analyst ID
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">
                Instant Rollback (Undo)
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* 4. Docker 1-Command Deployment */}
      <section className="rounded-2xl border border-gray-800 bg-gray-900/50 p-8 space-y-6">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center space-x-2 text-blue-400 text-xs font-semibold uppercase tracking-wider">
              <Terminal className="w-4 h-4" />
              <span>Zero-Dependency Deployment</span>
            </div>
            <h3 className="text-xl md:text-2xl font-bold text-white mt-1">
              Deploy SOC Copilot in 1 Command with Docker
            </h3>
            <p className="text-xs text-gray-400 mt-1">
              Multi-stage Docker builds orchestrate the FastAPI backend, React dashboard, and optional attack simulator.
            </p>
          </div>

          <button
            onClick={copyDockerCommand}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-200 text-xs font-mono border border-gray-700 transition-colors"
          >
            {copiedCmd ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{copiedCmd ? "Copied!" : "Copy Command"}</span>
          </button>
        </div>

        {/* Code Box */}
        <div className="bg-[#05080E] p-4 rounded-xl border border-gray-800 font-mono text-xs text-gray-300 overflow-x-auto space-y-2">
          <div className="text-gray-500"># 1. Clone the repository</div>
          <div className="text-blue-300">git clone https://github.com/your-org/soc-copilot.git && cd soc-copilot</div>
          <div className="text-gray-500 pt-2"># 2. Start full production stack via Docker Compose</div>
          <div className="text-emerald-400 font-bold">docker compose up --build</div>
          <div className="text-gray-500 pt-2"># 3. Access dashboard at http://localhost:5173</div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2 text-xs">
          <div className="flex items-center space-x-2 text-gray-300">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>Multi-stage Nginx production proxy</span>
          </div>
          <div className="flex items-center space-x-2 text-gray-300">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>Persistent Docker SQLite volume</span>
          </div>
          <div className="flex items-center space-x-2 text-gray-300">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
            <span>Automated attack simulator demo profile</span>
          </div>
        </div>
      </section>

      {/* 5. Enterprise Comparison Matrix */}
      <section className="space-y-6">
        <div className="text-center max-w-2xl mx-auto space-y-2">
          <h2 className="text-xs font-bold text-indigo-400 uppercase tracking-widest">Market Comparison</h2>
          <h3 className="text-2xl font-bold text-white tracking-tight">
            How SOC Copilot Stacks Up
          </h3>
        </div>

        <div className="overflow-x-auto rounded-xl border border-gray-800 bg-gray-900/60 shadow-lg">
          <table className="w-full text-left text-xs text-gray-300">
            <thead className="bg-gray-950 text-gray-400 uppercase tracking-wider text-[11px] border-b border-gray-800">
              <tr>
                <th className="p-4 font-semibold">Evaluation Criteria</th>
                <th className="p-4 font-bold text-blue-400">SOC Copilot</th>
                <th className="p-4 font-semibold">Splunk ES</th>
                <th className="p-4 font-semibold">Microsoft Sentinel</th>
                <th className="p-4 font-semibold">CrowdStrike Falcon</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/80 font-sans">
              <tr>
                <td className="p-4 font-semibold text-white">Annual Software Cost</td>
                <td className="p-4 font-bold text-emerald-400">Free / Open-Source</td>
                <td className="p-4 text-rose-300">$50,000 – $250,000+</td>
                <td className="p-4 text-rose-300">$30,000 – $120,000+</td>
                <td className="p-4 text-rose-300">$100,000+</td>
              </tr>
              <tr>
                <td className="p-4 font-semibold text-white">Deployment Time</td>
                <td className="p-4 font-bold text-emerald-400">&lt; 5 minutes (Docker)</td>
                <td className="p-4 text-gray-400">Months (Professional svcs)</td>
                <td className="p-4 text-gray-400">Weeks (Azure tenant setup)</td>
                <td className="p-4 text-gray-400">Weeks (Agent rollout)</td>
              </tr>
              <tr>
                <td className="p-4 font-semibold text-white">AI Analyst Engine</td>
                <td className="p-4 font-bold text-emerald-400">Gemini 3.5 Flash (RAG)</td>
                <td className="p-4 text-gray-400">Paid add-on</td>
                <td className="p-4 text-gray-400">Security Copilot ($4/hr)</td>
                <td className="p-4 text-gray-400">Charlotte AI (Tiered add-on)</td>
              </tr>
              <tr>
                <td className="p-4 font-semibold text-white">Correlation Model</td>
                <td className="p-4 font-bold text-emerald-400">MITRE Kill-Chain Clustering</td>
                <td className="p-4 text-gray-400">Manual SPL queries</td>
                <td className="p-4 text-gray-400">Manual KQL analytics</td>
                <td className="p-4 text-gray-400">Proprietary ThreatGraph</td>
              </tr>
              <tr>
                <td className="p-4 font-semibold text-white">Human-in-the-Loop Safety</td>
                <td className="p-4 font-bold text-emerald-400">1-Click Modal & Audit Trail</td>
                <td className="p-4 text-gray-400">Complex SOAR scripts</td>
                <td className="p-4 text-gray-400">Logic Apps setup</td>
                <td className="p-4 text-gray-400">Manual RTR scripts</td>
              </tr>
              <tr>
                <td className="p-4 font-semibold text-white">Offline / Air-Gapped Mode</td>
                <td className="p-4 font-bold text-emerald-400">Yes (Dynamic Rotational Engine)</td>
                <td className="p-4 text-rose-400">No</td>
                <td className="p-4 text-rose-400">No</td>
                <td className="p-4 text-rose-400">No</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>

      {/* 6. Ready to Test CTA */}
      <section className="rounded-2xl border border-blue-500/30 bg-gradient-to-r from-blue-950/40 via-gray-900 to-indigo-950/40 p-8 text-center space-y-6">
        <h3 className="text-2xl md:text-3xl font-extrabold text-white tracking-tight">
          Experience Autonomous Cyber Defense in Action
        </h3>
        <p className="text-xs md:text-sm text-gray-300 max-w-xl mx-auto">
          Start the live operations center, trigger the 4-phase attack simulator, watch the kill-chain correlate
          in real time, and contain an active intrusion in one click.
        </p>
        <div className="flex flex-wrap justify-center gap-4">
          <Link
            to="/"
            className="px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-medium text-xs md:text-sm transition-all shadow-md shadow-blue-600/30"
          >
            Open Live Operations Center
          </Link>
          <Link
            to="/mitre"
            className="px-6 py-3 rounded-xl bg-gray-800 hover:bg-gray-700 text-gray-200 border border-gray-700 font-medium text-xs md:text-sm transition-all"
          >
            Explore MITRE Matrix
          </Link>
        </div>
      </section>
    </div>
  )
}

