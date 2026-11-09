import React, { useState } from "react"
import { NavLink } from "react-router-dom"
import {
  Shield,
  LayoutDashboard,
  AlertOctagon,
  Grid,
  Zap,
  Radio,
  CheckCircle,
  Play,
  RotateCw,
  X,
  Sparkles,
} from "lucide-react"
import { api } from "../api"

export default function Navbar({ wsConnected, backendStatus, onSimulationTriggered }) {
  const [simModalOpen, setSimModalOpen] = useState(false)
  const [isSimulating, setIsSimulating] = useState(false)
  const [simMessage, setSimMessage] = useState("")

  const triggerSimulation = async (scenario) => {
    setIsSimulating(true)
    setSimMessage(`Injecting synthetic logs for ${scenario}...`)

    try {
      // Build realistic simulation logs according to scenario
      let lines = []
      let source = "ssh"

      if (scenario === "full_attack_chain") {
        const attackerIp = "185.220.101.5"
        // 1. Port scan
        for (let p = 20; p <= 45; p++) {
          lines.push(
            `timestamp=2024-01-01T12:00:00Z devname="FW-CORE-01" action="deny" srcip=${attackerIp} dstip=10.0.0.15 srcport=43210 dstport=${p} proto=tcp bytes=60 msg="Packet dropped"`
          )
        }
        await api.ingestLogs({ source: "firewall", lines })

        // 2. SSH Brute Force
        lines = []
        for (let i = 0; i < 15; i++) {
          lines.push(
            `Jan 01 12:01:${(10 + i).toString().padStart(2, "0")} soc-prod-srv01 sshd[1234]: Failed password for invalid user admin from ${attackerIp} port ${45000 + i} ssh2`
          )
        }
        await api.ingestLogs({ source: "ssh", lines })

        // 3. Accepted login
        await api.ingestLogs({
          source: "ssh",
          lines: [
            `Jan 01 12:02:00 soc-prod-srv01 sshd[1250]: Accepted password for admin from ${attackerIp} port 45020 ssh2`,
            `Jan 01 12:02:01 soc-prod-srv01 sshd[1250]: pam_unix(sshd:session): session opened for user admin by (uid=0)`,
          ],
        })

        // 4. Large Outbound Transfer (Exfil)
        await api.ingestLogs({
          source: "firewall",
          lines: [
            `timestamp=2024-01-01T12:02:30Z devname="FW-CORE-01" action="allow" srcip=10.0.0.15 dstip=${attackerIp} srcport=45000 dstport=443 proto=tcp bytes=75000000 msg="Inbound connection allowed"`,
          ],
        })
      } else if (scenario === "ssh_bruteforce") {
        const attackerIp = "194.26.29.112"
        for (let i = 0; i < 15; i++) {
          lines.push(
            `Jan 01 12:00:${(10 + i).toString().padStart(2, "0")} soc-prod-srv01 sshd[2222]: Failed password for root from ${attackerIp} port ${42000 + i} ssh2`
          )
        }
        await api.ingestLogs({ source: "ssh", lines })
      } else if (scenario === "sql_injection") {
        const attackerIp = "45.154.255.89"
        lines = [
          `${attackerIp} - - [01/Jan/2024:12:00:00 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 200 4500 "-" "sqlmap/1.7"`,
          `${attackerIp} - - [01/Jan/2024:12:00:01 +0000] "GET /login?user=admin%27%20OR%201=1-- HTTP/1.1" 500 1200 "-" "sqlmap/1.7"`,
        ]
        await api.ingestLogs({ source: "web", lines })
      } else if (scenario === "port_scan") {
        const attackerIp = "103.203.57.18"
        for (let p = 1000; p <= 1025; p++) {
          lines.push(
            `timestamp=2024-01-01T12:00:00Z devname="FW-CORE-01" action="deny" srcip=${attackerIp} dstip=10.0.0.15 srcport=50000 dstport=${p} proto=tcp bytes=64 msg="Packet dropped"`
          )
        }
        await api.ingestLogs({ source: "firewall", lines })
      }

      setSimMessage(`Success! Ingested telemetry for ${scenario}. Detections & correlation triggered.`)
      if (onSimulationTriggered) onSimulationTriggered()
      setTimeout(() => {
        setIsSimulating(false)
        setSimModalOpen(false)
        setSimMessage("")
      }, 1500)
    } catch (err) {
      setSimMessage(`Simulation failed: ${err.message}`)
      setIsSimulating(false)
    }
  }

  return (
    <>
      <header className="border-b border-gray-800 bg-[#0B0F17]/95 backdrop-blur-md sticky top-0 z-40 px-6 py-3.5">
        <div className="max-w-7xl mx-auto flex items-center justify-between">
          {/* Logo & Navigation */}
          <div className="flex items-center space-x-8">
            <NavLink to="/" className="flex items-center space-x-3 group">
              <div className="p-2 bg-blue-600/20 text-blue-400 rounded-lg border border-blue-500/30 group-hover:border-blue-500/60 transition-colors">
                <Shield className="w-5 h-5 text-blue-400" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold tracking-tight text-white">
                    SOC Copilot
                  </span>
                  <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    Autonomous
                  </span>
                </div>
                <p className="text-[11px] text-gray-400">AI Threat Correlation & Response</p>
              </div>
            </NavLink>

            <nav className="hidden md:flex items-center space-x-1">
              <NavLink
                to="/"
                end
                className={({ isActive }) =>
                  `flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    isActive
                      ? "bg-blue-600/15 text-blue-400 border border-blue-500/30"
                      : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                  }`
                }
              >
                <LayoutDashboard className="w-3.5 h-3.5" />
                <span>Overview</span>
              </NavLink>

              <NavLink
                to="/incidents"
                className={({ isActive }) =>
                  `flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    isActive
                      ? "bg-blue-600/15 text-blue-400 border border-blue-500/30"
                      : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                  }`
                }
              >
                <AlertOctagon className="w-3.5 h-3.5" />
                <span>Incidents</span>
              </NavLink>

              <NavLink
                to="/mitre"
                className={({ isActive }) =>
                  `flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    isActive
                      ? "bg-blue-600/15 text-blue-400 border border-blue-500/30"
                      : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                  }`
                }
              >
                <Grid className="w-3.5 h-3.5" />
                <span>MITRE Matrix</span>
              </NavLink>

              <NavLink
                to="/response"
                className={({ isActive }) =>
                  `flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    isActive
                      ? "bg-blue-600/15 text-blue-400 border border-blue-500/30"
                      : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                  }`
                }
              >
                <Zap className="w-3.5 h-3.5" />
                <span>Response Center</span>
              </NavLink>

              <NavLink
                to="/about"
                className={({ isActive }) =>
                  `flex items-center space-x-2 px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                    isActive
                      ? "bg-blue-600/15 text-blue-400 border border-blue-500/30"
                      : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                  }`
                }
              >
                <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                <span>Showcase</span>
              </NavLink>
            </nav>
          </div>

          {/* Right Status Badges & Simulator Trigger */}
          <div className="flex items-center space-x-3">
            <button
              onClick={() => setSimModalOpen(true)}
              className="flex items-center space-x-1.5 text-xs font-medium px-3 py-1.5 rounded-lg bg-emerald-600/20 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-600/30 transition-all shadow-sm shadow-emerald-950/40"
            >
              <Play className="w-3.5 h-3.5 fill-emerald-400" />
              <span>Simulate Attack</span>
            </button>

            <div className="hidden sm:flex items-center space-x-2 text-xs px-2.5 py-1.5 rounded-md bg-gray-900 border border-gray-800">
              <Radio
                className={`w-3.5 h-3.5 ${
                  wsConnected ? "text-emerald-400 animate-pulse" : "text-gray-500"
                }`}
              />
              <span className="text-gray-400">WS:</span>
              <span className={wsConnected ? "text-emerald-400 font-medium" : "text-gray-500"}>
                {wsConnected ? "Live" : "Polling"}
              </span>
            </div>

            <div className="hidden sm:flex items-center space-x-2 text-xs px-2.5 py-1.5 rounded-md bg-gray-900 border border-gray-800">
              <CheckCircle
                className={`w-3.5 h-3.5 ${
                  backendStatus === "Online" ? "text-emerald-400" : "text-rose-400"
                }`}
              />
              <span className="text-gray-400">API:</span>
              <span
                className={
                  backendStatus === "Online" ? "text-emerald-400 font-medium" : "text-rose-400"
                }
              >
                {backendStatus}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Simulation Modal */}
      {simModalOpen && (
        <div className="fixed inset-0 z-[9999] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-md w-full p-6 space-y-4 shadow-2xl animate-in fade-in zoom-in-95">
            <div className="flex items-center justify-between pb-3 border-b border-gray-800">
              <div className="flex items-center space-x-2">
                <Play className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-semibold text-white">Live Attack Simulator</h3>
              </div>
              <button
                onClick={() => setSimModalOpen(false)}
                className="text-gray-400 hover:text-white"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-gray-400 leading-relaxed">
              Inject synthetic attack telemetry into the SOC Copilot ingestion pipeline.
              Watch the detection rules fire, alerts correlate into an incident, and Gemini generate automated triage.
            </p>

            <div className="space-y-2">
              <button
                disabled={isSimulating}
                onClick={() => triggerSimulation("full_attack_chain")}
                className="w-full text-left p-3 rounded-lg bg-gray-800/80 hover:bg-gray-800 border border-rose-500/30 hover:border-rose-500/60 transition-all text-xs group"
              >
                <div className="font-semibold text-rose-400 group-hover:text-rose-300">
                  Full Attack Chain (Multi-Stage Critical)
                </div>
                <div className="text-gray-400 text-[11px] mt-0.5">
                  Port Scan → SSH Brute Force → Valid Login → Massive Exfiltration (185.220.101.5)
                </div>
              </button>

              <button
                disabled={isSimulating}
                onClick={() => triggerSimulation("ssh_bruteforce")}
                className="w-full text-left p-3 rounded-lg bg-gray-800/60 hover:bg-gray-800 border border-amber-500/20 hover:border-amber-500/40 transition-all text-xs group"
              >
                <div className="font-semibold text-amber-400 group-hover:text-amber-300">
                  SSH Brute Force Attack
                </div>
                <div className="text-gray-400 text-[11px] mt-0.5">
                  15 rapid failed authentications against root user (194.26.29.112)
                </div>
              </button>

              <button
                disabled={isSimulating}
                onClick={() => triggerSimulation("sql_injection")}
                className="w-full text-left p-3 rounded-lg bg-gray-800/60 hover:bg-gray-800 border border-blue-500/20 hover:border-blue-500/40 transition-all text-xs group"
              >
                <div className="font-semibold text-blue-400 group-hover:text-blue-300">
                  SQL Injection Web Attack
                </div>
                <div className="text-gray-400 text-[11px] mt-0.5">
                  Web server exploits with UNION SELECT patterns & sqlmap user-agent
                </div>
              </button>

              <button
                disabled={isSimulating}
                onClick={() => triggerSimulation("port_scan")}
                className="w-full text-left p-3 rounded-lg bg-gray-800/60 hover:bg-gray-800 border border-purple-500/20 hover:border-purple-500/40 transition-all text-xs group"
              >
                <div className="font-semibold text-purple-400 group-hover:text-purple-300">
                  Perimeter Port Scan
                </div>
                <div className="text-gray-400 text-[11px] mt-0.5">
                  Firewall drops across 25 distinct destination ports (103.203.57.18)
                </div>
              </button>
            </div>

            {simMessage && (
              <div className="p-2.5 rounded-lg bg-gray-800 border border-gray-700 text-xs flex items-center space-x-2 text-gray-300">
                {isSimulating && <RotateCw className="w-3.5 h-3.5 animate-spin text-blue-400" />}
                <span>{simMessage}</span>
              </div>
            )}
          </div>
        </div>
      )}
    </>
  )
}

