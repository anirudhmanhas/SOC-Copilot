import React, { useEffect, useState } from "react"
import { Grid, ShieldAlert, CheckCircle, Info, RefreshCw } from "lucide-react"
import { api } from "../api"

const MITRE_TACTICS = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
]

export default function MitreMatrix() {
  const [rules, setRules] = useState([])
  const [alerts, setAlerts] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedTech, setSelectedTech] = useState(null)

  const fetchData = async () => {
    try {
      const [rulesData, alertsData] = await Promise.all([
        api.getRules().catch(() => []),
        api.getAlerts({ limit: 500 }).catch(() => []),
      ])
      setRules(rulesData)
      setAlerts(alertsData)
    } catch (err) {
      console.error("Failed to load MITRE data:", err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
  }, [])

  // Aggregate technique alerts count
  const techniqueHits = {}
  alerts.forEach((a) => {
    if (a.mitre_technique_id) {
      techniqueHits[a.mitre_technique_id] = (techniqueHits[a.mitre_technique_id] || 0) + 1
    }
  })

  // Group rules/techniques under each tactic
  const tacticColumns = {}
  MITRE_TACTICS.forEach((t) => {
    tacticColumns[t] = []
  })

  rules.forEach((rule) => {
    const tactic = rule.mitre_tactic || "Initial Access"
    if (!tacticColumns[tactic]) {
      tacticColumns[tactic] = []
    }
    // Avoid duplicate techniques per column
    if (!tacticColumns[tactic].some((item) => item.id === rule.mitre_technique_id)) {
      tacticColumns[tactic].push({
        id: rule.mitre_technique_id,
        name: rule.mitre_technique_name || rule.name,
        description: rule.description,
        rule_name: rule.name,
        severity: rule.severity,
      })
    }
  })

  const totalDetections = Object.values(techniqueHits).reduce((a, b) => a + b, 0)
  const activeTechniquesCount = Object.keys(techniqueHits).length

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-gray-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            MITRE ATT&CK Matrix Heatmap
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20">
              v14 Enterprise
            </span>
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Tactical kill-chain heatmap mapping rule detections to adversary techniques.
          </p>
        </div>

        <div className="flex items-center space-x-3 text-xs">
          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 animate-pulse" />
            <span className="text-gray-400">Triggered Techniques:</span>
            <span className="font-semibold text-rose-400">{activeTechniquesCount}</span>
          </div>

          <div className="flex items-center space-x-2 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800">
            <span className="text-gray-400">Total Alert Hits:</span>
            <span className="font-semibold text-white">{totalDetections}</span>
          </div>
        </div>
      </div>

      {/* Heatmap Grid */}
      <div className="rounded-xl border border-gray-800 bg-gray-950/70 p-4 overflow-x-auto shadow-inner">
        {loading ? (
          <div className="py-24 text-center text-xs text-gray-500">Loading MITRE Matrix...</div>
        ) : (
          <div className="flex space-x-3 min-w-[1400px]">
            {MITRE_TACTICS.map((tactic) => {
              const techniques = tacticColumns[tactic] || []
              const hasActiveHits = techniques.some((t) => (techniqueHits[t.id] || 0) > 0)

              return (
                <div key={tactic} className="w-48 flex-shrink-0 flex flex-col space-y-2">
                  {/* Tactic Column Header */}
                  <div
                    className={`p-2.5 rounded-lg border text-center transition-all ${
                      hasActiveHits
                        ? "bg-purple-950/40 border-purple-500/50 text-purple-300 shadow-sm shadow-purple-950/40"
                        : "bg-gray-900 border-gray-800 text-gray-300"
                    }`}
                  >
                    <div className="text-[11px] font-bold uppercase tracking-wider truncate">
                      {tactic}
                    </div>
                    <div className="text-[10px] text-gray-400 mt-0.5 font-mono">
                      {techniques.length} Techniques
                    </div>
                  </div>

                  {/* Technique Cells */}
                  <div className="space-y-2 flex-1">
                    {techniques.length === 0 ? (
                      <div className="p-2 text-center text-[10px] text-gray-600 border border-dashed border-gray-800/60 rounded-lg">
                        No rules mapped
                      </div>
                    ) : (
                      techniques.map((tech) => {
                        const hits = techniqueHits[tech.id] || 0
                        const isTriggered = hits > 0

                        return (
                          <div
                            key={tech.id}
                            onClick={() => setSelectedTech({ ...tech, hits })}
                            className={`p-2.5 rounded-lg border cursor-pointer transition-all ${
                              isTriggered
                                ? "bg-rose-950/40 border-rose-500/60 hover:border-rose-400 shadow-md shadow-rose-950/30"
                                : "bg-gray-900/60 border-gray-800 hover:border-gray-700 text-gray-400"
                            }`}
                          >
                            <div className="flex items-center justify-between gap-1">
                              <span
                                className={`text-[10px] font-mono font-bold ${
                                  isTriggered ? "text-rose-400" : "text-gray-400"
                                }`}
                              >
                                {tech.id}
                              </span>
                              {isTriggered && (
                                <span className="px-1.5 py-0.2 rounded-full text-[9px] font-bold bg-rose-500/20 text-rose-300 border border-rose-500/30">
                                  {hits} {hits === 1 ? "hit" : "hits"}
                                </span>
                              )}
                            </div>
                            <div
                              className={`text-[11px] font-medium mt-1 leading-snug line-clamp-2 ${
                                isTriggered ? "text-white" : "text-gray-300"
                              }`}
                            >
                              {tech.name}
                            </div>
                          </div>
                        )
                      })
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Selected Technique Details Drawer / Card */}
      {selectedTech && (
        <div className="p-5 rounded-xl bg-gray-900 border border-gray-800 shadow-lg space-y-3 animate-in fade-in">
          <div className="flex items-start justify-between">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">
                  {selectedTech.id}
                </span>
                <h3 className="text-sm font-bold text-white">{selectedTech.name}</h3>
                {selectedTech.hits > 0 && (
                  <span className="text-xs px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30 font-bold">
                    {selectedTech.hits} Triggered Detections
                  </span>
                )}
              </div>
              <p className="text-xs text-gray-300 leading-relaxed font-sans pt-1">
                {selectedTech.description}
              </p>
            </div>
            <button
              onClick={() => setSelectedTech(null)}
              className="text-xs text-gray-400 hover:text-white px-2 py-1 rounded bg-gray-800"
            >
              Close
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

