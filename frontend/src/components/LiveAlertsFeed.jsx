import React, { useState, useEffect } from "react"
import { ShieldAlert, AlertTriangle, Radio, X, ExternalLink, Clock, Shield } from "lucide-react"

export default function LiveAlertsFeed({ initialAlerts = [] }) {
  const [alerts, setAlerts] = useState(initialAlerts)
  const [toasts, setToasts] = useState([])
  const [filter, setFilter] = useState("all")

  // Sync initial alerts if prop updates
  useEffect(() => {
    if (initialAlerts.length > 0) {
      setAlerts((prev) => {
        // Merge without duplicates based on alert.id
        const existingIds = new Set(prev.map((a) => a.id))
        const newOnes = initialAlerts.filter((a) => !existingIds.has(a.id))
        return [...newOnes, ...prev].slice(0, 100)
      })
    }
  }, [initialAlerts])

  // Listen for real-time WebSocket events dispatched from App.jsx
  useEffect(() => {
    const handleWsEvent = (e) => {
      const event = e.detail
      if (!event) return

      if (event.type === "ALERT_TRIGGERED" && event.payload) {
        const newAlert = event.payload
        setAlerts((prev) => [newAlert, ...prev.filter((a) => a.id !== newAlert.id)].slice(0, 100))

        // Trigger toast notification
        const toastId = `${newAlert.id || Date.now()}-${Math.random()}`
        setToasts((prev) => [
          {
            id: toastId,
            rule_name: newAlert.rule_name,
            severity: newAlert.severity,
            src_ip: newAlert.src_ip,
            timestamp: newAlert.timestamp || new Date().toISOString(),
          },
          ...prev.slice(0, 4), // Keep max 5 toasts on screen
        ])

        // Auto-dismiss toast after 4.5 seconds
        setTimeout(() => {
          setToasts((prev) => prev.filter((t) => t.id !== toastId))
        }, 4500)
      }
    }

    window.addEventListener("soc-ws-event", handleWsEvent)
    return () => window.removeEventListener("soc-ws-event", handleWsEvent)
  }, [])

  const dismissToast = (toastId) => {
    setToasts((prev) => prev.filter((t) => t.id !== toastId))
  }

  // Filter alerts by severity
  const filteredAlerts = alerts.filter((a) => {
    if (filter === "all") return true
    return a.severity?.toLowerCase() === filter
  })

  return (
    <>
      {/* Toast Notification Container (Fixed Top-Right) */}
      <div className="fixed top-16 right-6 z-[999] flex flex-col space-y-2 pointer-events-none max-w-sm w-full">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`pointer-events-auto p-3.5 rounded-xl border shadow-2xl backdrop-blur-md animate-in slide-in-from-top-3 flex items-start justify-between gap-3 ${
              toast.severity === "critical"
                ? "bg-rose-950/90 border-rose-500/70 text-rose-100 shadow-rose-950/50 critical-pulse-card"
                : toast.severity === "high"
                ? "bg-amber-950/90 border-amber-500/70 text-amber-100 shadow-amber-950/50"
                : "bg-gray-900/90 border-gray-700 text-gray-200"
            }`}
          >
            <div className="flex items-start space-x-2.5">
              <ShieldAlert
                className={`w-4 h-4 flex-shrink-0 mt-0.5 ${
                  toast.severity === "critical" ? "text-rose-400" : "text-amber-400"
                }`}
              />
              <div className="space-y-0.5 text-xs">
                <div className="flex items-center gap-1.5 font-bold">
                  <span className="uppercase text-[10px] px-1.5 py-0.2 rounded bg-black/40 font-mono">
                    {toast.severity}
                  </span>
                  <span className="truncate max-w-[200px]">{toast.rule_name}</span>
                </div>
                <div className="text-[11px] opacity-80 font-mono">
                  Attacker IP: {toast.src_ip || "Unknown"}
                </div>
              </div>
            </div>

            <button
              onClick={() => dismissToast(toast.id)}
              className="text-gray-400 hover:text-white p-0.5"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        ))}
      </div>

      {/* Live Alerts Feed Panel */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/70 p-5 shadow-sm space-y-4">
        {/* Panel Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-gray-800 pb-3">
          <div>
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <Radio className="w-4 h-4 text-emerald-400 animate-pulse" />
              <span>Real-Time Live Alerts Stream</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                Live WS Feed
              </span>
            </h2>
            <p className="text-xs text-gray-400">
              Instantaneous detection engine alerts updating in real time without browser reload
            </p>
          </div>

          {/* Severity Filter Pills */}
          <div className="flex items-center space-x-1 self-start sm:self-auto">
            {["all", "critical", "high", "medium", "low"].map((sev) => (
              <button
                key={sev}
                onClick={() => setFilter(sev)}
                className={`px-2.5 py-1 rounded text-[11px] font-medium capitalize transition-colors ${
                  filter === sev
                    ? "bg-blue-600 text-white"
                    : "bg-gray-800/80 text-gray-400 hover:text-gray-200"
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Alerts Feed List */}
        <div className="max-h-[380px] overflow-y-auto space-y-2 pr-1">
          {filteredAlerts.length === 0 ? (
            <div className="py-12 text-center text-gray-500 text-xs flex flex-col items-center justify-center space-y-2">
              <Shield className="w-8 h-8 text-gray-600" />
              <span>No alerts matching the selected filter.</span>
              <span className="text-[11px] text-gray-600">
                Trigger an attack simulation from the navbar to see detections stream in live.
              </span>
            </div>
          ) : (
            filteredAlerts.map((alert) => {
              const isCritical = alert.severity?.toLowerCase() === "critical"
              const isHigh = alert.severity?.toLowerCase() === "high"

              return (
                <div
                  key={alert.id || `${alert.rule_id}-${alert.timestamp}`}
                  className={`p-3 rounded-lg border transition-all flex flex-col sm:flex-row sm:items-center justify-between gap-2.5 text-xs ${
                    isCritical
                      ? "bg-rose-950/30 border-rose-500/60 critical-pulse-card text-rose-100"
                      : isHigh
                      ? "bg-gray-900/90 border-amber-500/40 text-gray-200 hover:border-amber-500/60"
                      : "bg-gray-900/60 border-gray-800 text-gray-300 hover:border-gray-700"
                  }`}
                >
                  <div className="space-y-1">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono ${
                          isCritical
                            ? "bg-rose-500/20 text-rose-300 border border-rose-500/40"
                            : isHigh
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                            : "bg-blue-500/20 text-blue-300 border border-blue-500/40"
                        }`}
                      >
                        {alert.severity}
                      </span>
                      <span className="font-semibold text-white">{alert.rule_name}</span>
                      {alert.mitre_technique_id && (
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-purple-500/10 text-purple-300 border border-purple-500/20">
                          {alert.mitre_technique_id}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-gray-300 leading-snug line-clamp-1">
                      {alert.description}
                    </p>
                  </div>

                  <div className="flex items-center space-x-3 text-[11px] font-mono text-gray-400 flex-shrink-0 self-end sm:self-center">
                    {alert.src_ip && (
                      <span className="px-2 py-0.5 rounded bg-gray-950 border border-gray-800 text-gray-300">
                        {alert.src_ip}
                      </span>
                    )}
                    <div className="flex items-center space-x-1 text-gray-400">
                      <Clock className="w-3 h-3" />
                      <span>
                        {alert.timestamp
                          ? new Date(alert.timestamp).toLocaleTimeString()
                          : "Just now"}
                      </span>
                    </div>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>
    </>
  )
}

