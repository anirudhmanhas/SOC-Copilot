import React, { useEffect, useState } from "react"
import {
  ShieldAlert,
  ShieldCheck,
  UserX,
  Ticket,
  ScrollText,
  RefreshCw,
  RotateCcw,
  Clock,
  CheckCircle2,
  AlertTriangle,
} from "lucide-react"
import { api } from "../api"

export default function ResponseCenter() {
  const [activeTab, setActiveTab] = useState("blocked_ips")
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [feedback, setFeedback] = useState(null)

  // Data states
  const [blockedIps, setBlockedIps] = useState([])
  const [disabledUsers, setDisabledUsers] = useState([])
  const [tickets, setTickets] = useState([])
  const [auditLogs, setAuditLogs] = useState([])

  const loadData = async () => {
    try {
      const [ips, users, tix, audits] = await Promise.all([
        api.getBlockedIPs().catch(() => []),
        api.getDisabledUsers().catch(() => []),
        api.getTickets().catch(() => []),
        api.getAuditLogs().catch(() => []),
      ])
      setBlockedIps(ips)
      setDisabledUsers(users)
      setTickets(tix)
      setAuditLogs(audits)
    } catch (err) {
      console.error("Failed to load response data:", err)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 8000)
    return () => clearInterval(interval)
  }, [])

  const handleRefresh = () => {
    setRefreshing(true)
    loadData()
  }

  // Undo Unblock IP
  const handleUnblock = async (ip) => {
    try {
      await api.unblockIP(ip, "SOC Lead Analyst")
      setFeedback({ type: "success", text: `Successfully unblocked IP address ${ip}.` })
      await loadData()
    } catch (err) {
      setFeedback({ type: "error", text: `Failed to unblock IP: ${err.message}` })
    }
  }

  // Undo Enable User
  const handleEnableUser = async (username) => {
    try {
      await api.enableUser(username, "SOC Lead Analyst")
      setFeedback({ type: "success", text: `Successfully re-enabled user account '${username}'.` })
      await loadData()
    } catch (err) {
      setFeedback({ type: "error", text: `Failed to enable user: ${err.message}` })
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-gray-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            Incident Response Center
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              Active Containment
            </span>
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Audit trail of perimeter firewall block rules, identity revocations, ticketing integrations, and undo capabilities.
          </p>
        </div>

        <button
          onClick={handleRefresh}
          disabled={refreshing}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 hover:bg-gray-800 text-xs text-gray-300 transition-colors self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-blue-400" : ""}`} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Feedback banner */}
      {feedback && (
        <div
          className={`p-3 rounded-lg text-xs flex items-center space-x-2 ${
            feedback.type === "success"
              ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20"
              : "bg-rose-500/10 text-rose-300 border border-rose-500/20"
          }`}
        >
          {feedback.type === "success" ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          )}
          <span>{feedback.text}</span>
        </div>
      )}

      {/* Tabs */}
      <div className="flex items-center space-x-2 border-b border-gray-800 pb-px">
        <button
          onClick={() => setActiveTab("blocked_ips")}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all ${
            activeTab === "blocked_ips"
              ? "border-rose-500 text-rose-400 bg-rose-500/5"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <ShieldAlert className="w-4 h-4" />
          <span>Firewall Blocked IPs</span>
          <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] bg-gray-800 text-gray-300">
            {blockedIps.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("disabled_users")}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all ${
            activeTab === "disabled_users"
              ? "border-amber-500 text-amber-400 bg-amber-500/5"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <UserX className="w-4 h-4" />
          <span>Disabled User Accounts</span>
          <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] bg-gray-800 text-gray-300">
            {disabledUsers.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("tickets")}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all ${
            activeTab === "tickets"
              ? "border-blue-500 text-blue-400 bg-blue-500/5"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <Ticket className="w-4 h-4" />
          <span>SOC Tickets</span>
          <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] bg-gray-800 text-gray-300">
            {tickets.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab("audit_logs")}
          className={`flex items-center space-x-2 px-4 py-2.5 text-xs font-medium border-b-2 transition-all ${
            activeTab === "audit_logs"
              ? "border-purple-500 text-purple-400 bg-purple-500/5"
              : "border-transparent text-gray-400 hover:text-gray-200"
          }`}
        >
          <ScrollText className="w-4 h-4" />
          <span>Audit Log Trail</span>
          <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] bg-gray-800 text-gray-300">
            {auditLogs.length}
          </span>
        </button>
      </div>

      {/* Tab Panels */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/70 overflow-hidden shadow-sm">
        {loading ? (
          <div className="p-12 text-center text-xs text-gray-500">Loading response data...</div>
        ) : (
          <>
            {/* TAB 1: BLOCKED IPS */}
            {activeTab === "blocked_ips" && (
              <div className="overflow-x-auto">
                {blockedIps.length === 0 ? (
                  <div className="p-12 text-center text-gray-500 text-xs">
                    No IPs are currently in the firewall blocklist.
                  </div>
                ) : (
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-gray-800 bg-gray-900 text-[11px] uppercase tracking-wider text-gray-400 font-semibold">
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">IP Address</th>
                        <th className="py-3 px-4">Blocked At</th>
                        <th className="py-3 px-4">Reason / Incident</th>
                        <th className="py-3 px-4 text-right">Undo Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800/60 font-mono text-gray-300">
                      {blockedIps.map((ip) => (
                        <tr key={ip.id} className="hover:bg-gray-800/40 transition-colors">
                          <td className="py-3.5 px-4">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider ${
                                ip.status === "active"
                                  ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                                  : "bg-gray-800 text-gray-400 border border-gray-700"
                              }`}
                            >
                              {ip.status}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 font-bold text-white">{ip.ip_address}</td>
                          <td className="py-3.5 px-4 text-gray-400">
                            {new Date(ip.blocked_at).toLocaleString()}
                          </td>
                          <td className="py-3.5 px-4 text-gray-300 font-sans max-w-sm truncate">
                            {ip.reason || "Perimeter firewall containment"}
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            {ip.status === "active" ? (
                              <button
                                onClick={() => handleUnblock(ip.ip_address)}
                                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-rose-400 hover:text-rose-300 font-sans font-medium transition-colors"
                              >
                                <RotateCcw className="w-3 h-3" />
                                <span>Unblock IP</span>
                              </button>
                            ) : (
                              <span className="text-gray-500 font-sans text-[11px]">Unblocked</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* TAB 2: DISABLED USERS */}
            {activeTab === "disabled_users" && (
              <div className="overflow-x-auto">
                {disabledUsers.length === 0 ? (
                  <div className="p-12 text-center text-gray-500 text-xs">
                    No user accounts have been disabled.
                  </div>
                ) : (
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-gray-800 bg-gray-900 text-[11px] uppercase tracking-wider text-gray-400 font-semibold">
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Username</th>
                        <th className="py-3 px-4">Disabled At</th>
                        <th className="py-3 px-4">Reason / Incident</th>
                        <th className="py-3 px-4 text-right">Undo Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800/60 font-mono text-gray-300">
                      {disabledUsers.map((u) => (
                        <tr key={u.id} className="hover:bg-gray-800/40 transition-colors">
                          <td className="py-3.5 px-4">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider ${
                                u.status === "disabled"
                                  ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                                  : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                              }`}
                            >
                              {u.status}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 font-bold text-white">{u.username}</td>
                          <td className="py-3.5 px-4 text-gray-400">
                            {new Date(u.disabled_at).toLocaleString()}
                          </td>
                          <td className="py-3.5 px-4 text-gray-300 font-sans max-w-sm truncate">
                            {u.reason || "Account revoked"}
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            {u.status === "disabled" ? (
                              <button
                                onClick={() => handleEnableUser(u.username)}
                                className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-emerald-400 hover:text-emerald-300 font-sans font-medium transition-colors"
                              >
                                <RotateCcw className="w-3 h-3" />
                                <span>Re-enable</span>
                              </button>
                            ) : (
                              <span className="text-gray-500 font-sans text-[11px]">Enabled</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* TAB 3: TICKETS */}
            {activeTab === "tickets" && (
              <div className="overflow-x-auto">
                {tickets.length === 0 ? (
                  <div className="p-12 text-center text-gray-500 text-xs">
                    No tickets have been created yet.
                  </div>
                ) : (
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-gray-800 bg-gray-900 text-[11px] uppercase tracking-wider text-gray-400 font-semibold">
                        <th className="py-3 px-4">Ticket #</th>
                        <th className="py-3 px-4">Severity</th>
                        <th className="py-3 px-4">Subject</th>
                        <th className="py-3 px-4">Created At</th>
                        <th className="py-3 px-4">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800/60 text-gray-300 font-sans">
                      {tickets.map((t) => (
                        <tr key={t.id} className="hover:bg-gray-800/40 transition-colors">
                          <td className="py-3.5 px-4 font-mono font-bold text-blue-400">
                            {t.ticket_number}
                          </td>
                          <td className="py-3.5 px-4">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider font-mono ${
                                t.severity === "critical"
                                  ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                                  : t.severity === "high"
                                  ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                                  : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                              }`}
                            >
                              {t.severity}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 font-medium text-white max-w-sm truncate">
                            {t.title}
                          </td>
                          <td className="py-3.5 px-4 text-gray-400 font-mono text-[11px]">
                            {new Date(t.created_at).toLocaleString()}
                          </td>
                          <td className="py-3.5 px-4">
                            <span className="px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 capitalize font-mono">
                              {t.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}

            {/* TAB 4: AUDIT LOG TRAIL */}
            {activeTab === "audit_logs" && (
              <div className="overflow-x-auto">
                {auditLogs.length === 0 ? (
                  <div className="p-12 text-center text-gray-500 text-xs">
                    No audit records recorded yet.
                  </div>
                ) : (
                  <table className="w-full text-left text-xs">
                    <thead>
                      <tr className="border-b border-gray-800 bg-gray-900 text-[11px] uppercase tracking-wider text-gray-400 font-semibold">
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4">Action</th>
                        <th className="py-3 px-4">Target</th>
                        <th className="py-3 px-4">Analyst</th>
                        <th className="py-3 px-4">Status</th>
                        <th className="py-3 px-4">Audit Details</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800/60 font-mono text-gray-300">
                      {auditLogs.map((log) => (
                        <tr key={log.id} className="hover:bg-gray-800/40 transition-colors">
                          <td className="py-3 px-4 text-gray-400 text-[11px]">
                            {new Date(log.timestamp).toLocaleString()}
                          </td>
                          <td className="py-3 px-4 font-bold text-white capitalize">
                            {log.action.replace("_", " ")}
                          </td>
                          <td className="py-3 px-4 text-blue-300 font-bold">{log.target}</td>
                          <td className="py-3 px-4 text-gray-300 font-sans">{log.analyst}</td>
                          <td className="py-3 px-4">
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase">
                              {log.status}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-gray-400 font-sans text-[11px] max-w-sm truncate">
                            {log.details || "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

