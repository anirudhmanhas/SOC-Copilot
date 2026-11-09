import React, { useEffect, useState } from "react"
import { Link } from "react-router-dom"
import {
  AlertOctagon,
  Search,
  Filter,
  ArrowUpDown,
  ExternalLink,
  ShieldCheck,
  RefreshCw,
  Clock,
  User,
  Activity,
} from "lucide-react"
import { api } from "../api"

const SEVERITY_ORDER = { critical: 4, high: 3, medium: 2, low: 1 }

export default function Incidents() {
  const [incidents, setIncidents] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [search, setSearch] = useState("")
  const [severityFilter, setSeverityFilter] = useState("all")
  const [statusFilter, setStatusFilter] = useState("all")

  const fetchIncidents = async () => {
    try {
      const data = await api.getIncidents({ limit: 200 })
      setIncidents(data)
    } catch (err) {
      console.error("Failed to fetch incidents:", err)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchIncidents()
    const interval = setInterval(fetchIncidents, 6000)
    return () => clearInterval(interval)
  }, [])

  const handleRefresh = () => {
    setRefreshing(true)
    fetchIncidents()
  }

  // Filter & sort
  const filtered = incidents
    .filter((inc) => {
      const matchesSearch =
        !search ||
        inc.title?.toLowerCase().includes(search.toLowerCase()) ||
        inc.src_ip?.toLowerCase().includes(search.toLowerCase()) ||
        (inc.affected_users || []).some((u) => u.toLowerCase().includes(search.toLowerCase()))

      const matchesSeverity =
        severityFilter === "all" || inc.severity?.toLowerCase() === severityFilter

      const matchesStatus =
        statusFilter === "all" || inc.status?.toLowerCase() === statusFilter

      return matchesSearch && matchesSeverity && matchesStatus
    })
    .sort((a, b) => {
      const sevDiff = (SEVERITY_ORDER[b.severity] || 0) - (SEVERITY_ORDER[a.severity] || 0)
      if (sevDiff !== 0) return sevDiff
      return new Date(b.updated_at) - new Date(a.updated_at)
    })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-gray-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            Correlated Security Incidents
            <span className="text-xs font-mono font-medium px-2 py-0.5 rounded bg-gray-800 text-gray-300">
              {filtered.length} active
            </span>
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Atomic alerts grouped by attacker IP or compromised user within temporal sliding windows.
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

      {/* Filter Toolbar */}
      <div className="flex flex-col md:flex-row gap-3 items-stretch md:items-center justify-between">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-gray-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search by IP, title, or user..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 transition-colors"
          />
        </div>

        <div className="flex items-center space-x-2">
          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          {/* Status Filter */}
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-3 py-2 rounded-lg bg-gray-900 border border-gray-800 text-xs text-gray-300 focus:outline-none focus:border-blue-500"
          >
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="contained">Contained</option>
            <option value="closed">Closed</option>
          </select>
        </div>
      </div>

      {/* Incidents Table */}
      <div className="rounded-xl border border-gray-800 bg-gray-900/70 overflow-hidden shadow-sm">
        {loading ? (
          <div className="p-12 text-center text-xs text-gray-500">Loading incidents...</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-gray-500 space-y-2">
            <ShieldCheck className="w-8 h-8 mx-auto text-gray-600" />
            <p className="text-xs font-medium text-gray-400">No incidents match the selected filters.</p>
            <p className="text-[11px] text-gray-600">
              Clear filters or trigger an attack simulation to populate events.
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead>
                <tr className="border-b border-gray-800 bg-gray-900 text-[11px] uppercase tracking-wider text-gray-400 font-semibold">
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Incident Title</th>
                  <th className="py-3 px-4">Attacker IP</th>
                  <th className="py-3 px-4">Targeted Users</th>
                  <th className="py-3 px-4">MITRE ATT&CK</th>
                  <th className="py-3 px-4">Status</th>
                  <th className="py-3 px-4 text-right">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/60 text-gray-300">
                {filtered.map((inc) => (
                  <tr
                    key={inc.id}
                    className="hover:bg-gray-800/40 transition-colors group cursor-pointer"
                  >
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                          inc.severity === "critical"
                            ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                            : inc.severity === "high"
                            ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                            : inc.severity === "medium"
                            ? "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                            : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                        }`}
                      >
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 font-medium text-white max-w-[280px]">
                      <Link
                        to={`/incidents/${inc.id}`}
                        className="hover:text-blue-400 transition-colors block truncate"
                      >
                        {inc.title}
                      </Link>
                      <div className="text-[11px] text-gray-500 flex items-center gap-1.5 mt-0.5">
                        <Clock className="w-3 h-3" />
                        <span>{new Date(inc.created_at).toLocaleString()}</span>
                      </div>
                    </td>
                    <td className="py-3.5 px-4 font-mono text-gray-300">
                      {inc.src_ip || "—"}
                    </td>
                    <td className="py-3.5 px-4">
                      {inc.affected_users && inc.affected_users.length > 0 ? (
                        <div className="flex flex-wrap gap-1">
                          {inc.affected_users.map((u, i) => (
                            <span
                              key={i}
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-gray-800 text-[11px] text-gray-300 font-mono"
                            >
                              <User className="w-2.5 h-2.5 text-gray-500" />
                              {u}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-gray-600">—</span>
                      )}
                    </td>
                    <td className="py-3.5 px-4">
                      <div className="flex flex-wrap gap-1 max-w-[180px]">
                        {(inc.mitre_techniques || []).map((tech, i) => (
                          <span
                            key={i}
                            className="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-400 border border-purple-500/20 text-[10px] font-mono"
                          >
                            {tech}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 text-[11px] ${
                          inc.status === "contained"
                            ? "text-emerald-400"
                            : inc.status === "investigating"
                            ? "text-blue-400"
                            : inc.status === "closed"
                            ? "text-gray-500"
                            : "text-amber-400"
                        }`}
                      >
                        <span
                          className={`w-1.5 h-1.5 rounded-full ${
                            inc.status === "contained"
                              ? "bg-emerald-400"
                              : inc.status === "investigating"
                              ? "bg-blue-400"
                              : inc.status === "closed"
                              ? "bg-gray-500"
                              : "bg-amber-400 animate-pulse"
                          }`}
                        />
                        <span className="capitalize">{inc.status}</span>
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <Link
                        to={`/incidents/${inc.id}`}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-gray-800 hover:bg-gray-700 text-blue-400 hover:text-blue-300 font-medium transition-colors"
                      >
                        <span>Investigate</span>
                        <ExternalLink className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

