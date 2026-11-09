import React, { useEffect, useState } from "react"
import { Link } from "react-router-dom"
import {
  ShieldAlert,
  AlertOctagon,
  Database,
  ShieldCheck,
  TrendingUp,
  ArrowRight,
  RefreshCw,
  ExternalLink,
} from "lucide-react"
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
} from "recharts"
import { api } from "../api"
import AttackMap from "../components/AttackMap"
import LiveAlertsFeed from "../components/LiveAlertsFeed"

const SEVERITY_COLORS = {
  critical: "#EF4444",
  high: "#F59E0B",
  medium: "#3B82F6",
  low: "#10B981",
}

export default function Overview() {
  const [loading, setLoading] = useState(true)
  const [logs, setLogs] = useState([])
  const [alerts, setAlerts] = useState([])
  const [incidents, setIncidents] = useState([])
  const [blockedIps, setBlockedIps] = useState([])
  const [refreshing, setRefreshing] = useState(false)

  const fetchData = async () => {
    try {
      const [logsData, alertsData, incidentsData, blockedData] = await Promise.all([
        api.getLogs({ limit: 500 }).catch(() => []),
        api.getAlerts({ limit: 500 }).catch(() => []),
        api.getIncidents({ limit: 100 }).catch(() => []),
        api.getBlockedIPs({ status: "active" }).catch(() => []),
      ])
      setLogs(logsData)
      setAlerts(alertsData)
      setIncidents(incidentsData)
      setBlockedIps(blockedData)
    } catch (err) {
      console.error("Failed to load overview data:", err)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 8000)

    const handleWsEvent = (e) => {
      const event = e.detail
      if (!event) return
      // When any security event or log ingestion occurs, refresh metrics without full reload
      if (
        event.type === "ALERT_TRIGGERED" ||
        event.type === "INCIDENT_UPDATED" ||
        event.type === "ACTION_EXECUTED" ||
        event.type === "ACTION_UNDONE" ||
        event.type === "LOGS_INGESTED"
      ) {
        fetchData()
      }
    }

    window.addEventListener("soc-ws-event", handleWsEvent)
    return () => {
      clearInterval(interval)
      window.removeEventListener("soc-ws-event", handleWsEvent)
    }
  }, [])

  const handleManualRefresh = () => {
    setRefreshing(true)
    fetchData()
  }

  // Calculate Metrics
  const totalEvents = logs.length
  const openIncidents = incidents.filter((i) => i.status !== "closed").length
  const criticalAlerts = alerts.filter((a) => a.severity === "critical").length
  const activeBlockedCount = blockedIps.length

  // Build events-over-time chart data (grouped by minute)
  const timelineMap = {}
  logs.forEach((log) => {
    const d = new Date(log.timestamp)
    const key = `${d.getHours().toString().padStart(2, "0")}:${d
      .getMinutes()
      .toString()
      .padStart(2, "0")}`
    timelineMap[key] = (timelineMap[key] || 0) + 1
  })
  const timelineData = Object.keys(timelineMap)
    .sort()
    .slice(-12)
    .map((k) => ({ time: k, events: timelineMap[k] }))

  // Default fallback if no timeline events yet
  const chartTimelineData =
    timelineData.length > 0
      ? timelineData
      : [
          { time: "12:00", events: 4 },
          { time: "12:05", events: 12 },
          { time: "12:10", events: 8 },
          { time: "12:15", events: 25 },
          { time: "12:20", events: 18 },
        ]

  // Severity Distribution for Donut Chart
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 }
  alerts.forEach((a) => {
    const sev = a.severity?.toLowerCase() || "low"
    if (severityCounts[sev] !== undefined) {
      severityCounts[sev] += 1
    }
  })
  const donutData = [
    { name: "Critical", value: severityCounts.critical, color: SEVERITY_COLORS.critical },
    { name: "High", value: severityCounts.high, color: SEVERITY_COLORS.high },
    { name: "Medium", value: severityCounts.medium, color: SEVERITY_COLORS.medium },
    { name: "Low", value: severityCounts.low, color: SEVERITY_COLORS.low },
  ].filter((d) => d.value > 0)

  const chartDonutData =
    donutData.length > 0
      ? donutData
      : [
          { name: "Critical", value: 3, color: SEVERITY_COLORS.critical },
          { name: "High", value: 5, color: SEVERITY_COLORS.high },
          { name: "Medium", value: 2, color: SEVERITY_COLORS.medium },
          { name: "Low", value: 1, color: SEVERITY_COLORS.low },
        ]

  // Top Attacker IPs Bar Chart Data
  const ipCounts = {}
  alerts.forEach((a) => {
    if (a.src_ip) {
      ipCounts[a.src_ip] = (ipCounts[a.src_ip] || 0) + 1
    }
  })
  const topIpsData = Object.entries(ipCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([ip, count]) => ({ ip, count }))

  const chartTopIpsData =
    topIpsData.length > 0
      ? topIpsData
      : [
          { ip: "185.220.101.5", count: 18 },
          { ip: "194.26.29.112", count: 12 },
          { ip: "103.203.57.18", count: 7 },
        ]

  return (
    <div className="space-y-6">
      {/* Top Banner / Actions */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-gray-800">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            SOC Operations Center
            <span className="text-xs font-normal text-gray-400 bg-gray-800/80 px-2 py-0.5 rounded-full border border-gray-700">
              Live Real-Time
            </span>
          </h1>
          <p className="text-xs text-gray-400 mt-0.5">
            Real-time telemetry aggregation, automated MITRE correlation, and AI-directed containment.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={handleManualRefresh}
            disabled={refreshing}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 border border-gray-800 hover:bg-gray-800 text-xs text-gray-300 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? "animate-spin text-blue-400" : ""}`} />
            <span>Refresh</span>
          </button>
          <Link
            to="/incidents"
            className="flex items-center space-x-1.5 px-3.5 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors shadow-sm"
          >
            <span>View All Incidents</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Events */}
        <div className="p-4 rounded-xl bg-gray-900/80 border border-gray-800 hover:border-gray-700 transition-all shadow-sm">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-[11px] uppercase tracking-wider font-semibold">Total Ingested Events</span>
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400">
              <Database className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-white tracking-tight">
            {loading ? "..." : totalEvents.toLocaleString()}
          </div>
          <div className="flex items-center space-x-1.5 text-[11px] text-gray-400 mt-2">
            <TrendingUp className="w-3 h-3 text-emerald-400" />
            <span>SSH, Nginx, Perimeter Firewall</span>
          </div>
        </div>

        {/* Open Incidents */}
        <div className="p-4 rounded-xl bg-gray-900/80 border border-gray-800 hover:border-gray-700 transition-all shadow-sm">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-[11px] uppercase tracking-wider font-semibold">Open Incidents</span>
            <div className="p-2 rounded-lg bg-rose-500/10 text-rose-400">
              <AlertOctagon className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-rose-400 tracking-tight">
            {loading ? "..." : openIncidents}
          </div>
          <div className="text-[11px] text-gray-400 mt-2 flex items-center justify-between">
            <span>Correlated multi-stage attacks</span>
            <Link to="/incidents" className="text-blue-400 hover:underline">
              Inspect →
            </Link>
          </div>
        </div>

        {/* Critical Alerts */}
        <div className="p-4 rounded-xl bg-gray-900/80 border border-gray-800 hover:border-gray-700 transition-all shadow-sm">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-[11px] uppercase tracking-wider font-semibold">Critical Alerts</span>
            <div className="p-2 rounded-lg bg-amber-500/10 text-amber-400">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-amber-400 tracking-tight">
            {loading ? "..." : criticalAlerts}
          </div>
          <div className="text-[11px] text-gray-400 mt-2">
            <span>{alerts.length} total YAML rule matches</span>
          </div>
        </div>

        {/* Blocked IPs */}
        <div className="p-4 rounded-xl bg-gray-900/80 border border-gray-800 hover:border-gray-700 transition-all shadow-sm">
          <div className="flex items-center justify-between text-gray-400 mb-2">
            <span className="text-[11px] uppercase tracking-wider font-semibold">Firewall Blocklist</span>
            <div className="p-2 rounded-lg bg-emerald-500/10 text-emerald-400">
              <ShieldCheck className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-bold text-emerald-400 tracking-tight">
            {loading ? "..." : activeBlockedCount}
          </div>
          <div className="text-[11px] text-gray-400 mt-2 flex items-center justify-between">
            <span>Active perimeter drop rules</span>
            <Link to="/response" className="text-emerald-400 hover:underline">
              Manage →
            </Link>
          </div>
        </div>
      </div>

      {/* Real-time Threat Map */}
      <AttackMap alerts={alerts} blockedIps={blockedIps} />

      {/* Real-Time Live Alerts Feed */}
      <LiveAlertsFeed initialAlerts={alerts} />

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Events Over Time Line Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-gray-900/70 border border-gray-800 shadow-sm flex flex-col">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-sm font-semibold text-white">Event Telemetry Velocity</h2>
              <p className="text-xs text-gray-400">Ingested security log volume over time</p>
            </div>
            <span className="text-[11px] px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">
              Events/min
            </span>
          </div>
          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartTimelineData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="eventGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" vertical={false} />
                <XAxis dataKey="time" stroke="#6B7280" fontSize={11} tickLine={false} />
                <YAxis stroke="#6B7280" fontSize={11} tickLine={false} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#111827",
                    borderColor: "#374151",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Area
                  type="monotone"
                  dataKey="events"
                  stroke="#3B82F6"
                  strokeWidth={2}
                  fillOpacity={1}
                  fill="url(#eventGrad)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Alerts by Severity Donut Chart */}
        <div className="p-5 rounded-xl bg-gray-900/70 border border-gray-800 shadow-sm flex flex-col">
          <div className="mb-2">
            <h2 className="text-sm font-semibold text-white">Detections by Severity</h2>
            <p className="text-xs text-gray-400">Breakdown of active detection rules</p>
          </div>
          <div className="h-48 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={chartDonutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={55}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {chartDonutData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#111827",
                    borderColor: "#374151",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="grid grid-cols-2 gap-2 mt-2 pt-3 border-t border-gray-800/80 text-xs">
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500" />
              <span className="text-gray-400">Critical:</span>
              <span className="font-semibold text-white">{severityCounts.critical}</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500" />
              <span className="text-gray-400">High:</span>
              <span className="font-semibold text-white">{severityCounts.high}</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-blue-500" />
              <span className="text-gray-400">Medium:</span>
              <span className="font-semibold text-white">{severityCounts.medium}</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500" />
              <span className="text-gray-400">Low:</span>
              <span className="font-semibold text-white">{severityCounts.low}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Section: Top Attacker IPs & Recent Incidents */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Top Attacker IPs Bar Chart */}
        <div className="p-5 rounded-xl bg-gray-900/70 border border-gray-800 shadow-sm">
          <h2 className="text-sm font-semibold text-white mb-1">Top Offending Source IPs</h2>
          <p className="text-xs text-gray-400 mb-4">Adversary IPs generating maximum rule matches</p>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartTopIpsData} layout="vertical" margin={{ top: 0, right: 20, left: 20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1F2937" horizontal={false} />
                <XAxis type="number" stroke="#6B7280" fontSize={11} tickLine={false} />
                <YAxis dataKey="ip" type="category" stroke="#9CA3AF" fontSize={11} tickLine={false} width={90} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#111827",
                    borderColor: "#374151",
                    borderRadius: "8px",
                    fontSize: "12px",
                  }}
                />
                <Bar dataKey="count" fill="#F43F5E" radius={[0, 4, 4, 0]} barSize={16} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Priority Incidents List */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-gray-900/70 border border-gray-800 shadow-sm flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <div>
              <h2 className="text-sm font-semibold text-white">Active Threat Incidents</h2>
              <p className="text-xs text-gray-400">Correlated multi-stage attack campaigns requiring analyst review</p>
            </div>
            <Link to="/incidents" className="text-xs text-blue-400 hover:text-blue-300 font-medium">
              View all ({incidents.length})
            </Link>
          </div>

          <div className="flex-1 overflow-x-auto">
            {incidents.length === 0 ? (
              <div className="h-48 flex flex-col items-center justify-center text-center p-6 text-gray-500">
                <ShieldCheck className="w-8 h-8 mb-2 text-gray-600" />
                <p className="text-xs">No correlated incidents detected.</p>
                <p className="text-[11px] text-gray-600 mt-1">
                  Click "Simulate Attack" in the navbar to trigger synthetic threat telemetry.
                </p>
              </div>
            ) : (
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-gray-800 text-[11px] uppercase tracking-wider text-gray-400 font-medium">
                    <th className="py-2.5 px-3">Severity</th>
                    <th className="py-2.5 px-3">Title</th>
                    <th className="py-2.5 px-3">Attacker IP</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800/60 font-mono text-gray-300">
                  {incidents.slice(0, 5).map((inc) => (
                    <tr key={inc.id} className="hover:bg-gray-800/40 transition-colors">
                      <td className="py-3 px-3">
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
                      <td className="py-3 px-3 font-sans font-medium text-white max-w-[260px] truncate">
                        {inc.title}
                      </td>
                      <td className="py-3 px-3 text-gray-300">{inc.src_ip || "—"}</td>
                      <td className="py-3 px-3">
                        <span
                          className={`inline-flex items-center gap-1.5 text-[11px] ${
                            inc.status === "contained"
                              ? "text-emerald-400"
                              : inc.status === "investigating"
                              ? "text-blue-400"
                              : "text-amber-400"
                          }`}
                        >
                          <span
                            className={`w-1.5 h-1.5 rounded-full ${
                              inc.status === "contained"
                                ? "bg-emerald-400"
                                : inc.status === "investigating"
                                ? "bg-blue-400"
                                : "bg-amber-400 animate-pulse"
                            }`}
                          />
                          <span className="capitalize">{inc.status}</span>
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <Link
                          to={`/incidents/${inc.id}`}
                          className="inline-flex items-center space-x-1 text-xs text-blue-400 hover:text-blue-300 font-sans"
                        >
                          <span>Analyze</span>
                          <ExternalLink className="w-3 h-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

