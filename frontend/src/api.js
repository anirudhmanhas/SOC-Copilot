/**
 * SOC Copilot - Frontend API Client
 * Centralized fetch wrapper communicating with FastAPI backend.
 */

const BASE_URL = import.meta.env.VITE_API_URL || ""

async function request(path, options = {}) {
  const url = `${BASE_URL}${path}`
  const headers = {
    "Content-Type": "application/json",
    ...options.headers,
  }

  try {
    const res = await fetch(url, { ...options, headers })
    if (!res.ok) {
      let errorMsg = `HTTP ${res.status}: ${res.statusText}`
      try {
        const errJson = await res.json()
        errorMsg = errJson.detail || errorMsg
      } catch {
        // ignore json parse error
      }
      throw new Error(errorMsg)
    }
    return await res.json()
  } catch (err) {
    console.error(`API Error on ${url}:`, err)
    throw err
  }
}

export const api = {
  // Health
  getHealth: () => request("/api/health"),

  // Logs
  getLogs: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/api/logs${q ? `?${q}` : ""}`)
  },
  ingestLogs: (payload) =>
    request("/api/ingest", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  // Alerts
  getAlerts: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/api/alerts${q ? `?${q}` : ""}`)
  },

  // Rules
  getRules: () => request("/api/rules"),

  // Incidents
  getIncidents: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/api/incidents${q ? `?${q}` : ""}`)
  },
  getIncident: (id) => request(`/api/incidents/${id}`),
  getIncidentTimeline: (id) => request(`/api/incidents/${id}/timeline`),
  analyzeIncident: (id, force = false) =>
    request(`/api/incidents/${id}/analyze?force=${force}`, {
      method: "POST",
    }),
  executeAction: (incidentId, actionType, target, analyst = "SOC Analyst", reason = "") =>
    request(`/api/incidents/${incidentId}/actions`, {
      method: "POST",
      body: JSON.stringify({
        action_type: actionType,
        target,
        analyst,
        reason,
      }),
    }),
  undoIncidentAction: (incidentId, actionType, target, analyst = "SOC Analyst") =>
    request(`/api/incidents/${incidentId}/actions/undo`, {
      method: "POST",
      body: JSON.stringify({
        action_type: actionType,
        target,
        analyst,
      }),
    }),

  // Blocked IPs
  getBlockedIPs: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/api/blocked-ips${q ? `?${q}` : ""}`)
  },
  unblockIP: (idOrIp, analyst = "SOC Analyst") => {
    if (typeof idOrIp === "number" || /^\d+$/.test(idOrIp)) {
      return request(`/api/blocked-ips/${idOrIp}/unblock?analyst=${encodeURIComponent(analyst)}`, {
        method: "POST",
      })
    }
    return request("/api/blocked-ips/unblock", {
      method: "POST",
      body: JSON.stringify({ ip_address: idOrIp, analyst }),
    })
  },

  // Disabled Users
  getDisabledUsers: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/api/disabled-users${q ? `?${q}` : ""}`)
  },
  enableUser: (idOrUsername, analyst = "SOC Analyst") => {
    if (typeof idOrUsername === "number" || /^\d+$/.test(idOrUsername)) {
      return request(`/api/disabled-users/${idOrUsername}/enable?analyst=${encodeURIComponent(analyst)}`, {
        method: "POST",
      })
    }
    return request("/api/disabled-users/enable", {
      method: "POST",
      body: JSON.stringify({ username: idOrUsername, analyst }),
    })
  },

  // Tickets
  getTickets: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/api/tickets${q ? `?${q}` : ""}`)
  },

  // Audit Logs
  getAuditLogs: (params = {}) => {
    const q = new URLSearchParams(params).toString()
    return request(`/api/audit-logs${q ? `?${q}` : ""}`)
  },
}

