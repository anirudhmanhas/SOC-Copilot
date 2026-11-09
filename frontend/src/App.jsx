import React, { useState, useEffect, useRef } from "react"
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import Navbar from "./components/Navbar"
import Overview from "./pages/Overview"
import Incidents from "./pages/Incidents"
import IncidentDetail from "./pages/IncidentDetail"
import MitreMatrix from "./pages/MitreMatrix"
import ResponseCenter from "./pages/ResponseCenter"
import Showcase from "./pages/Showcase"
import { api } from "./api"

export default function App() {
  const [backendStatus, setBackendStatus] = useState("Checking...")
  const [wsConnected, setWsConnected] = useState(false)
  const reconnectTimeoutRef = useRef(null)

  useEffect(() => {
    // 1. Health check poller
    const checkHealth = () => {
      api
        .getHealth()
        .then((data) => setBackendStatus(data.status === "healthy" ? "Online" : "Unknown"))
        .catch(() => setBackendStatus("Offline"))
    }

    checkHealth()
    const healthInterval = setInterval(checkHealth, 8000)

    // 2. Resilient WebSocket with auto-reconnect
    let ws = null
    const connectWS = () => {
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:"
      ws = new WebSocket(`${protocol}//${window.location.host}/ws`)

      ws.onopen = () => {
        setWsConnected(true)
      }

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          console.log("[WS] Received:", msg)
          window.dispatchEvent(new CustomEvent("soc-ws-event", { detail: msg }))
        } catch {
          // ignore pong / non-json
        }
      }

      ws.onclose = () => {
        setWsConnected(false)
        reconnectTimeoutRef.current = setTimeout(connectWS, 4000)
      }

      ws.onerror = () => {
        setWsConnected(false)
        ws.close()
      }
    }

    connectWS()

    return () => {
      clearInterval(healthInterval)
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current)
      if (ws) ws.close()
    }
  }, [])

  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col bg-[#0B0F17] text-gray-100 selection:bg-blue-600/30 selection:text-white">
        {/* Navigation Bar */}
        <Navbar
          wsConnected={wsConnected}
          backendStatus={backendStatus}
        />

        {/* Main Application Container */}
        <main className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 py-6">
          <Routes>
            <Route path="/" element={<Overview />} />
            <Route path="/incidents" element={<Incidents />} />
            <Route path="/incidents/:id" element={<IncidentDetail />} />
            <Route path="/mitre" element={<MitreMatrix />} />
            <Route path="/response" element={<ResponseCenter />} />
            <Route path="/about" element={<Showcase />} />
            <Route path="/showcase" element={<Showcase />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>

        {/* Minimalist SOC Footer */}
        <footer className="border-t border-gray-900 bg-gray-950/60 py-4 px-6 text-center text-[11px] text-gray-500">
          <div className="max-w-7xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-2">
            <div>
              SOC Copilot — Autonomous Security Operations Center powered by Google Gemini & MITRE ATT&CK
            </div>
            <div className="flex items-center space-x-3 text-gray-600">
              <span>FastAPI</span>
              <span>•</span>
              <span>React 18</span>
              <span>•</span>
              <span>Tailwind CSS</span>
              <span>•</span>
              <span>Recharts</span>
            </div>
          </div>
        </footer>
      </div>
    </BrowserRouter>
  )
}
