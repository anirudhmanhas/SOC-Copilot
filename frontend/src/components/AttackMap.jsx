import React, { useState, useEffect } from "react"
import { MapContainer, TileLayer, CircleMarker, Popup, Polyline } from "react-leaflet"
import { Shield, Globe, ShieldAlert, ShieldCheck } from "lucide-react"

// Central protected enterprise gateway coordinates (Washington, D.C. SOC)
const OUR_NETWORK_COORDS = [38.9072, -77.0369]

// Static IP-to-geolocation registry for synthetic attack telemetry
const STATIC_GEO_REGISTRY = {
  "185.220.101.5": { lat: 52.3702, lng: 4.8952, city: "Amsterdam", country: "Netherlands", threat: "Tor Exit Node" },
  "194.26.29.112": { lat: 55.7558, lng: 37.6173, city: "Moscow", country: "Russia", threat: "Bulletproof VPS" },
  "103.203.57.18": { lat: 1.3521, lng: 103.8198, city: "Singapore", country: "Singapore", threat: "High-Risk Subnet" },
  "45.154.255.89": { lat: 44.4268, lng: 26.1025, city: "Bucharest", country: "Romania", threat: "Known Scanner" },
  "193.106.191.66": { lat: 52.52, lng: 13.405, city: "Berlin", country: "Germany", threat: "Port Scan Network" },
  "177.54.148.12": { lat: -23.5505, lng: -46.6333, city: "São Paulo", country: "Brazil", threat: "Compromised Host" },
  "203.0.113.195": { lat: 37.7749, lng: -122.4194, city: "San Francisco", country: "United States", threat: "Simulated External" },
  "198.51.100.42": { lat: 40.7128, lng: -74.006, city: "New York", country: "United States", threat: "Simulated External" },
  "198.51.100.99": { lat: 51.5074, lng: -0.1278, city: "London", country: "United Kingdom", threat: "Brute Force Source" },
  "203.0.113.55": { lat: 35.6762, lng: 139.6503, city: "Tokyo", country: "Japan", threat: "Web SQLi Probe" },
}

const geoCache = { ...STATIC_GEO_REGISTRY }

export default function AttackMap({ alerts = [], blockedIps = [] }) {
  const [geoNodes, setGeoNodes] = useState([])

  // Build set of currently active blocked IP strings
  const activeBlockedSet = new Set(
    blockedIps.filter((b) => b.status === "active").map((b) => b.ip_address)
  )

  useEffect(() => {
    // Collect all unique attacker IPs from alerts
    const uniqueIps = Array.from(
      new Set(
        alerts
          .map((a) => a.src_ip)
          .filter(
            (ip) =>
              ip &&
              !ip.startsWith("10.") &&
              !ip.startsWith("192.168.") &&
              !ip.startsWith("127.")
          )
      )
    )

    // Ensure common simulation IPs are always rendered if alerts are low
    const targetIps =
      uniqueIps.length > 0
        ? uniqueIps
        : ["185.220.101.5", "194.26.29.112", "103.203.57.18", "45.154.255.89"]

    const resolved = []

    targetIps.forEach((ip) => {
      if (geoCache[ip]) {
        resolved.push({
          ip,
          ...geoCache[ip],
          isBlocked: activeBlockedSet.has(ip),
        })
      } else {
        // Fallback to free ip-api.com lookup
        fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`)
          .then((res) => res.json())
          .then((data) => {
            if (data.status === "success" && data.lat && data.lon) {
              const node = {
                lat: data.lat,
                lng: data.lon,
                city: data.city || "Unknown",
                country: data.country || "External",
                threat: "External Host",
              }
              geoCache[ip] = node
              setGeoNodes((prev) => [
                ...prev.filter((p) => p.ip !== ip),
                { ip, ...node, isBlocked: activeBlockedSet.has(ip) },
              ])
            }
          })
          .catch(() => {
            // Default coordinate fallback if offline
            const defaultNode = {
              lat: 51.5074,
              lng: -0.1278,
              city: "External",
              country: "Global",
              threat: "External Actor",
            }
            geoCache[ip] = defaultNode
            resolved.push({ ip, ...defaultNode, isBlocked: activeBlockedSet.has(ip) })
          })
      }
    })

    setGeoNodes(resolved)
  }, [alerts, blockedIps])

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/80 p-5 shadow-sm space-y-4">
      {/* Map Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-white flex items-center gap-2">
            <Globe className="w-4 h-4 text-blue-400" />
            <span>Global Threat Vector & Attack Geolocation Map</span>
          </h2>
          <p className="text-xs text-gray-400">
            Real-time trajectory tracking of incoming adversary traffic directed at protected enterprise perimeter
          </p>
        </div>

        {/* Legend */}
        <div className="flex items-center space-x-4 text-xs font-mono">
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-blue-500 ring-2 ring-blue-500/30" />
            <span className="text-gray-300">Our Network</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500 ring-2 ring-rose-500/30 animate-pulse" />
            <span className="text-rose-400">Active Threat</span>
          </div>
          <div className="flex items-center space-x-1.5">
            <span className="w-2.5 h-2.5 rounded-full bg-gray-500 ring-2 ring-gray-500/30" />
            <span className="text-gray-400">Blocked (Contained)</span>
          </div>
        </div>
      </div>

      {/* Map Canvas */}
      <div className="h-[360px] w-full rounded-xl overflow-hidden border border-gray-800/80 relative z-0 isolate dark-leaflet-map">
        <MapContainer
          center={[35, 10]}
          zoom={2}
          minZoom={2}
          maxZoom={8}
          scrollWheelZoom={false}
          style={{ height: "100%", width: "100%" }}
        >
          {/* OpenStreetMap with Dark Tactical CSS Filter (Keyless & Open) */}
          <TileLayer
            attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
            url="https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png"
          />

          {/* 1. "Our Network" Central Protected Gateway */}
          <CircleMarker
            center={OUR_NETWORK_COORDS}
            radius={8}
            pathOptions={{
              color: "#3B82F6",
              fillColor: "#60A5FA",
              fillOpacity: 1,
              weight: 2,
            }}
          >
            <Popup>
              <div className="p-1 space-y-1 text-xs">
                <div className="font-bold text-blue-400 flex items-center gap-1">
                  <Shield className="w-3.5 h-3.5" />
                  <span>Our Network (HQ Perimeter Gateway)</span>
                </div>
                <div className="text-[11px] text-gray-300">
                  Target Server: <span className="font-mono text-white">10.0.0.15</span>
                </div>
                <div className="text-[10px] text-emerald-400 font-medium">
                  Firewall Policy: ACTIVE ENFORCEMENT
                </div>
              </div>
            </Popup>
          </CircleMarker>

          {/* 2. Attacker Markers & Trajectory Polylines */}
          {geoNodes.map((node) => {
            const isBlocked = activeBlockedSet.has(node.ip)
            const attackerCoords = [node.lat, node.lng]

            const markerColor = isBlocked ? "#6B7280" : "#EF4444"
            const fillColor = isBlocked ? "#4B5563" : "#F43F5E"
            const lineColor = isBlocked ? "#4B5563" : "#F43F5E"

            return (
              <React.Fragment key={node.ip}>
                {/* Animated Trajectory Line */}
                <Polyline
                  positions={[attackerCoords, OUR_NETWORK_COORDS]}
                  pathOptions={{
                    color: lineColor,
                    weight: isBlocked ? 1.5 : 2,
                    opacity: isBlocked ? 0.35 : 0.85,
                    dashArray: isBlocked ? "4, 6" : "8, 8",
                    className: isBlocked ? "attack-line-blocked" : "attack-line-active",
                  }}
                />

                {/* Attacker Origin Marker */}
                <CircleMarker
                  center={attackerCoords}
                  radius={isBlocked ? 5 : 7}
                  pathOptions={{
                    color: markerColor,
                    fillColor: fillColor,
                    fillOpacity: isBlocked ? 0.6 : 0.95,
                    weight: isBlocked ? 1 : 2,
                  }}
                >
                  <Popup>
                    <div className="p-1 space-y-1 text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono font-bold text-white">{node.ip}</span>
                        <span
                          className={`text-[9px] font-bold px-1.5 py-0.5 rounded uppercase ${
                            isBlocked
                              ? "bg-gray-800 text-gray-400 border border-gray-700"
                              : "bg-rose-500/20 text-rose-300 border border-rose-500/30"
                          }`}
                        >
                          {isBlocked ? "BLOCKED" : "ACTIVE"}
                        </span>
                      </div>
                      <div className="text-[11px] text-gray-300">
                        Location: {node.city}, {node.country}
                      </div>
                      <div className="text-[10px] text-gray-400">
                        Profile: <span className="text-gray-200">{node.threat || "Adversary Source"}</span>
                      </div>
                      <div className="text-[10px] text-gray-500 pt-1 border-t border-gray-800 font-mono">
                        Trajectory: [{node.lat.toFixed(2)}, {node.lng.toFixed(2)}] → Our Network
                      </div>
                    </div>
                  </Popup>
                </CircleMarker>
              </React.Fragment>
            )
          })}
        </MapContainer>

        {/* Floating Geo Status Indicator */}
        <div className="absolute bottom-3 left-3 z-[1000] px-3 py-1.5 rounded-lg bg-gray-950/85 backdrop-blur-md border border-gray-800 text-[11px] text-gray-300 flex items-center space-x-2">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          <span>Active Origin Vectors: </span>
          <span className="font-bold text-white">{geoNodes.length}</span>
          <span className="text-gray-500">|</span>
          <span>Blocked Nodes: </span>
          <span className="font-bold text-rose-400">
            {geoNodes.filter((g) => activeBlockedSet.has(g.ip)).length}
          </span>
        </div>
      </div>
    </div>
  )
}

