import React, { useState } from "react"
import { ShieldAlert, ShieldCheck, Ticket, UserX, X, AlertTriangle } from "lucide-react"

export default function ActionModal({
  isOpen,
  onClose,
  onConfirm,
  actionType,
  defaultTarget,
  incidentTitle,
  isLoading,
}) {
  const [target, setTarget] = useState(defaultTarget || "")
  const [analyst, setAnalyst] = useState("SOC Analyst")
  const [reason, setReason] = useState("")

  // Keep target updated if prop changes
  React.useEffect(() => {
    setTarget(defaultTarget || "")
  }, [defaultTarget])

  if (!isOpen) return null

  const getActionConfig = () => {
    switch (actionType) {
      case "block_ip":
        return {
          title: "Confirm Firewall Block Rule",
          icon: ShieldAlert,
          iconColor: "text-rose-400",
          iconBg: "bg-rose-500/10 border-rose-500/30",
          targetLabel: "Target IP Address to Block",
          desc: "This will add the IP address to the perimeter firewall blocklist, drop all subsequent incoming packets, and move the incident status to Contained.",
          btnColor: "bg-rose-600 hover:bg-rose-500 text-white",
          btnText: "Block IP at Firewall",
        }
      case "disable_user":
        return {
          title: "Confirm Account Revocation",
          icon: UserX,
          iconColor: "text-amber-400",
          iconBg: "bg-amber-500/10 border-amber-500/30",
          targetLabel: "Target Username to Disable",
          desc: "This will revoke active credentials and disable the account in the Identity Provider (IAM/Active Directory), and move the incident status to Contained.",
          btnColor: "bg-amber-600 hover:bg-amber-500 text-white",
          btnText: "Disable Account",
        }
      case "create_ticket":
        return {
          title: "Create Escalation Ticket",
          icon: Ticket,
          iconColor: "text-blue-400",
          iconBg: "bg-blue-500/10 border-blue-500/30",
          targetLabel: "Ticket Subject / Title",
          desc: "This will generate an official incident ticket pre-filled with the incident details, severity, kill-chain timeline, and the Gemini AI summary.",
          btnColor: "bg-blue-600 hover:bg-blue-500 text-white",
          btnText: "Create Ticket",
        }
      default:
        return {
          title: "Confirm Response Action",
          icon: ShieldCheck,
          iconColor: "text-blue-400",
          iconBg: "bg-blue-500/10 border-blue-500/30",
          targetLabel: "Target",
          desc: "Execute this response containment action.",
          btnColor: "bg-blue-600 hover:bg-blue-500 text-white",
          btnText: "Execute Action",
        }
    }
  }

  const config = getActionConfig()
  const Icon = config.icon

  const handleSubmit = (e) => {
    e.preventDefault()
    onConfirm({ target, analyst, reason })
  }

  return (
    <div className="fixed inset-0 z-[9999] bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-md w-full p-6 space-y-5 shadow-2xl animate-in fade-in zoom-in-95">
        <div className="flex items-start justify-between">
          <div className="flex items-center space-x-3">
            <div className={`p-2.5 rounded-xl border ${config.iconBg}`}>
              <Icon className={`w-5 h-5 ${config.iconColor}`} />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">{config.title}</h3>
              <p className="text-[11px] text-gray-400 truncate max-w-[280px]">
                {incidentTitle}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white p-1 rounded-lg hover:bg-gray-800"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="p-3 rounded-lg bg-gray-800/60 border border-gray-800 text-xs text-gray-300 leading-relaxed flex items-start space-x-2.5">
          <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
          <span>{config.desc}</span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3.5">
          <div>
            <label className="block text-[11px] font-medium text-gray-300 uppercase tracking-wider mb-1">
              {config.targetLabel}
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              required
              className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-blue-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-[11px] font-medium text-gray-300 uppercase tracking-wider mb-1">
              Approving Analyst
            </label>
            <input
              type="text"
              value={analyst}
              onChange={(e) => setAnalyst(e.target.value)}
              required
              className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-[11px] font-medium text-gray-300 uppercase tracking-wider mb-1">
              Operational Justification (Optional)
            </label>
            <textarea
              rows={2}
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Confirmed malicious scanning and brute force actor from threat intel."
              className="w-full px-3 py-2 rounded-lg bg-gray-950 border border-gray-800 text-white text-xs focus:outline-none focus:border-blue-500 placeholder-gray-600"
            />
          </div>

          <div className="flex items-center justify-end space-x-2 pt-2 border-t border-gray-800">
            <button
              type="button"
              onClick={onClose}
              disabled={isLoading}
              className="px-3.5 py-1.5 rounded-lg text-xs font-medium text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isLoading || !target.trim()}
              className={`px-4 py-1.5 rounded-lg text-xs font-medium transition-all shadow-md ${config.btnColor} ${
                isLoading ? "opacity-50 cursor-not-allowed" : ""
              }`}
            >
              {isLoading ? "Executing..." : config.btnText}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

