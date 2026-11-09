import React, { useEffect, useState } from "react"
import { useParams, Link } from "react-router-dom"
import {
  ArrowLeft,
  Bot,
  Sparkles,
  ShieldAlert,
  ShieldCheck,
  UserX,
  Ticket,
  Clock,
  Radio,
  ExternalLink,
  ChevronRight,
  RotateCw,
  CheckCircle2,
  AlertTriangle,
  Layers,
  Terminal,
} from "lucide-react"
import { api } from "../api"
import ActionModal from "../components/ActionModal"

export default function IncidentDetail() {
  const { id } = useParams()
  const [incident, setIncident] = useState(null)
  const [timeline, setTimeline] = useState(null)
  const [loading, setLoading] = useState(true)
  const [analyzing, setAnalyzing] = useState(false)
  const [actionLoading, setActionLoading] = useState(false)
  const [feedbackMsg, setFeedbackMsg] = useState(null)
  const [triageData, setTriageData] = useState(null)

  // Action Confirmation Modal State
  const [modalOpen, setModalOpen] = useState(false)
  const [selectedActionType, setSelectedActionType] = useState(null)
  const [defaultTarget, setDefaultTarget] = useState("")

  const loadData = async () => {
    try {
      const [incData, timeData] = await Promise.all([
        api.getIncident(id),
        api.getIncidentTimeline(id).catch(() => null),
      ])
      setIncident(incData)
      setTimeline(timeData)
    } catch (err) {
      console.error("Failed to load incident detail:", err)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [id])

  // Trigger Gemini AI Triage on demand
  const handleAnalyzeWithAI = async (force = true) => {
    setAnalyzing(true)
    setFeedbackMsg(null)
    try {
      const result = await api.analyzeIncident(id, force)
      setTriageData(result)
      // Refresh incident state and timeline
      const [incData, timeData] = await Promise.all([
        api.getIncident(id),
        api.getIncidentTimeline(id),
      ])
      setIncident(incData)
      setTimeline(timeData)
      setFeedbackMsg({
        type: "success",
        text: `AI Triage updated successfully (confidence: ${(result.confidence * 100).toFixed(0)}%).`,
      })
    } catch (err) {
      setFeedbackMsg({
        type: "error",
        text: `AI Triage failed: ${err.message}`,
      })
    } finally {
      setAnalyzing(false)
    }
  }

  // Open confirmation modal for containment action
  const openActionModal = (actionType, target) => {
    setSelectedActionType(actionType)
    setDefaultTarget(target || incident?.src_ip || "")
    setModalOpen(true)
  }

  // Execute confirmed action
  const handleConfirmAction = async ({ target, analyst, reason }) => {
    setActionLoading(true)
    try {
      const res = await api.executeAction(id, selectedActionType, target, analyst, reason)
      setModalOpen(false)
      await loadData()
      setFeedbackMsg({
        type: "success",
        text: `Action executed: ${res.action_type} for ${res.target}. Incident moved to Contained.`,
      })
    } catch (err) {
      setFeedbackMsg({
        type: "error",
        text: `Action failed: ${err.message}`,
      })
    } finally {
      setActionLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="h-96 flex flex-col items-center justify-center text-gray-500 space-y-2">
        <RotateCw className="w-6 h-6 animate-spin text-blue-400" />
        <span className="text-xs">Loading incident details...</span>
      </div>
    )
  }

  if (!incident) {
    return (
      <div className="p-8 text-center text-gray-500 space-y-3">
        <AlertTriangle className="w-8 h-8 mx-auto text-amber-400" />
        <h2 className="text-sm font-semibold text-white">Incident Not Found</h2>
        <p className="text-xs">No incident exists with ID {id}.</p>
        <Link to="/incidents" className="inline-block text-xs text-blue-400 hover:underline">
          Return to Incidents List
        </Link>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Back Link & Header */}
      <div>
        <Link
          to="/incidents"
          className="inline-flex items-center space-x-1.5 text-xs text-gray-400 hover:text-white transition-colors mb-3"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          <span>Back to Incidents</span>
        </Link>

        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4 p-5 rounded-xl bg-gray-900 border border-gray-800 shadow-sm">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span
                className={`px-2.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                  incident.severity === "critical"
                    ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                    : incident.severity === "high"
                    ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                    : incident.severity === "medium"
                    ? "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                    : "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                }`}
              >
                {incident.severity}
              </span>

              <span
                className={`inline-flex items-center gap-1.5 text-xs font-medium px-2 py-0.5 rounded ${
                  incident.status === "contained"
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                    : incident.status === "investigating"
                    ? "bg-blue-500/10 text-blue-400 border border-blue-500/20"
                    : "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    incident.status === "contained"
                      ? "bg-emerald-400"
                      : incident.status === "investigating"
                      ? "bg-blue-400"
                      : "bg-amber-400 animate-pulse"
                  }`}
                />
                <span className="capitalize">{incident.status}</span>
              </span>

              <span className="text-xs font-mono text-gray-400">
                Incident #{incident.id}
              </span>
            </div>

            <h1 className="text-lg font-bold text-white tracking-tight">
              {incident.title}
            </h1>

            <div className="flex flex-wrap items-center gap-4 text-xs text-gray-400 pt-1">
              <div>
                Attacker IP:{" "}
                <span className="text-gray-200 font-mono font-medium">
                  {incident.src_ip || "Unknown"}
                </span>
              </div>
              <div>
                Affected Users:{" "}
                <span className="text-gray-200 font-mono font-medium">
                  {incident.affected_users && incident.affected_users.length > 0
                    ? incident.affected_users.join(", ")
                    : "None confirmed"}
                </span>
              </div>
              <div className="flex items-center gap-1">
                <Clock className="w-3.5 h-3.5" />
                <span>{new Date(incident.created_at).toLocaleString()}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-2 self-start lg:self-center">
            <button
              onClick={() => handleAnalyzeWithAI(true)}
              disabled={analyzing}
              className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-medium transition-all shadow-md shadow-blue-950/50"
            >
              <Bot className={`w-4 h-4 ${analyzing ? "animate-spin" : ""}`} />
              <span>{analyzing ? "Analyzing with Gemini..." : "Re-Analyze with AI"}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Feedback Banner */}
      {feedbackMsg && (
        <div
          className={`p-3 rounded-lg text-xs flex items-center space-x-2 ${
            feedbackMsg.type === "success"
              ? "bg-emerald-500/10 text-emerald-300 border border-emerald-500/20"
              : "bg-rose-500/10 text-rose-300 border border-rose-500/20"
          }`}
        >
          {feedbackMsg.type === "success" ? (
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-rose-400 flex-shrink-0" />
          )}
          <span>{feedbackMsg.text}</span>
        </div>
      )}

      {/* Main Grid: AI Analyst Card (Left) & Attack Timeline (Right) */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: AI Analyst Card & Recommendations */}
        <div className="lg:col-span-5 space-y-6">
          {/* AI Analyst Card */}
          <div className="rounded-xl border border-blue-500/30 bg-gray-900/90 overflow-hidden shadow-xl shadow-blue-950/20">
            <div className="p-4 bg-gradient-to-r from-blue-950/40 via-gray-900 to-indigo-950/40 border-b border-gray-800 flex items-center justify-between">
              <div className="flex items-center space-x-2.5">
                <div className="p-1.5 rounded-lg bg-blue-600/20 text-blue-400 border border-blue-500/30">
                  <Bot className="w-4 h-4" />
                </div>
                <div>
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-1.5">
                    Gemini AI Triage Analyst
                    <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                  </h3>
                  <p className="text-[10px] text-gray-400">Retrieval-Augmented Threat Intelligence</p>
                </div>
              </div>

              {incident.ai_summary && (
                <div className="text-right">
                  <span className="text-[10px] font-mono font-semibold px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/20">
                    Confidence:{" "}
                    {triageData?.confidence
                      ? `${(triageData.confidence * 100).toFixed(0)}%`
                      : incident.severity === "critical"
                      ? "95%"
                      : incident.severity === "high"
                      ? "88%"
                      : "76%"}
                  </span>
                </div>
              )}
            </div>

            <div className="p-5 space-y-4 text-xs">
              {(incident.ai_summary || triageData?.summary) ? (
                <>
                  {/* Summary */}
                  <div className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-semibold text-gray-300 uppercase tracking-wider block">
                        Executive Threat Summary
                      </span>
                      {(triageData?.ai_generated_at || incident.ai_generated_at) && (
                        <span className="text-[10px] font-mono text-gray-500">
                          Updated: {new Date(triageData?.ai_generated_at || incident.ai_generated_at).toLocaleTimeString()}
                        </span>
                      )}
                    </div>
                    <p className="text-gray-300 leading-relaxed font-sans bg-gray-950/60 p-3 rounded-lg border border-gray-800">
                      {triageData?.summary || incident.ai_summary}
                    </p>
                  </div>

                  {triageData?.likely_attacker_goal && (
                    <div className="space-y-1">
                      <span className="text-[11px] font-semibold text-gray-300 uppercase tracking-wider block">
                        Likely Attacker Goal
                      </span>
                      <p className="text-gray-400 leading-relaxed font-sans bg-gray-950/40 p-2.5 rounded-lg border border-gray-800/80">
                        {triageData.likely_attacker_goal}
                      </p>
                    </div>
                  )}

                  {triageData?.attack_stage_analysis && (
                    <div className="space-y-1">
                      <span className="text-[11px] font-semibold text-gray-300 uppercase tracking-wider block">
                        Attack Stage Analysis
                      </span>
                      <p className="text-gray-400 leading-relaxed font-sans bg-gray-950/40 p-2.5 rounded-lg border border-gray-800/80">
                        {triageData.attack_stage_analysis}
                      </p>
                    </div>
                  )}

                  {/* Recommended Actions (1-Click) */}
                  <div className="space-y-2 pt-2 border-t border-gray-800">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-semibold text-gray-300 uppercase tracking-wider">
                        Recommended Containment Playbook
                      </span>
                      <span className="text-[10px] text-amber-400/90 font-medium">
                        Human Approval Required
                      </span>
                    </div>

                    <div className="space-y-2 pt-1">
                      {((triageData?.recommended_actions && triageData.recommended_actions.length > 0)
                        ? triageData.recommended_actions
                        : incident.ai_recommendations && incident.ai_recommendations.length > 0
                        ? incident.ai_recommendations
                        : []).length > 0 ? (
                        ((triageData?.recommended_actions && triageData.recommended_actions.length > 0)
                          ? triageData.recommended_actions
                          : incident.ai_recommendations
                        ).map((rec, i) => (
                          <div
                            key={i}
                            className="p-3 rounded-lg bg-gray-950 border border-gray-800/80 hover:border-gray-700 transition-all flex flex-col justify-between gap-2.5"
                          >
                            <div>
                              <div className="flex items-center justify-between">
                                <span className="font-semibold text-white capitalize flex items-center gap-1.5">
                                  {rec.action_type === "block_ip" && (
                                    <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                                  )}
                                  {rec.action_type === "disable_user" && (
                                    <UserX className="w-3.5 h-3.5 text-amber-400" />
                                  )}
                                  {rec.action_type === "create_ticket" && (
                                    <Ticket className="w-3.5 h-3.5 text-blue-400" />
                                  )}
                                  {rec.action_type?.replace("_", " ")}:{" "}
                                  <span className="font-mono text-gray-300 font-normal">
                                    {rec.target}
                                  </span>
                                </span>
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 capitalize">
                                  {rec.priority || "high"}
                                </span>
                              </div>
                              <p className="text-[11px] text-gray-400 mt-1 leading-relaxed">
                                {rec.reason}
                              </p>
                            </div>

                            <button
                              onClick={() => openActionModal(rec.action_type, rec.target)}
                              className={`self-end px-3 py-1 rounded text-[11px] font-medium transition-colors shadow-sm ${
                                rec.action_type === "block_ip"
                                  ? "bg-rose-600/20 text-rose-300 border border-rose-500/30 hover:bg-rose-600 hover:text-white"
                                  : rec.action_type === "disable_user"
                                  ? "bg-amber-600/20 text-amber-300 border border-amber-500/30 hover:bg-amber-600 hover:text-white"
                                  : "bg-blue-600/20 text-blue-300 border border-blue-500/30 hover:bg-blue-600 hover:text-white"
                              }`}
                            >
                              {rec.action_type === "block_ip"
                                ? "Block IP"
                                : rec.action_type === "disable_user"
                                ? "Disable User"
                                : rec.action_type === "create_ticket"
                                ? "Create Ticket"
                                : "Execute Action"}
                            </button>
                          </div>
                        ))
                      ) : (
                        <div className="space-y-2">
                          <button
                            onClick={() => openActionModal("block_ip", incident.src_ip)}
                            className="w-full flex items-center justify-between p-2.5 rounded-lg bg-gray-800/80 hover:bg-gray-800 border border-rose-500/30 text-rose-400 font-medium text-xs transition-colors"
                          >
                            <span className="flex items-center gap-2">
                              <ShieldAlert className="w-4 h-4" />
                              Block Attacker IP ({incident.src_ip})
                            </span>
                            <span>Execute →</span>
                          </button>
                        </div>
                      )}
                    </div>
                  </div>
                </>
              ) : (
                <div className="py-6 text-center space-y-3">
                  <Bot className="w-8 h-8 mx-auto text-blue-400/60" />
                  <p className="text-gray-400 text-xs">
                    No AI triage generated yet for this incident.
                  </p>
                  <button
                    onClick={() => handleAnalyzeWithAI(false)}
                    disabled={analyzing}
                    className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors inline-flex items-center space-x-1.5 shadow-sm"
                  >
                    <Sparkles className="w-3.5 h-3.5" />
                    <span>Generate AI Analysis</span>
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* Response Actions History */}
          <div className="p-4 rounded-xl bg-gray-900 border border-gray-800 shadow-sm space-y-3">
            <h3 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-emerald-400" />
              <span>Executed Containment Audit</span>
            </h3>

            {incident.response_actions && incident.response_actions.length > 0 ? (
              <div className="space-y-2">
                {incident.response_actions.map((act) => (
                  <div
                    key={act.id}
                    className="p-2.5 rounded-lg bg-gray-950 border border-gray-800 text-xs flex items-start justify-between"
                  >
                    <div>
                      <div className="font-semibold text-gray-200 capitalize flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                        {act.action_type.replace("_", " ")}: {act.target}
                      </div>
                      <p className="text-[11px] text-gray-400 mt-0.5">{act.details}</p>
                      <span className="text-[10px] text-gray-500">
                        Approved by {act.analyst || "analyst"} at {new Date(act.performed_at).toLocaleTimeString()}
                      </span>
                    </div>
                    <span className="px-1.5 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 uppercase font-mono">
                      {act.status}
                    </span>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500">
                No active containment actions have been executed yet.
              </p>
            )}
          </div>
        </div>

        {/* Right Column: Attack Timeline (Ordered by MITRE Kill-Chain) */}
        <div className="lg:col-span-7">
          <div className="p-5 rounded-xl bg-gray-900 border border-gray-800 shadow-sm space-y-4">
            <div className="flex items-center justify-between border-b border-gray-800 pb-3">
              <div>
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Layers className="w-4 h-4 text-purple-400" />
                  <span>Attack Kill-Chain Progression</span>
                </h3>
                <p className="text-xs text-gray-400">
                  Chronological progression ordered by MITRE ATT&CK tactic hierarchy
                </p>
              </div>

              {timeline && timeline.tactics_traversed && (
                <div className="text-xs font-mono text-purple-400 bg-purple-500/10 px-2 py-0.5 rounded border border-purple-500/20">
                  {timeline.tactics_traversed.length} Tactics Traversed
                </div>
              )}
            </div>

            {/* Vertical Timeline */}
            {timeline && timeline.timeline && timeline.timeline.length > 0 ? (
              <div className="relative pl-6 space-y-6 before:absolute before:left-2.5 before:top-2 before:bottom-2 before:w-0.5 before:bg-gradient-to-b before:from-purple-500/80 before:via-blue-500/60 before:to-rose-500/80">
                {timeline.timeline.map((step, idx) => (
                  <div key={idx} className="relative group">
                    {/* Bullet marker */}
                    <div className="absolute -left-[27px] top-1.5 w-3.5 h-3.5 rounded-full bg-gray-900 border-2 border-purple-400 group-hover:border-white transition-colors flex items-center justify-center">
                      <div className="w-1.5 h-1.5 rounded-full bg-purple-400" />
                    </div>

                    {/* Step Card */}
                    <div className="p-4 rounded-xl bg-gray-950/80 border border-gray-800/80 hover:border-gray-700 transition-all space-y-2">
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center space-x-2">
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-purple-500/20 text-purple-300 border border-purple-500/30 uppercase font-bold tracking-wider">
                            Phase {step.step}: {step.tactic}
                          </span>
                          <span className="text-[11px] font-mono text-gray-400">
                            {step.technique_id} - {step.technique_name}
                          </span>
                        </div>

                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider ${
                            step.severity === "critical"
                              ? "bg-rose-500/20 text-rose-400 border border-rose-500/30"
                              : step.severity === "high"
                              ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                              : "bg-blue-500/20 text-blue-400 border border-blue-500/30"
                          }`}
                        >
                          {step.severity}
                        </span>
                      </div>

                      <div className="font-semibold text-white text-xs">
                        {step.rule_name}
                      </div>

                      <p className="text-xs text-gray-300 leading-relaxed font-sans">
                        {step.description}
                      </p>

                      <div className="flex flex-wrap items-center gap-4 text-[11px] text-gray-400 pt-1 border-t border-gray-900">
                        <span className="font-mono text-gray-400">
                          Timestamp: {new Date(step.timestamp).toLocaleTimeString()}
                        </span>
                        {step.src_ip && (
                          <span className="font-mono text-gray-400">
                            Src: {step.src_ip}
                          </span>
                        )}
                        {step.user && (
                          <span className="font-mono text-gray-400">
                            Target User: {step.user}
                          </span>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-12 text-center text-gray-500 text-xs">
                No timeline events available for this incident.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Action Execution Confirmation Modal */}
      <ActionModal
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        onConfirm={handleConfirmAction}
        actionType={selectedActionType}
        defaultTarget={defaultTarget}
        incidentTitle={incident.title}
        isLoading={actionLoading}
      />
    </div>
  )
}

