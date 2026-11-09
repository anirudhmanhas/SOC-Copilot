"""
SOC Copilot - Real-time WebSocket Event Broadcaster
===================================================
Dispatches real-time security events to active WebSocket connections on the dashboard:
- LOGS_INGESTED: New telemetry arrived
- ALERT_TRIGGERED: Rule match detected
- INCIDENT_UPDATED: Incident formed or escalated
- ACTION_EXECUTED: Containment action applied
"""

import asyncio
import logging
from typing import Any, Dict

logger = logging.getLogger("soc_copilot.broadcaster")


def broadcast_event(event_type: str, payload: Dict[str, Any] = None) -> None:
    """
    Broadcasts a real-time event to all connected dashboard WebSockets.
    Safe to call from both synchronous and asynchronous contexts.
    """
    try:
        from ..main import manager, _main_loop
        if not manager.active_connections:
            return

        message = {
            "type": event_type,
            "payload": payload or {},
        }

        if _main_loop and _main_loop.is_running():
            asyncio.run_coroutine_threadsafe(manager.broadcast(message), _main_loop)
        else:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(manager.broadcast(message))
            except RuntimeError:
                pass
    except Exception as exc:
        logger.debug("Broadcast notification suppressed: %s", exc)

