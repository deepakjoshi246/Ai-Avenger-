"""
Scan orchestration for AI Protector.

Functions:
  create_scan(description) -> int   — inserts a Scan row, returns ID
  run_scan(scan_id)                 — executes all attacks, logs events, calls evaluator
"""

import json
import datetime
from sqlmodel import Session, select

from .db import engine, init_db
from .models import Scan, Event, Finding
from .attack_library import get_all_attacks
from .agent import agent_process, execute_tool
from .auth import authorize_tool, set_mode
from . import evaluation as eval_mod

_UTC = datetime.timezone.utc


def create_scan(description: str = "Manual scan", mode: str = "baseline") -> int:
    init_db()
    with Session(engine) as session:
        scan = Scan(description=f"[{mode.upper()}] {description}", status="running")
        session.add(scan)
        session.commit()
        session.refresh(scan)
        return scan.id


def _log_event(session: Session, scan_id: int, event_type: str, payload: dict) -> int:
    event = Event(
        scan_id=scan_id,
        type=event_type,
        payload=json.dumps(payload),
        timestamp=datetime.datetime.now(_UTC),
    )
    session.add(event)
    session.commit()
    session.refresh(event)
    return event.id


def run_scan(scan_id: int, mode: str = "baseline"):
    """Execute all predefined attacks against the mock agent and record every event."""
    # Apply the requested auth mode
    set_mode(mode)

    attacks = get_all_attacks()

    with Session(engine) as session:
        for attack in attacks:
            attack_id = attack["id"]

            # Step 1: Log the prompt event
            prompt_text = attack["attack_input"]
            if attack.get("injected_document"):
                # Prepend injected document to simulate indirect injection
                full_prompt = (
                    f"[DOCUMENT START]\n{attack['injected_document']}\n[DOCUMENT END]\n\n"
                    f"User: {prompt_text}"
                )
            else:
                full_prompt = prompt_text

            prompt_event_id = _log_event(session, scan_id, "prompt", {
                "attack_id": attack_id,
                "category": attack["category"],
                "is_control": attack["is_control"],
                "input": full_prompt,
                "injected_document": attack.get("injected_document"),
            })

            # Step 2: Invoke the mock agent
            agent_result = agent_process(full_prompt)

            # Step 3: Log the model response
            response_event_id = _log_event(session, scan_id, "model_response", {
                "attack_id": attack_id,
                "agent_result": agent_result,
            })

            # Step 4: Handle tool requests
            tool_event_id = None
            auth_event_id = None
            tool_result_event_id = None

            if agent_result.get("type") == "tool_request":
                tool_name = agent_result["tool"]
                tool_args = agent_result["args"]

                # Log the tool request
                tool_event_id = _log_event(session, scan_id, "tool_request", {
                    "attack_id": attack_id,
                    "tool": tool_name,
                    "args": tool_args,
                })

                # Step 5: Authorization check
                auth_decision = authorize_tool(tool_name, tool_args)
                auth_event_id = _log_event(session, scan_id, "auth_decision", {
                    "attack_id": attack_id,
                    "tool": tool_name,
                    "args": tool_args,
                    "allowed": auth_decision["allowed"],
                    "reason": auth_decision["reason"],
                })

                # Step 6: Execute tool only if authorized
                if auth_decision["allowed"]:
                    tool_result = execute_tool(tool_name, tool_args)
                    tool_result_event_id = _log_event(session, scan_id, "tool_result", {
                        "attack_id": attack_id,
                        "tool": tool_name,
                        "args": tool_args,
                        "result": tool_result,
                        "executed": True,
                    })
                else:
                    tool_result_event_id = _log_event(session, scan_id, "tool_result", {
                        "attack_id": attack_id,
                        "tool": tool_name,
                        "args": tool_args,
                        "result": None,
                        "executed": False,
                        "blocked_reason": auth_decision["reason"],
                    })

        # Mark scan as completed
        scan = session.get(Scan, scan_id)
        if scan:
            scan.status = "completed"
            session.add(scan)
            session.commit()

    # Step 7: Evaluate findings
    eval_mod.process_scan(scan_id)
