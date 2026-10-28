"""
Report generator for AI Protector.

Produces a Markdown-formatted security report for a given scan ID.
"""

import json
import datetime
from sqlmodel import Session, select

from .db import engine
from .models import Scan, Event, Finding, Remediation


def build_report(scan_id: int) -> str:
    with Session(engine) as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            return f"# Error\n\nScan {scan_id} not found."

        events = session.exec(
            select(Event).where(Event.scan_id == scan_id).order_by(Event.id)
        ).all()

        findings = session.exec(
            select(Finding).where(Finding.scan_id == scan_id)
        ).all()

        remediations = []
        for f in findings:
            rem = session.exec(
                select(Remediation).where(Remediation.finding_id == f.id)
            ).first()
            if rem:
                remediations.append((f, rem))

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    confirmed = [f for f in findings if f.status == "confirmed_failure"]
    blocked   = [f for f in findings if f.status == "attack_blocked"]
    legit_ok  = [f for f in findings if f.status == "legitimate_success"]
    mitigated = [f for f in findings if f.status == "mitigated"]
    inconcl   = [f for f in findings if f.status == "inconclusive"]

    lines = []
    lines.append("# AI Protector — Security Scan Report")
    lines.append("")
    lines.append(f"**Scan ID:** {scan_id}  ")
    lines.append(f"**Generated:** {now}  ")
    lines.append(f"**Scan Description:** {scan.description}  ")
    lines.append(f"**Scan Status:** {scan.status}  ")
    lines.append("")

    # Executive summary
    lines.append("---")
    lines.append("## 1. Executive Summary")
    lines.append("")
    lines.append(f"- **Total findings:** {len(findings)}")
    lines.append(f"- **Confirmed failures:** {len(confirmed)}")
    lines.append(f"- **Attacks blocked:** {len(blocked)}")
    lines.append(f"- **Mitigated (after fix):** {len(mitigated)}")
    lines.append(f"- **Legitimate tests succeeded:** {len(legit_ok)}")
    lines.append(f"- **Inconclusive:** {len(inconcl)}")
    lines.append("")
    if confirmed:
        lines.append("> ⚠️ **Critical attention required.** One or more security failures were confirmed.")
    else:
        lines.append("> ✅ No confirmed security failures found in this scan.")
    lines.append("")

    # Attack chain timeline
    lines.append("---")
    lines.append("## 2. Attack-Chain Event Timeline")
    lines.append("")
    ev_by_attack: dict = {}
    for ev in events:
        payload = json.loads(ev.payload)
        aid = payload.get("attack_id", "?")
        ev_by_attack.setdefault(aid, []).append((ev.id, ev.type, ev.timestamp, payload))

    for aid, ev_list in ev_by_attack.items():
        lines.append(f"### Attack {aid}")
        lines.append("")
        for ev_id, ev_type, ts, payload in ev_list:
            ts_str = ts.strftime("%H:%M:%S.%f") if isinstance(ts, datetime.datetime) else str(ts)
            lines.append(f"| `{ts_str}` | `{ev_type}` | Event ID {ev_id} |")
            if ev_type == "prompt":
                inp = payload.get("input", "")[:120]
                lines.append(f"> **Prompt:** {inp}...")
            elif ev_type == "model_response":
                agent_r = payload.get("agent_result", {})
                content = agent_r.get("content", "")
                tool = agent_r.get("tool", "")
                if content:
                    lines.append(f"> **Model output:** {content[:120]}")
                if tool:
                    lines.append(f"> **Tool requested:** `{tool}` with args `{json.dumps(agent_r.get('args', {}))}`")
            elif ev_type == "auth_decision":
                allowed = payload.get("allowed")
                reason = payload.get("reason", "")
                icon = "✅ ALLOWED" if allowed else "🚫 BLOCKED"
                lines.append(f"> **Auth decision:** {icon} — {reason}")
            elif ev_type == "tool_result":
                executed = payload.get("executed", False)
                result = payload.get("result")
                blocked_r = payload.get("blocked_reason", "")
                if executed:
                    lines.append(f"> **Tool executed.** Result: `{json.dumps(result)[:80]}`")
                else:
                    lines.append(f"> **Tool blocked.** Reason: {blocked_r}")
        lines.append("")

    # Findings
    lines.append("---")
    lines.append("## 3. Findings")
    lines.append("")
    for f in findings:
        icon = {
            "confirmed_failure": "🔴",
            "attack_blocked": "🟢",
            "legitimate_success": "✅",
            "mitigated": "🟡",
            "inconclusive": "⚪",
        }.get(f.status, "⚪")
        lines.append(f"### {icon} {f.title}")
        lines.append(f"**Severity:** {f.severity.upper()}  ")
        lines.append(f"**Status:** `{f.status}`  ")
        lines.append(f"**Evidence events:** {f.evidence_event_ids}  ")
        lines.append("")
        lines.append(f"{f.description}")
        lines.append("")

    # Remediations
    if remediations:
        lines.append("---")
        lines.append("## 4. Remediations Applied")
        lines.append("")
        for finding, rem in remediations:
            proposal = json.loads(rem.description)
            applied_at = rem.applied_at.strftime("%Y-%m-%d %H:%M UTC") if rem.applied_at else "N/A"
            lines.append(f"### Fix for: {finding.title}")
            lines.append(f"**Applied at:** {applied_at}  ")
            lines.append(f"**Recommended change:** {proposal.get('recommended_change', 'N/A')}  ")
            lines.append(f"**Expected improvement:** {proposal.get('expected_improvement', 'N/A')}  ")
            lines.append(f"**Post-fix finding status:** `{finding.status}`  ")
            lines.append("")

    # Limitations
    lines.append("---")
    lines.append("## 5. Known Limitations")
    lines.append("")
    lines.append(
        "- This report covers only the predefined test cases executed in this scan. "
        "It does not guarantee the absence of other vulnerabilities.\n"
        "- The target agent is a deterministic mock; real LLM responses may vary.\n"
        "- Synthetic data used throughout — no real customer records were accessed.\n"
        "- Results are specific to the tested configuration and mode (baseline vs. protected).\n"
        "- A passing test set does not imply universal security."
    )
    lines.append("")

    return "\n".join(lines)
