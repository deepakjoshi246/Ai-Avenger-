"""
Nebius Token Factory + NVIDIA Nemotron integration (optional).

If NEBIUS_API_KEY is set, makes real inference calls to the Nebius endpoint
using the specified NEMOTRON_MODEL (defaults to meta-llama/Meta-Llama-3.1-70B-Instruct
if the Nemotron model is unavailable).

Falls back gracefully to a deterministic simulation when credentials are missing.

IMPORTANT: Never expose NEBIUS_API_KEY in logs, responses, or the frontend.
"""

import os
import requests
from typing import Optional

NEBIUS_BASE_URL = "https://api.studio.nebius.com/v1"
DEFAULT_MODEL = os.environ.get("NEMOTRON_MODEL", "nvidia/Llama-3.1-Nemotron-70B-Instruct")


def _get_api_key() -> Optional[str]:
    return os.environ.get("NEBIUS_API_KEY")


def is_configured() -> bool:
    return bool(_get_api_key())


def analyze_attack_trace(attack_chain_summary: str) -> dict:
    """
    Use the NVIDIA Nemotron model via Nebius to analyze an attack trace.
    Returns a dict with 'analysis' and 'source' ('model' or 'simulated').
    """
    api_key = _get_api_key()

    if not api_key:
        # Graceful fallback – simulated analysis
        return {
            "source": "simulated",
            "model": None,
            "analysis": (
                "⚠️ Simulated analysis (NEBIUS_API_KEY not configured).\n\n"
                "Based on the attack chain summary, the agent was susceptible to a prompt-injection "
                "attack embedded in an untrusted document. The authorization layer was the last line "
                "of defense and was effective in protected mode. Recommended fix: enforce deterministic "
                "authorization checks outside the LLM inference path."
            ),
        }

    system_prompt = (
        "You are an AI security analyst. You will be given a summary of an attack chain "
        "executed against an AI agent. Analyze the chain, identify the failed security control, "
        "explain how the attack succeeded or was blocked, and recommend a targeted remediation. "
        "Be concise, technical, and evidence-based. Do not exaggerate the risk."
    )

    user_prompt = (
        f"Here is the recorded attack chain summary:\n\n{attack_chain_summary}\n\n"
        "Please provide:\n"
        "1. A brief analysis of what happened.\n"
        "2. Which security control failed (or succeeded).\n"
        "3. A specific, actionable remediation recommendation."
    )

    try:
        response = requests.post(
            f"{NEBIUS_BASE_URL}/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": DEFAULT_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": 512,
                "temperature": 0.3,
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        return {
            "source": "model",
            "model": DEFAULT_MODEL,
            "analysis": content,
        }
    except requests.exceptions.Timeout:
        return {
            "source": "error",
            "model": DEFAULT_MODEL,
            "analysis": "Model inference timed out. Please retry.",
        }
    except requests.exceptions.HTTPError as e:
        return {
            "source": "error",
            "model": DEFAULT_MODEL,
            "analysis": f"API error: {e.response.status_code} — {e.response.text[:200]}",
        }
    except Exception as e:
        return {
            "source": "error",
            "model": DEFAULT_MODEL,
            "analysis": f"Unexpected error: {str(e)[:200]}",
        }

