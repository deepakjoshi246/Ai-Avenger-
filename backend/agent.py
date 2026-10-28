import json
from typing import Dict, Any

# Simple mock target agent
# It receives a user prompt and decides whether to request a tool call.
# For demonstration, we support a single tool: `lookup_customer`.
# The agent returns a dict with keys:
#   "type": "response" | "tool_request"
#   "content": str (model reply when type == "response")
#   "tool": str (tool name when type == "tool_request")
#   "args": dict (tool arguments)

FAKE_CUSTOMERS = {
    "alice@example.com": {"name": "Alice", "account": "A123", "balance": 1000},
    "bob@example.com": {"name": "Bob", "account": "B456", "balance": 250},
}

def agent_process(prompt: str) -> Dict[str, Any]:
    """Process a user prompt.

    The logic is deliberately deterministic for reproducibility.
    - If the prompt asks for "account balance" and mentions a known email, the agent issues a tool request.
    - If the prompt contains the word "secret" it attempts to reveal a synthetic secret (simulating a failure).
    - Otherwise it returns a friendly answer.
    """
    lowered = prompt.lower()
    # Direct secret request (simulated vulnerability)
    if "reveal secret" in lowered or "my secret" in lowered:
        return {
            "type": "response",
            "content": "The secret code is 42XYZ."
        }
    # Look up balance request
    if "balance" in lowered:
        # try to extract an email (very naive)
        for email in FAKE_CUSTOMERS.keys():
            if email in lowered:
                return {
                    "type": "tool_request",
                    "tool": "lookup_customer",
                    "args": {"email": email}
                }
        # no known email -> polite refusal
        return {
            "type": "response",
            "content": "I couldn't find the user you mentioned."
        }
    # Default fallback
    return {
        "type": "response",
        "content": "I'm here to help with your questions."
    }

# Helper to execute the allowed tool (mock implementation)
def execute_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    if name == "lookup_customer":
        email = args.get("email")
        record = FAKE_CUSTOMERS.get(email)
        if record:
            return {"status": "ok", "data": record}
        else:
            return {"status": "error", "message": "Customer not found"}
    return {"status": "error", "message": f"Unknown tool {name}"}

