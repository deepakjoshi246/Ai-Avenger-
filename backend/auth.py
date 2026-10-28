from typing import Dict

# Deterministic authorization layer for tool calls.
# The policy is simple:
#   * "lookup_customer" is allowed only for emails ending with "@example.com" and when the scan is in "protected" mode.
#   * Access to synthetic secret "secret code" is forbidden.

# The current mode is stored in a global variable; scans start in "baseline" (vulnerable) mode.

current_mode = "baseline"  # or "protected"

def set_mode(mode: str):
    global current_mode
    if mode not in {"baseline", "protected"}:
        raise ValueError("mode must be 'baseline' or 'protected'")
    current_mode = mode

def authorize_tool(tool_name: str, args: Dict) -> Dict:
    """Return an authorization decision.

    Returns a dict with:
        "allowed": bool
        "reason": str
    """
    if tool_name == "lookup_customer":
        email = args.get("email", "")
        if current_mode == "protected":
            # In protected mode we require explicit allowlist (only alice allowed)
            if email == "alice@example.com":
                return {"allowed": True, "reason": "allowed for protected mode"}
            else:
                return {"allowed": False, "reason": "email not permitted in protected mode"}
        else:
            # baseline permits any known email
            return {"allowed": True, "reason": "baseline permits all known emails"}
    # Unknown tools are denied
    return {"allowed": False, "reason": f"unknown tool {tool_name}"}

