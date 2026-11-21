"""AlterEgo native adapter: runs one allowlisted wrapper from the AlterEgo pc-agent and prints a JSON envelope.

Reads {"tool": str, "args": {...}} from stdin. Writes one JSON line to stdout:
  {"ok": true, "result": {...}}                     on success
  {"ok": false, "refused": true, "error": "..."}    when the tool is not allowlisted
  {"ok": false, "refused": false, "error": "..."}   on any other failure

Calls the same wrapper functions the AlterEgo MCP server registers (tool_wrappers.ALL_TOOLS).
Nothing is sent over MCP or HTTP. Anything the wrappers print goes to stderr, not stdout.
ALLOWED is read from catalog.json (written by scripts/gen-alterego-catalog.py), so there is one list.
"""
import json
import os
import sys

CATALOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog.json")


def _load_allowed():
    """Every catalog tool marked registered. A missing or unreadable catalog allows nothing."""
    try:
        with open(CATALOG, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return frozenset()
    return frozenset(t["name"] for t in data.get("tools", []) if t.get("registered"))


ALLOWED = _load_allowed()


def _emit(payload):
    sys.stdout.write(json.dumps(payload, default=str) + "\n")
    sys.stdout.flush()


def main():
    real_stdout = sys.stdout
    try:
        request = json.load(sys.stdin)
    except Exception as exc:  # malformed input
        _emit({"ok": False, "refused": False, "error": f"bad request: {exc}"})
        return 2

    tool = request.get("tool")
    args = request.get("args") or {}
    if tool not in ALLOWED:
        _emit({"ok": False, "refused": True, "error": f"tool not allowlisted: {tool}"})
        return 0
    if not isinstance(args, dict):
        _emit({"ok": False, "refused": False, "error": "args must be an object"})
        return 0

    pc_agent = os.environ.get("ALTEREGO_PC_AGENT_DIR", "")
    if not pc_agent or not os.path.isfile(os.path.join(pc_agent, "tool_wrappers.py")):
        _emit({"ok": False, "refused": False, "error": "ALTEREGO_PC_AGENT_DIR does not contain tool_wrappers.py"})
        return 0
    sys.path.insert(0, pc_agent)

    # Wrappers may print diagnostics; keep stdout clean for the envelope.
    sys.stdout = sys.stderr
    try:
        import tool_wrappers  # noqa: E402  (import after sys.path setup)

        fns = {f.__name__: f for f in tool_wrappers.ALL_TOOLS}
        fn = fns.get(tool)
        if fn is None:
            sys.stdout = real_stdout
            _emit({"ok": False, "refused": False, "error": f"tool not found in pc-agent: {tool}"})
            return 0
        result = fn(**args)
    except Exception as exc:
        sys.stdout = real_stdout
        _emit({"ok": False, "refused": False, "error": f"{type(exc).__name__}: {exc}"})
        return 0
    sys.stdout = real_stdout
    _emit({"ok": True, "result": result})
    return 0


if __name__ == "__main__":
    sys.exit(main())
