"""Generate src/engines/alterego/catalog.json from the AlterEgo pc-agent wrappers.

The catalog is the single list of AlterEgo tools the app may call. adapter.py reads its
allowlist from it, and plugin registration reads its schemas from it, so the two cannot drift.

Usage:
    python scripts/gen-alterego-catalog.py [path\\to\\alterego\\pc-agent]

The path defaults to $ALTEREGO_PC_AGENT_DIR, then ~/alterego/pc-agent. Re-run this whenever the
AlterEgo wrappers change, then review the diff.
"""
import inspect
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "src" / "engines" / "alterego" / "catalog.json"

# Tools that replay or batch other tools by name. Their inner calls cannot be checked one by one,
# so they are not registered in the app.
NOT_REGISTERED = {
    "macro_replay": "replays recorded tool calls the scope gate cannot read",
}

# Python annotation text -> JSON schema type. Unknown annotations fall back to "string".
TYPE_MAP = [
    ("bool", "boolean"),
    ("int", "integer"),
    ("float", "number"),
    ("dict", "object"),
    ("list", "array"),
    ("str", "string"),
]


def json_type(annotation: str) -> str:
    text = annotation or ""
    for needle, kind in TYPE_MAP:
        if needle in text:
            return kind
    return "string"


def clean_default(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return None


def main() -> int:
    pc_agent = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get(
        "ALTEREGO_PC_AGENT_DIR", str(Path.home() / "alterego" / "pc-agent")))
    if not (pc_agent / "tool_wrappers.py").is_file():
        print(f"no tool_wrappers.py in {pc_agent}", file=sys.stderr)
        return 2
    sys.path.insert(0, str(pc_agent))
    import tool_wrappers  # noqa: E402

    tools = []
    for fn in tool_wrappers.ALL_TOOLS:
        sig = inspect.signature(fn)
        params = {}
        required = []
        for p in sig.parameters.values():
            if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
                continue
            annotation = p.annotation if isinstance(p.annotation, str) else getattr(p.annotation, "__name__", str(p.annotation))
            if annotation is inspect._empty or annotation == "":
                annotation = "str"
            spec = {"type": json_type(annotation), "description": f"{p.name} ({annotation})"}
            if p.default is inspect._empty:
                required.append(p.name)
            else:
                default = clean_default(p.default)
                if default is not None:
                    spec["default"] = default
            params[p.name] = spec
        doc = (inspect.getdoc(fn) or "").strip().split("\n")[0][:240]
        entry = {
            "name": fn.__name__,
            "description": doc or f"AlterEgo tool {fn.__name__} (native).",
            "parameters": params,
            "required": required,
            "registered": fn.__name__ not in NOT_REGISTERED,
        }
        if fn.__name__ in NOT_REGISTERED:
            entry["notRegisteredReason"] = NOT_REGISTERED[fn.__name__]
        tools.append(entry)

    tools.sort(key=lambda t: t["name"])
    catalog = {
        "source": "AlterEgo pc-agent tool_wrappers.ALL_TOOLS",
        "count": len(tools),
        "registered": sum(1 for t in tools if t["registered"]),
        "tools": tools,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUT} : {catalog['count']} tools, {catalog['registered']} registered")
    return 0


if __name__ == "__main__":
    sys.exit(main())
