"""Queries on a uiautomator dump (XML on stdin), for e2e/run.sh.

  ui.py has <regex>          exit 0 when a node's text or content-desc matches
  ui.py center <regex>       "x y" of the first such node (exit 1: none)
  ui.py texts                every text on screen, " | "-separated
  ui.py fgs_row <label>      Quick Settings > Active apps, the row of app <label>:
                             stop (Stop button enabled), stopped, none (no button:
                             the app's user control is disabled), absent (no row)
  ui.py fgs_stop <label>     "x y" of that row's Stop button (exit 1: none)
  ui.py button <label>       Settings button <label> (a TextView next to the
                             clickable view): enabled / disabled (exit 1: none)
"""
import re
import sys
import xml.etree.ElementTree as ET

root = ET.parse(sys.stdin).getroot()
nodes = list(root.iter("node"))
parent = {c: p for p in root.iter() for c in p}
cmd, arg = sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else ""


def label(n):
    return (n.get("text") or "") + "\n" + (n.get("content-desc") or "")


def center(n):
    x1, y1, x2, y2 = map(int, re.findall(r"\d+", n.get("bounds")))
    return f"{(x1 + x2) // 2} {(y1 + y2) // 2}"


def fgs_button(name):
    """(row found, stop button node or None)."""
    for n in nodes:
        if n.get("resource-id", "").endswith(":id/fgs_manager_app_item_label") and n.get("text") == name:
            row = parent[parent[n]]
            for b in row.iter("node"):
                if b.get("resource-id", "").endswith(":id/fgs_manager_app_item_stop_button"):
                    return True, b
            return True, None
    return False, None


def first(rx):
    return next((n for n in nodes if any(re.search(rx, s) for s in label(n).split("\n") if s)), None)


if cmd == "has":
    sys.exit(0 if first(arg) is not None else 1)
elif cmd == "center":
    n = first(arg)
    if n is None:
        sys.exit(1)
    print(center(n))
elif cmd == "texts":
    print(" | ".join(n.get("text") for n in nodes if n.get("text")))
elif cmd == "fgs_row":
    found, b = fgs_button(arg)
    if not found:
        print("absent")
    elif b is None:
        print("none")
    elif b.get("enabled") == "true":
        print("stop")
    else:
        print("stopped")
elif cmd == "fgs_stop":
    _, b = fgs_button(arg)
    if b is None or b.get("enabled") != "true":
        sys.exit(1)
    print(center(b))
elif cmd == "button":
    for n in nodes:
        if n.get("text") == arg:
            a = n
            while a in parent:
                a = parent[a]
                clickable = [x for x in a.iter("node") if x.get("clickable") == "true"]
                if clickable:
                    print("enabled" if clickable[0].get("enabled") == "true" else "disabled")
                    sys.exit(0)
    sys.exit(1)
else:
    sys.exit(f"unknown command {cmd}")
