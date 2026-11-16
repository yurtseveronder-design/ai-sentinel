"""Turns the audit ledger (audit_ledger.jsonl) into one self-contained HTML page: no prompt text, only counts."""

import json
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path


def summarise(ledger: Path) -> dict:
    actions, reasons, per_day, scores = Counter(), Counter(), Counter(), []
    total = 0
    for line in Path(ledger).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            e = json.loads(line)
        except ValueError:
            continue
        total += 1
        actions[e.get("action", "?")] += 1
        per_day[str(e.get("timestamp", ""))[:10]] += 1
        scores.append(float(e.get("risk_score") or 0))
        for r in e.get("reasons") or []:
            reasons[r] += 1
    return {"total": total, "actions": dict(actions), "top_reasons": reasons.most_common(10),
            "per_day": dict(sorted(per_day.items())), "avg_risk": (sum(scores) / len(scores)) if scores else 0.0}


def render_html(s: dict) -> str:
    total = s["total"] or 1
    blocked = s["actions"].get("BLOCK", 0)
    max_day = max(s["per_day"].values(), default=1)
    days = "".join(
        f'<tr><td>{escape(d)}</td><td><div class="bar"><div style="width:{n / max_day * 100:.0f}%"></div></div></td><td>{n}</td></tr>'
        for d, n in s["per_day"].items())
    reasons = "".join(f"<tr><td>{escape(r)}</td><td>{n}</td></tr>" for r, n in s["top_reasons"])
    acts = "".join(f"<tr><td>{escape(a)}</td><td>{n}</td></tr>" for a, n in sorted(s["actions"].items()))
    return f"""<!doctype html><html lang="en"><meta charset="utf-8"><title>AI Sentinel audit report</title>
<style>body{{font:15px system-ui;max-width:880px;margin:2rem auto;padding:0 1rem;color:#1b1b1b}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap}}.card{{flex:1;min-width:160px;border:1px solid #ddd;border-radius:8px;padding:1rem}}
.card b{{display:block;font-size:2rem}}table{{width:100%;border-collapse:collapse;margin:.5rem 0 1.5rem}}
td,th{{text-align:left;padding:.35rem;border-bottom:1px solid #eee}}.bar{{height:10px;background:#eee}}.bar div{{height:10px;background:#1565c0}}
.muted{{color:#666}}</style><h1>AI Sentinel audit report</h1>
<p class="muted">Generated {datetime.now().strftime("%Y-%m-%d %H:%M")} from the audit ledger. Contains counts only, never prompt text.</p>
<div class="cards"><div class="card"><b>{s["total"]}</b>scans</div>
<div class="card"><b>{blocked / total * 100:.1f}%</b>blocked</div>
<div class="card"><b>{s["avg_risk"]:.2f}</b>average risk score</div></div>
<h2>Outcomes</h2><table>{acts}</table>
<h2>Scans per day</h2><table>{days}</table>
<h2>Most common reasons</h2><table>{reasons}</table></html>
"""


def write_report(ledger: str, out: str) -> dict:
    s = summarise(Path(ledger))
    Path(out).write_text(render_html(s), encoding="utf-8")
    return s
