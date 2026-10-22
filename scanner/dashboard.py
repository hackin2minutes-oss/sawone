#!/usr/bin/env python3
"""
Sawone portfolio dashboard: one page for every repository that runs Sawone.

  dashboard.py --inputs reports-by-repo/ --history history.json --out site/ [--title "..."]

--inputs   one sub-directory per repository (owner__repo), each holding that repository's latest report
           files: summary.json, findings-consolidated.json (and optionally evidence/index.json)
--history  JSON file of earlier snapshots; this run's snapshot is appended (one per repository per day)
--out      writes index.html (self-contained) and data.json

The page shows the portfolio verdict, then per repository: last scan, verdict, gates, blocking findings by
severity, known-exploited and live-secret counts, findings past their fix deadline, a trend line from the
history, and NCA/SAMA compliance coverage; then the top risks across the portfolio.
"""
import argparse
import datetime as dt
import html
import json
from collections import Counter
from pathlib import Path

import phases as PH

SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
COLORS = {"CRITICAL": "#7f1d1d", "HIGH": "#dc2626", "MEDIUM": "#f59e0b", "LOW": "#3b82f6"}


def esc(x):
    return html.escape(str(x if x is not None else ""))


def load(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError):
        return None


def snapshot(name, d):
    s = load(d / "summary.json") or {}
    merged = load(d / "findings-consolidated.json") or []
    blocking = [f for f in merged if f.get("gating")]
    stages = s.get("stages") or []
    failed = [r for r in stages if r.get("status") == "failed" and r.get("gate", True)]
    errors = [r for r in stages if r.get("status") == "error"]
    gates = [r for r in stages if r.get("gate", True) and r.get("status") in ("passed", "failed", "error")]
    comp = s.get("compliance") or []
    by_fw = {}
    for c in comp:
        fw = by_fw.setdefault(c["framework"], Counter())
        fw[c["status"]] += 1
    run = (load(d / "evidence" / "index.json") or {}).get("run") or {}
    return {
        "repo": s.get("repository") or name.replace("__", "/"),
        "scanned": (s.get("generated") or (load(d / "evidence" / "index.json") or {}).get("generated") or "")[:16].replace("T", " "),
        "ref": run.get("REF", ""), "sha": run.get("SHA", "")[:12], "run_url": run.get("RUN_URL", ""),
        "passed": bool(s.get("passed")), "enforce": s.get("enforce", True),
        "gates_failed": len(failed), "gates_total": len(gates), "errors": len(errors),
        "blocking": len(blocking), "by_sev": dict(Counter(f.get("severity") for f in blocking)),
        "kev": len({f["id"] for f in merged if f.get("kev")}),
        "live": sum(1 for f in merged if f.get("verified")),
        "overdue": sum(1 for f in blocking if f.get("overdue")),
        "new": (s.get("trend") or {}).get("new"), "fixed": (s.get("trend") or {}).get("fixed"),
        "compliance": {fw: dict(c) for fw, c in by_fw.items()},
        "phases": PH.status(stages, _sel(s.get("phases")), bool(failed), bool(errors)),
        "top": [{"id": f["id"], "title": f.get("title", ""), "severity": f.get("severity"), "kev": bool(f.get("kev")),
                 "where": f.get("package") and f"{f['package']} {f.get('version', '')}" or f.get("location", ""),
                 "tools": f.get("tools") or [f.get("tool")]} for f in blocking[:5]],
    }


def _sel(value):
    try:
        return PH.parse(value)
    except ValueError:
        return list(PH.PHASES)


PH_COLOR = {"passed": "#16a34a", "failed": "#dc2626", "error": "#d97706", "report": "#4f46e5", "skipped": "#cbd5e1",
            "notsel": "#e2e8f0", "elsewhere": "#94a3b8"}


def lifecycle(st):
    """Eight chips, Plan to Monitor, coloured by result; the title attribute names phase and result."""
    return '<div class="lc">' + "".join(
        f'<span title="{PH.TITLES[p]}: {esc(st.get(p, "skipped"))}" style="background:{PH_COLOR.get(st.get(p), "#cbd5e1")}">'
        f'{PH.TITLES[p][0]}</span>' for p in PH.PHASES) + "</div>"


def spark(points, w=110, h=26):
    if len(points) < 2:
        return '<span class="muted">—</span>'
    hi = max(points) or 1
    step = w / (len(points) - 1)
    xy = " ".join(f"{i * step:.1f},{h - 2 - (p / hi) * (h - 4):.1f}" for i, p in enumerate(points))
    up = points[-1] > points[0]
    col = "#dc2626" if up else "#16a34a"
    return (f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}"><polyline fill="none" stroke="{col}" '
            f'stroke-width="1.6" points="{xy}"/></svg>')


def bar(by_sev, w=120, h=9):
    total = sum(by_sev.get(s, 0) for s in SEVS)
    if not total:
        return ""
    x, parts = 0.0, []
    for s in SEVS:
        bw = w * by_sev.get(s, 0) / total
        if bw:
            parts.append(f'<rect x="{x:.1f}" y="0" width="{bw:.1f}" height="{h}" fill="{COLORS[s]}"/>')
            x += bw
    return f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}">{"".join(parts)}</svg>'


CSS = """
.lc { display: flex; gap: 2px; margin-top: 5px; } .lc span { width: 15px; height: 15px; border-radius: 3px; color: #fff;
  font-size: 9px; font-weight: 700; display: inline-flex; align-items: center; justify-content: center; }
:root { --bg:#f8fafc; --card:#fff; --ink:#0f172a; --muted:#64748b; --line:#e2e8f0; --head:#0b1220; }
@media (prefers-color-scheme: dark) { :root { --bg:#0b1220; --card:#111827; --ink:#e2e8f0; --muted:#94a3b8; --line:#1f2937; } }
* { box-sizing: border-box; } body { margin:0; background:var(--bg); color:var(--ink); font:14px/1.45 Inter, system-ui, sans-serif; }
header { background:var(--head); color:#e2e8f0; padding:22px 16px; } header .in, main { max-width:1200px; margin:0 auto; }
header h1 { margin:0 0 4px; font-size:22px; } header .sub { color:#94a3b8; font-size:13px; }
main { padding:16px; } .tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:10px; margin:14px 0 20px; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:12px; }
.tile .n { font-size:26px; font-weight:700; } .tile .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.3px; }
.red { color:#dc2626; } .green { color:#16a34a; } .dark { color:#991b1b; } .amber { color:#d97706; }
h2 { font-size:17px; margin:26px 0 10px; } .wrap { overflow-x:auto; background:var(--card); border:1px solid var(--line); border-radius:10px; }
table { width:100%; border-collapse:collapse; min-width:860px; } th, td { padding:9px 10px; border-bottom:1px solid var(--line); text-align:left; vertical-align:top; }
th { font-size:11px; text-transform:uppercase; letter-spacing:.3px; color:var(--muted); }
.pill { display:inline-block; padding:2px 8px; border-radius:20px; font-size:11px; font-weight:600; }
.ok { background:#dcfce7; color:#166534; } .bad { background:#fee2e2; color:#991b1b; } .warn { background:#fef3c7; color:#92400e; }
.mono { font-family: ui-monospace, Menlo, monospace; font-size:12px; } .muted { color:var(--muted); } .small { font-size:12px; }
.sev { display:inline-block; min-width:58px; text-align:center; color:#fff; border-radius:4px; font-size:11px; font-weight:700; padding:1px 4px; }
.kev { background:#7f1d1d; color:#fff; border-radius:4px; padding:0 5px; font-size:10px; font-weight:700; }
a { color:inherit; } footer { color:var(--muted); font-size:12px; padding:20px 16px 40px; max-width:1200px; margin:0 auto; }
"""


def render(snaps, history, title):
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    failing = [s for s in snaps if not s["passed"]]
    tot = Counter()
    for s in snaps:
        for k in ("blocking", "kev", "live", "overdue"):
            tot[k] += s[k]
    tiles = [(len(snaps), "Repositories", ""), (len(failing), "Failing", "red" if failing else "green"),
             (tot["blocking"], "Blocking findings", "red" if tot["blocking"] else "green"),
             (tot["kev"], "Known exploited (KEV)", "dark" if tot["kev"] else "green"),
             (tot["live"], "Live secrets", "dark" if tot["live"] else "green"),
             (tot["overdue"], "Past fix deadline", "amber" if tot["overdue"] else "green")]
    out = [f'<!doctype html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>'
           f'<title>{esc(title)}</title><style>{CSS}</style></head><body>',
           f'<header><div class="in"><h1>{esc(title)}</h1><div class="sub">Sawone portfolio · {len(snaps)} repositories · '
           f'updated {now}</div></div></header><main>',
           '<div class="tiles">' + "".join(f'<div class="tile"><div class="n {c}">{n}</div><div class="l">{esc(lbl)}</div></div>'
                                          for n, lbl, c in tiles) + '</div>']
    rows = []
    for s in sorted(snaps, key=lambda x: (x["passed"], -x["kev"], -x["blocking"])):
        hist = [h["blocking"] for h in history.get(s["repo"], [])][-20:]
        verdict = ('<span class="pill ok">passed</span>' if s["passed"] else
                   '<span class="pill warn">incomplete</span>' if s["errors"] and not s["gates_failed"] else
                   '<span class="pill bad">failed</span>')
        sev = " ".join(f'<span class="small" style="color:{COLORS[k]}">{k[0]}{v}</span>' for k, v in
                       ((k, s["by_sev"].get(k, 0)) for k in SEVS) if v)
        delta = ""
        if s.get("new") is not None:
            delta = f'<div class="small muted">{s["new"]} new · {s["fixed"]} fixed since last scan</div>'
        name = f'<a href="{esc(s["run_url"])}">{esc(s["repo"])}</a>' if s["run_url"] else esc(s["repo"])
        rows.append(f'<tr><td><b>{name}</b><div class="small muted mono">{esc(s["ref"])} {esc(s["sha"])}</div></td>'
                    f'<td class="small">{esc(s["scanned"])}</td><td>{verdict}{lifecycle(s.get("phases") or {})}</td>'
                    f'<td>{s["gates_failed"]} / {s["gates_total"]}' + (f' <span class="small amber">+{s["errors"]} err</span>' if s["errors"] else "")
                    + f'</td><td><b>{s["blocking"]}</b><div>{bar(s["by_sev"])}</div><div>{sev}</div>{delta}</td>'
                    f'<td class="{"dark" if s["kev"] else ""}"><b>{s["kev"]}</b></td><td class="{"dark" if s["live"] else ""}">{s["live"]}</td>'
                    f'<td class="{"amber" if s["overdue"] else ""}">{s["overdue"]}</td><td>{spark(hist)}</td></tr>')
    out.append('<h2>Repositories</h2><div class="wrap"><table><thead><tr><th>Repository</th><th>Last scan</th><th>Verdict · lifecycle</th>'
               '<th>Gates failed</th><th>Blocking</th><th>KEV</th><th>Live secrets</th><th>Overdue</th><th>Trend (blocking)</th>'
               '</tr></thead><tbody>' + "".join(rows) + '</tbody></table></div>'
               '<p class="small muted">Lifecycle: Plan · Code · Build · Test · Release · Deploy · Operate · Monitor. '
               'Green passed, red failed, amber scanner error, grey run by a separate workflow or not selected.</p>')
    # compliance coverage
    fws = sorted({fw for s in snaps for fw in s["compliance"]})
    if fws:
        crow = []
        for s in snaps:
            cells = []
            for fw in fws:
                c = s["compliance"].get(fw) or {}
                total = sum(c.values())
                if not total:
                    cells.append('<td class="muted">—</td>')
                    continue
                pct = round(100 * c.get("evidenced", 0) / total)
                cls = "green" if not c.get("gap") and not c.get("unverified") else "red" if c.get("gap") else "amber"
                cells.append(f'<td><b class="{cls}">{pct}%</b><div class="small muted">{c.get("gap", 0)} gap</div></td>')
            crow.append(f'<tr><td><b>{esc(s["repo"])}</b></td>{"".join(cells)}</tr>')
        out.append('<h2>Compliance evidence coverage</h2><div class="wrap"><table><thead><tr><th>Repository</th>'
                   + "".join(f"<th>{esc(fw)}</th>" for fw in fws) + '</tr></thead><tbody>' + "".join(crow)
                   + '</tbody></table></div><p class="small muted">Share of each framework\'s mapped controls evidenced by '
                     'the latest scan. An evidence map, not a compliance attestation.</p>')
    # top risks across the portfolio
    risks = [(s["repo"], f) for s in snaps for f in s["top"]]
    risks.sort(key=lambda rf: (not rf[1]["kev"], SEVS.index(rf[1]["severity"]) if rf[1]["severity"] in SEVS else 9))
    if risks:
        rr = "".join(f'<tr><td><span class="sev" style="background:{COLORS.get(f["severity"], "#9ca3af")}">{esc(f["severity"])}</span>'
                     + (' <span class="kev">KEV</span>' if f["kev"] else "")
                     + f'</td><td><span class="mono">{esc(f["id"])}</span><div class="small">{esc(f["title"][:140])}</div></td>'
                     f'<td class="mono small">{esc(str(f["where"])[:80])}</td><td>{esc(repo)}</td></tr>'
                     for repo, f in risks[:25])
        out.append('<h2>Top risks across the portfolio</h2><div class="wrap"><table><thead><tr><th>Severity</th><th>Finding</th>'
                   '<th>Where</th><th>Repository</th></tr></thead><tbody>' + rr + '</tbody></table></div>')
    out.append('</main><footer>Generated by Sawone from each repository\'s latest scan artefact. Findings are tool output; '
               'see each repository\'s security report for evidence and remediation.</footer></body></html>')
    return "".join(out)


def update_history(history, snaps):
    today = dt.date.today().isoformat()
    for s in snaps:
        h = [x for x in history.get(s["repo"], []) if x.get("date") != today]
        h.append({"date": today, "blocking": s["blocking"], "kev": s["kev"], "overdue": s["overdue"],
                  "gates_failed": s["gates_failed"], "passed": s["passed"]})
        history[s["repo"]] = h[-180:]
    return history


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", required=True)
    ap.add_argument("--history", default="history.json")
    ap.add_argument("--out", default="site")
    ap.add_argument("--title", default="Security posture")
    a = ap.parse_args()
    snaps = [snapshot(d.name, d) for d in sorted(Path(a.inputs).iterdir()) if (d / "summary.json").exists()]
    history = update_history(load(a.history) or {}, snaps)
    Path(a.history).write_text(json.dumps(history, indent=1))
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "index.html").write_text(render(snaps, history, a.title))
    (out / "data.json").write_text(json.dumps({"generated": dt.datetime.now(dt.timezone.utc).isoformat(),
                                               "repositories": snaps, "history": history}, indent=1))
    print(f"dashboard: {len(snaps)} repositories → {out / 'index.html'}")
    return 0 if snaps else 1


if __name__ == "__main__":
    raise SystemExit(main())
