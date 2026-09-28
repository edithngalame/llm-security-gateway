"""Backtest: replay labelled traffic through the gateway and measure how it performs.

Input is JSONL, one message per line:
    {"text": "...", "label": 1, "source": "user", "lang": "en", "family": "override"}
label: 1 = attack, 0 = benign. source/lang/family are optional (used for breakdowns).

A message counts as "caught" when the gateway BLOCKS it. Flags are reported
separately: they are logged for review but don't stop the attack.

Usage:
    python -m gateway.backtest data/samples/demo_traffic.jsonl
    python -m gateway.backtest traffic.jsonl --block retrieved=0.35 --out report.md
    python -m gateway.backtest traffic.jsonl --html reports/backtest.html --charts docs/img
    python -m gateway.backtest traffic.jsonl --record v0.1 --charts docs/img
--block compares the current thresholds against overrides (a what-if).
--html writes a self-contained visual report you can open in a browser or publish.
--charts writes SVG charts for the README.
--record appends this run to docs/results/history.json for the progress chart.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from html import escape
from pathlib import Path

from gateway import charts
from gateway.config import build_detectors
from gateway.detectors import Source
from gateway.policy import DEFAULT_THRESHOLDS, Action, Policy, Thresholds


@dataclass
class Sample:
    text: str
    label: int
    source: Source = Source.USER
    lang: str = "unknown"
    family: str = "unknown"


@dataclass
class Outcome:
    sample: Sample
    action: Action
    score: float
    latency_ms: float

    @property
    def predicted(self) -> int:
        return int(self.action == Action.BLOCK)


@dataclass
class Metrics:
    tp: int = 0
    fn: int = 0
    fp: int = 0
    tn: int = 0
    flagged_attacks: int = 0

    def add(self, o: Outcome) -> None:
        if o.sample.label == 1:
            if o.predicted:
                self.tp += 1
            else:
                self.fn += 1
                self.flagged_attacks += o.action == Action.FLAG
        elif o.predicted:
            self.fp += 1
        else:
            self.tn += 1

    @property
    def n(self) -> int:
        return self.tp + self.fn + self.fp + self.tn

    @property
    def recall(self) -> float | None:
        return self.tp / (self.tp + self.fn) if self.tp + self.fn else None

    @property
    def precision(self) -> float | None:
        return self.tp / (self.tp + self.fp) if self.tp + self.fp else None

    @property
    def fpr(self) -> float | None:
        return self.fp / (self.fp + self.tn) if self.fp + self.tn else None

    def as_dict(self) -> dict:
        return {"n": self.n, "tp": self.tp, "fn": self.fn, "fp": self.fp, "tn": self.tn,
                "recall": self.recall, "precision": self.precision, "fpr": self.fpr,
                "attacks_only_flagged": self.flagged_attacks}


@dataclass
class Report:
    name: str
    outcomes: list[Outcome]
    overall: Metrics = field(default_factory=Metrics)
    by: dict[str, dict[str, Metrics]] = field(default_factory=dict)

    @property
    def latencies(self) -> list[float]:
        return sorted(o.latency_ms for o in self.outcomes)

    def latency(self, q: float) -> float:
        lat = self.latencies
        return lat[min(len(lat) - 1, int(q * len(lat)))] if lat else 0.0


def load(path: str | Path) -> list[Sample]:
    samples = []
    for lineno, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("//"):
            continue
        try:
            row = json.loads(line)
            samples.append(Sample(
                text=row["text"], label=int(row["label"]),
                source=Source(row.get("source", "user")),
                lang=row.get("lang", "unknown"), family=row.get("family", "unknown"),
            ))
        except (KeyError, ValueError) as e:
            raise ValueError(f"{path}:{lineno}: bad row ({e})") from e
    return samples


def run(samples: list[Sample], policy: Policy, name: str = "current") -> Report:
    report = Report(name=name, outcomes=[])
    by: dict[str, dict[str, Metrics]] = {k: defaultdict(Metrics) for k in ("source", "lang", "family")}
    for s in samples:
        start = time.perf_counter()
        d = policy.evaluate(s.text, s.source)
        o = Outcome(s, d.action, d.score, (time.perf_counter() - start) * 1000)
        report.outcomes.append(o)
        report.overall.add(o)
        by["source"][s.source.value].add(o)
        by["lang"][s.lang].add(o)
        if s.label == 1:  # families only make sense for attacks
            by["family"][s.family].add(o)
    report.by = {k: dict(v) for k, v in by.items()}
    return report


def sweep(report: Report, source: Source, thresholds=None) -> list[dict]:
    """What recall/FPR would each block threshold have given, for one source?"""
    thresholds = thresholds or [round(0.05 * i, 2) for i in range(1, 20)]
    rows = [o for o in report.outcomes if o.sample.source == source]
    out = []
    for t in thresholds:
        m = Metrics()
        for o in rows:
            m.add(replace(o, action=Action.BLOCK if o.score >= t else Action.ALLOW))
        out.append({"threshold": t, "recall": m.recall, "fpr": m.fpr})
    return out


# ---------- formatting ----------

def _pct(x: float | None) -> str:
    return "—" if x is None else f"{100 * x:.1f}%"


def _table(groups: dict[str, Metrics], attacks_only: bool = False) -> str:
    if attacks_only:
        lines = ["| family | attacks | caught | recall |", "|---|---|---|---|"]
        for k, m in sorted(groups.items(), key=lambda kv: (kv[1].recall or 0)):
            lines.append(f"| {k} | {m.tp + m.fn} | {m.tp} | {_pct(m.recall)} |")
    else:
        lines = ["| group | n | recall | precision | FPR |", "|---|---|---|---|---|"]
        for k, m in sorted(groups.items()):
            lines.append(f"| {k} | {m.n} | {_pct(m.recall)} | {_pct(m.precision)} | {_pct(m.fpr)} |")
    return "\n".join(lines)


def to_markdown(reports: list[Report], show_errors: int = 15) -> str:
    base = reports[0]
    out = ["# Backtest report", "",
           (f"{base.overall.n} messages "
           f"({base.overall.tp + base.overall.fn} attacks, {base.overall.fp + base.overall.tn} benign)"), ""]

    out += ["## Summary", "", "| config | recall | precision | FPR | attacks only flagged | p50 ms | p95 ms |",
            "|---|---|---|---|---|---|---|"]
    for r in reports:
        m = r.overall
        out.append(f"| {r.name} | {_pct(m.recall)} | {_pct(m.precision)} | {_pct(m.fpr)} | "
                   f"{m.flagged_attacks} | {r.latency(0.5):.2f} | {r.latency(0.95):.2f} |")

    for r in reports:
        out += ["", f"## Breakdown: {r.name}", "", "### By source", "", _table(r.by["source"]),
                "", "### By language", "", _table(r.by["lang"]),
                "", "### By attack family (weakest first)", "", _table(r.by["family"], attacks_only=True)]

    out += ["", "## Threshold sweep (current config)", "",
            ("What each block threshold *would* have done. Use it to pick thresholds, "
            "but on a validation set, not the test set you report."), ""]
    for src in Source:
        rows = sweep(base, src)
        if not any(o.sample.source == src for o in base.outcomes):
            continue
        out += [f"**{src.value}**", "", "| threshold | recall | FPR |", "|---|---|---|"]
        out += [f"| {r['threshold']:.2f} | {_pct(r['recall'])} | {_pct(r['fpr'])} |" for r in rows[1::2]]
        out.append("")

    missed = [o for o in base.outcomes if o.sample.label == 1 and not o.predicted]
    wrong = [o for o in base.outcomes if o.sample.label == 0 and o.predicted]
    out += ["## Errors (current config)", "", f"### Missed attacks ({len(missed)})", ""]
    out += [f"- `{o.sample.source.value}/{o.sample.lang}` score {o.score:.2f}: {o.sample.text[:100]}"
            for o in sorted(missed, key=lambda o: o.score)[:show_errors]]
    out += ["", f"### Benign messages blocked ({len(wrong)})", ""]
    out += [f"- `{o.sample.source.value}/{o.sample.lang}` score {o.score:.2f}: {o.sample.text[:100]}"
            for o in sorted(wrong, key=lambda o: -o.score)[:show_errors]]
    return "\n".join(out) + "\n"


# ---------- visual outputs ----------

HISTORY = Path("docs/results/history.json")


def build_charts(report: Report, history: list[dict] | None = None) -> dict[str, str]:
    """Return {filename: svg} for one report."""
    n_att = report.overall.tp + report.overall.fn
    sub = f"{report.name} config · {n_att} attacks in the evaluation set"
    fams = [(k, m.recall, m.tp + m.fn) for k, m in report.by["family"].items()]
    out = {
        "family_recall.svg": charts.family_recall(fams, sub),
        "by_language.svg": charts.grouped_rates(
            [(k, m.recall, m.fpr) for k, m in sorted(report.by["lang"].items())],
            "Performance by language", sub),
        "by_source.svg": charts.grouped_rates(
            [(k, m.recall, m.fpr) for k, m in sorted(report.by["source"].items())],
            "Performance by where the text came from", sub),
    }
    for src in Source:
        if any(o.sample.source == src for o in report.outcomes):
            out[f"threshold_{src.value}.svg"] = charts.threshold_sweep(
                sweep(report, src), DEFAULT_THRESHOLDS[src].block, src.value)
    if history:
        out["progress.svg"] = charts.progress(history)
    return out


def load_history(path: Path = HISTORY, dataset: str | None = None) -> list[dict]:
    """History entries, only for the same evaluation set: numbers from different
    datasets can't be compared, so mixing them would be misleading."""
    if not path.exists():
        return []
    rows = json.loads(path.read_text(encoding="utf-8"))
    return [r for r in rows if dataset is None or r.get("dataset") == dataset]


def record(report: Report, version: str, dataset: str, path: Path = HISTORY) -> list[dict]:
    rows = json.loads(path.read_text(encoding="utf-8")) if path.exists() else []
    rows = [r for r in rows if not (r["version"] == version and r.get("dataset") == dataset)]
    m = report.overall
    rows.append({"version": version, "date": datetime.now(timezone.utc).date().isoformat(), "dataset": dataset,
                 "recall": m.recall, "precision": m.precision, "fpr": m.fpr, "n": m.n,
                 "p95_latency_ms": round(report.latency(0.95), 3)})
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    return [r for r in rows if r.get("dataset") == dataset]


_HTML_CSS = """
:root{--bg:#f4f4f1;--card:#fcfcfb;--t1:#0b0b0b;--t2:#52514e;--t3:#6f6e69;--grid:#e1e0d9;
--border:rgba(11,11,11,.10);--crit:#d03b3b;--good:#0ca30c}
@media (prefers-color-scheme:dark){:root{--bg:#121211;--card:#1a1a19;--t1:#fff;--t2:#c3c2b7;
--t3:#9a998f;--grid:#2c2c2a;--border:rgba(255,255,255,.10)}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t1);
font:14px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:1040px;margin:0 auto;padding:32px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:36px 0 12px}
.sub{color:var(--t2);margin:0 0 24px}
.tiles{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:16px;min-width:0}
.k{font-size:12px;color:var(--t2)}.v{font-size:28px;font-weight:650;font-variant-numeric:tabular-nums}
.n{font-size:12px;color:var(--t3)}
.charts{display:grid;grid-template-columns:minmax(0,1fr);gap:16px;max-width:780px}
.charts svg{display:block;border:1px solid var(--border);border-radius:10px}
.card{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px;font-variant-numeric:tabular-nums}
th{text-align:left;color:var(--t2);font-weight:600;font-size:12px;padding:6px 8px;border-bottom:1px solid var(--grid)}
td{padding:7px 8px;border-bottom:1px solid var(--grid);vertical-align:top}
.tag{font-size:11px;color:var(--t2);border:1px solid var(--border);border-radius:4px;padding:1px 6px;white-space:nowrap}
.errs td:last-child{word-break:break-word}
footer{margin-top:40px;color:var(--t3);font-size:12px}
@media (max-width:760px){.tiles{grid-template-columns:repeat(2,minmax(0,1fr))}}
"""


def to_html(reports: list[Report], dataset: str, history: list[dict] | None = None) -> str:
    base = reports[0]
    m = base.overall
    svgs = build_charts(base, history)

    def tile(k: str, v: str, n: str) -> str:
        return f'<div class="card"><div class="k">{k}</div><div class="v">{v}</div><div class="n">{n}</div></div>'

    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        f"<title>Backtest Report</title><style>{_HTML_CSS}</style></head><body><main>",
        "<h1>Backtest report: LLM Security Gateway</h1>",
        (f"<p class='sub'>{escape(dataset)} · {m.n} messages ({m.tp + m.fn} attacks, {m.fp + m.tn} harmless) · "
        f"generated {datetime.now(timezone.utc).date().isoformat()}</p>"),
        "<section class='tiles'>",
        tile("Attacks caught (recall)", _pct(m.recall), f"{m.tp} of {m.tp + m.fn} blocked"),
        tile("Harmless blocked (FPR)", _pct(m.fpr), f"{m.fp} of {m.fp + m.tn} messages"),
        tile("Precision", _pct(m.precision), "share of blocks that were real attacks"),
        tile("p95 latency", f"{base.latency(0.95):.2f} ms", "per message, detection only"),
        "</section>",
    ]
    if len(reports) > 1:
        parts.append("<h2>What-if comparison</h2><div class='card'><table><tr><th>Config</th><th>Recall</th>"
                     "<th>FPR</th><th>Precision</th><th>p95 ms</th></tr>")
        for r in reports:
            o = r.overall
            parts.append(f"<tr><td>{escape(r.name)}</td><td>{_pct(o.recall)}</td><td>{_pct(o.fpr)}</td>"
                         f"<td>{_pct(o.precision)}</td><td>{r.latency(0.95):.2f}</td></tr>")
        parts.append("</table></div>")
    if "progress.svg" in svgs:
        parts += ["<h2>Progress across releases</h2><div class='charts'>", svgs["progress.svg"], "</div>"]
    parts += ["<h2>Where it fails</h2><div class='charts'>", svgs["family_recall.svg"],
              svgs["by_language.svg"], svgs["by_source.svg"], "</div>",
              "<h2>Threshold trade-offs</h2><div class='charts'>"]
    parts += [v for k, v in svgs.items() if k.startswith("threshold_")]
    parts.append("</div>")

    missed = sorted((o for o in base.outcomes if o.sample.label == 1 and not o.predicted), key=lambda o: o.score)
    wrong = sorted((o for o in base.outcomes if o.sample.label == 0 and o.predicted), key=lambda o: -o.score)
    for title, rows in ((f"Missed attacks ({len(missed)})", missed), (f"Harmless messages blocked ({len(wrong)})", wrong)):
        parts.append(f"<h2>{title}</h2><div class='card'><table class='errs'><tr><th>Source</th><th>Lang</th>"
                     "<th>Family</th><th>Score</th><th>Message</th></tr>")
        for o in rows:
            parts.append(f"<tr><td>{o.sample.source.value}</td><td>{escape(o.sample.lang)}</td>"
                         f"<td><span class='tag'>{escape(o.sample.family)}</span></td><td>{o.score:.2f}</td>"
                         f"<td>{escape(o.sample.text)}</td></tr>")
        if not rows:
            parts.append("<tr><td colspan='5'>None</td></tr>")
        parts.append("</table></div>")
    parts.append("<footer>Blocked = caught. Flagged messages are logged for review but count as not caught. "
                 "Hover over any bar or point for its exact value.</footer></main></body></html>")
    return "".join(parts)


def _parse_overrides(items: list[str]) -> dict[Source, Thresholds]:
    thresholds = dict(DEFAULT_THRESHOLDS)
    for item in items:
        name, _, value = item.partition("=")
        src = Source(name.strip())
        block = float(value)
        thresholds[src] = Thresholds(flag=min(thresholds[src].flag, block), block=block)
    return thresholds


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Replay labelled traffic through the gateway.")
    ap.add_argument("traffic", help="JSONL file of labelled messages")
    ap.add_argument("--block", action="append", default=[], metavar="SOURCE=T",
                    help="compare against a different block threshold, e.g. --block retrieved=0.35")
    ap.add_argument("--out", help="write the markdown report to this file")
    ap.add_argument("--json", dest="json_out", help="write metrics as JSON (for CI or plotting)")
    ap.add_argument("--html", help="write a self-contained visual report (open it in a browser)")
    ap.add_argument("--charts", help="directory to write SVG charts into (e.g. docs/img)")
    ap.add_argument("--record", metavar="VERSION", help="save this run to the release history, e.g. v0.1")
    ap.add_argument("--quiet", action="store_true", help="don't print the markdown report")
    ap.add_argument("--classifier", action="store_true",
                    help="add the fine-tuned classifier as a second layer (needs: pip install -e \".[ml]\")")
    args = ap.parse_args(argv)
    dataset = Path(args.traffic).name

    samples = load(args.traffic)
    detectors = build_detectors(True if args.classifier else None)
    reports = [run(samples, Policy(detectors), "current")]
    if args.block:
        alt = Policy(detectors, thresholds=_parse_overrides(args.block))
        reports.append(run(samples, alt, "override: " + ", ".join(args.block)))

    history = record(reports[0], args.record, dataset) if args.record else load_history(dataset=dataset)

    md = to_markdown(reports)
    if args.out:
        Path(args.out).write_text(md, encoding="utf-8")
        print(f"report written to {args.out}", file=sys.stderr)
    elif not args.quiet:
        print(md)
    if args.html:
        Path(args.html).parent.mkdir(parents=True, exist_ok=True)
        Path(args.html).write_text(to_html(reports, dataset, history), encoding="utf-8")
        print(f"visual report written to {args.html}", file=sys.stderr)
    if args.charts:
        outdir = Path(args.charts)
        outdir.mkdir(parents=True, exist_ok=True)
        for name, svg in build_charts(reports[0], history).items():
            (outdir / name).write_text(svg, encoding="utf-8")
        print(f"charts written to {outdir}/", file=sys.stderr)
    if args.json_out:
        data = {r.name: {"overall": r.overall.as_dict(),
                         "p95_latency_ms": r.latency(0.95),
                         "by": {k: {g: m.as_dict() for g, m in v.items()} for k, v in r.by.items()}}
                for r in reports}
        Path(args.json_out).write_text(json.dumps(data, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
