import json
import xml.etree.ElementTree as ET
from pathlib import Path

from gateway import charts
from gateway.backtest import build_charts, load, load_history, main, record, run, to_html
from gateway.detectors import RuleDetector
from gateway.policy import Policy

DEMO = Path(__file__).resolve().parent.parent / "data" / "samples" / "demo_traffic.jsonl"


def _report():
    return run(load(DEMO), Policy([RuleDetector()]))


def test_every_chart_is_valid_svg():
    for name, svg in build_charts(_report()).items():
        root = ET.fromstring(svg)  # raises if malformed
        assert root.tag.endswith("svg"), name
        assert "prefers-color-scheme:dark" in svg, name  # dark mode support


def test_chart_escapes_labels():
    svg = charts.family_recall([("<script>", 0.5, 2)], "sub")
    assert "<script>" not in svg
    ET.fromstring(svg)


def test_html_report_sections_and_escaping():
    html = to_html([_report()], "demo")
    for section in ("Attacks caught (recall)", "Where it fails", "Threshold trade-offs", "Missed attacks"):
        assert section in html
    assert "<svg" in html


def test_history_only_compares_same_dataset(tmp_path):
    hist = tmp_path / "history.json"
    r = _report()
    record(r, "v0.1", "demo", hist)
    record(r, "v0.1", "demo", hist)          # re-recording replaces, not duplicates
    record(r, "v0.3", "other_set", hist)
    assert [h["version"] for h in load_history(hist, dataset="demo")] == ["v0.1"]
    assert len(json.loads(hist.read_text())) == 2


def test_cli_writes_html_and_charts(tmp_path):
    html, img = tmp_path / "r" / "index.html", tmp_path / "img"
    assert main([str(DEMO), "--quiet", "--html", str(html), "--charts", str(img)]) == 0
    assert html.exists() and (img / "family_recall.svg").exists()
