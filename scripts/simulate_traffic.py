"""Stream labelled traffic at a running gateway so the dashboard shows it live.

Uses only the standard library, so it runs anywhere Python does.

    python scripts/simulate_traffic.py                      # 2 messages/second, forever
    python scripts/simulate_traffic.py --rate 5 --count 100
    python scripts/simulate_traffic.py --url http://my-server:8000

At the end (or on Ctrl+C) it prints a live scorecard: how the gateway did on the
messages it just saw, using their labels. That's a mini real-time backtest.
"""

from __future__ import annotations

import argparse
import json
import random
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_TRAFFIC = Path(__file__).resolve().parent.parent / "data" / "samples" / "demo_traffic.jsonl"


def load(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.lstrip().startswith("//"):
            rows.append(json.loads(line))
    return rows


def scan(url: str, text: str, source: str) -> dict:
    req = urllib.request.Request(
        f"{url}/v1/scan",
        data=json.dumps({"text": text, "source": source}).encode(),
        headers={"content-type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--url", default="http://localhost:8000")
    ap.add_argument("--traffic", type=Path, default=DEFAULT_TRAFFIC)
    ap.add_argument("--rate", type=float, default=2.0, help="messages per second")
    ap.add_argument("--count", type=int, default=0, help="stop after N messages (0 = run until Ctrl+C)")
    ap.add_argument("--seed", type=int, default=None)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    rows = load(args.traffic)
    tally = {"caught": 0, "missed": 0, "false_block": 0, "ok_benign": 0}
    sent = 0
    print(f"Sending to {args.url} at {args.rate}/s. Open {args.url}/dashboard. Ctrl+C to stop.\n")

    try:
        while not args.count or sent < args.count:
            row = rng.choice(rows)
            try:
                result = scan(args.url, row["text"], row.get("source", "user"))
            except urllib.error.URLError as e:
                print(f"Can't reach the gateway at {args.url} ({e.reason}). Is uvicorn running?")
                return 1
            except TimeoutError:
                print("  (slow answer from the gateway, skipped this message)")
                continue
            blocked = result["action"] == "block"
            if row["label"] == 1:
                key, mark = ("caught", "✓ caught ") if blocked else ("missed", "✗ MISSED ")
            else:
                key, mark = ("false_block", "✗ FALSE BLOCK") if blocked else ("ok_benign", "✓ allowed")
            tally[key] += 1
            sent += 1
            print(f"{mark:<14} {result['action']:<5} {result['score']:.2f}  "
                  f"[{row.get('source', 'user')}/{row.get('lang', '?')}]  {row['text'][:60]}")
            time.sleep(1 / args.rate)
    except KeyboardInterrupt:
        pass

    attacks = tally["caught"] + tally["missed"]
    benign = tally["false_block"] + tally["ok_benign"]
    print("\n--- live scorecard ---")
    print(f"messages: {sent}")
    if attacks:
        print(f"attacks caught: {tally['caught']}/{attacks} ({100 * tally['caught'] / attacks:.0f}%)")
    if benign:
        print(f"benign wrongly blocked: {tally['false_block']}/{benign} ({100 * tally['false_block'] / benign:.0f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
