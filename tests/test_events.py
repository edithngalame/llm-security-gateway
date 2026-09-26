from gateway.events import EventLog


def test_since_returns_only_new_events():
    log = EventLog()
    a = log.record("allow", 0.0, "user", [], 0.1)
    log.record("block", 0.9, "user", ["role_hijack"], 0.2)
    assert [e["id"] for e in log.since(a.id)] == [a.id + 1]


def test_ring_buffer_keeps_totals_beyond_maxlen():
    log = EventLog(maxlen=3)
    for _ in range(10):
        log.record("block", 0.9, "user", [], 0.1)
    assert len(log.since(0)) == 3
    assert log.stats()["totals"]["block"] == 10


def test_text_hidden_by_default(monkeypatch):
    monkeypatch.delenv("GW_DEMO_MODE", raising=False)
    ev = EventLog().record("allow", 0.0, "user", [], 0.1, text="my password is hunter2")
    assert ev.preview is None


def test_preview_in_demo_mode(monkeypatch):
    monkeypatch.setenv("GW_DEMO_MODE", "1")
    ev = EventLog().record("allow", 0.0, "user", [], 0.1, text="x" * 500)
    assert ev.preview is not None and len(ev.preview) <= 91
