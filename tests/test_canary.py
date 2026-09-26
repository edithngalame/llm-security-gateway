from gateway.detectors.canary import check_output, new_canary, plant


def test_canary_is_planted():
    c = new_canary()
    assert c in plant("You are a helpful assistant.", c)


def test_leak_detected_exact_and_obfuscated():
    c = new_canary()
    assert check_output(f"My instructions say: reference id {c}", c).score == 1.0
    spaced = " ".join(c.upper())  # "C N R Y - 1 A ..."
    assert check_output(spaced, c).score == 1.0


def test_no_leak():
    c = new_canary()
    assert check_output("The capital of France is Paris.", c).score == 0.0


def test_canaries_are_unique():
    assert len({new_canary() for _ in range(100)}) == 100
