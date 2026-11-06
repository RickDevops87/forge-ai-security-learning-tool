from src.sandbox.canaries import CanaryDetector


def test_canary_detection():
    detector = CanaryDetector()
    result = detector.scan("This contains THIS_IS_A_CANARY_STRING in the text")
    assert result["triggered"] is True
    assert "THIS_IS_A_CANARY_STRING" in result["canaries_found"]


def test_no_canary():
    detector = CanaryDetector()
    result = detector.scan("This is normal text")
    assert result["triggered"] is False
    assert result["canaries_found"] == []


def test_multiple_canaries():
    detector = CanaryDetector()
    result = detector.scan("CANARY_KEY_DO_NOT_USE and THIS_IS_A_TEST_SECRET")
    assert result["triggered"] is True
    assert result["count"] == 2


def test_canary_reset():
    detector = CanaryDetector()
    detector.scan("THIS_IS_A_CANARY_STRING")
    assert len(detector.get_triggered()) == 1
    detector.reset()
    assert len(detector.get_triggered()) == 0
