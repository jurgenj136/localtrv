import localtrv


def test_version_string() -> None:
    assert isinstance(localtrv.__version__, str)
    assert localtrv.__version__
