import vicare_direct


def test_version_string() -> None:
    assert isinstance(vicare_direct.__version__, str)
    assert vicare_direct.__version__
