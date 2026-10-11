import vicare_local_ble


def test_version_string() -> None:
    assert isinstance(vicare_local_ble.__version__, str)
    assert vicare_local_ble.__version__
