import importlib

PACKAGES = ["gate", "evidence", "bank", "zk", "swarm", "mandate", "e2e", "bench"]


def test_all_packages_import():
    for name in PACKAGES:
        assert importlib.import_module(name) is not None
