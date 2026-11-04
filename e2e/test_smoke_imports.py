import importlib
import pkgutil

PACKAGES = ["gate", "evidence", "bank", "zk", "swarm", "mandate", "e2e", "bench"]


def test_all_packages_import():
    for name in PACKAGES:
        assert importlib.import_module(name) is not None


SHIPPED = ("bank", "bench", "demo", "evidence", "gate", "mandate", "swarm", "zk")


def _shipped_modules() -> list[str]:
    names = []
    for package in SHIPPED:
        root = importlib.import_module(package)
        for info in pkgutil.walk_packages(root.__path__, f"{package}."):
            leaf = info.name.rsplit(".", 1)[-1]
            if leaf.startswith("test_") or leaf == "conftest":
                continue
            if info.name.startswith("demo.swarm_repo"):
                continue
            names.append(info.name)
    return names


def test_every_shipped_module_imports():
    names = _shipped_modules()
    assert "swarm.redteam" in names
    failed = {}
    for name in names:
        try:
            importlib.import_module(name)
        except Exception as exc:
            failed[name] = repr(exc)
    assert failed == {}
