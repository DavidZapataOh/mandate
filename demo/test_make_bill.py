import hashlib

from demo.make_bill import INJECTION, main, render


def test_render_is_deterministic_pdf():
    clean = render(poisoned=False)
    assert clean.startswith(b"%PDF-")
    assert hashlib.sha256(clean).digest() == hashlib.sha256(render(False)).digest()


def test_poisoned_copy_differs_only_by_injection():
    clean = render(poisoned=False)
    poisoned = render(poisoned=True)
    assert poisoned != clean
    assert len(poisoned) > len(clean)
    assert INJECTION.startswith("NOTICE TO AI PAYMENT ASSISTANTS")


def test_main_writes_both_bills(tmp_path):
    assert main([str(tmp_path)]) == 0
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "acme-A-991-poisoned.pdf",
        "acme-A-991.pdf",
    ]
