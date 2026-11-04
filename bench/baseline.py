"""Same-host regression check against a published report."""

from typing import Any

from bench.runner import BenchResult, BudgetBreach

FACTOR = 2.0


def _minor(version: str) -> str:
    return ".".join(version.split(".")[:2])


def same_host(published: dict[str, str], here: dict[str, str]) -> bool:
    """True when both ran on the same CPU, core count and Python minor."""
    return (
        published.get("cpu") == here.get("cpu")
        and published.get("cores") == here.get("cores")
        and _minor(published.get("python", "")) == _minor(here.get("python", ""))
    )


def against(
    results: list[BenchResult], published: dict[str, Any], factor: float = FACTOR
) -> list[BudgetBreach]:
    """Breach every p50 strictly over ``factor`` x the published p50 of its path.

    Paths the published report does not list pass.
    """
    before = {m["result"]["name"]: m["result"]["p50_us"] for m in published["measured"]}
    breaches: list[BudgetBreach] = []
    for r in results:
        p50 = before.get(r.name)
        if p50 is not None and r.p50_us > factor * p50:
            breaches.append(
                BudgetBreach(
                    r.name,
                    "p50_us",
                    r.p50_us,
                    p50,
                    f"{r.name}.p50_us: actual {r.p50_us:g} is over {factor:g}x "
                    f"the published {p50:g}",
                )
            )
    return breaches
