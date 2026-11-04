import os

import pytest

from swarm.console_line import console_line_json, read_console_line
from swarm.live_attack import live_attacker
from swarm.redteam import AttackKind
from swarm.test_console_attacks import _world


@pytest.mark.live
def test_console_asks_the_open_weights_attacker():
    if not os.environ.get("BASETEN_API_KEY"):
        pytest.skip("live: set BASETEN_API_KEY")
    _, hub, runner = _world()
    live = live_attacker(runner, dict(os.environ), enabled=True)
    line = live.ask(AttackKind.MCP_EXFIL)
    assert line == hub.get(1)
    assert read_console_line(console_line_json(line)) == line
    assert (line.subject["origin"], line.meta["provider"]) == ("model", "baseten")
    assert "muse-spark-open" in line.meta["model"]
    assert (line.subject["layer"], line.subject["blocked"]) == ("mcp", True)
    assert line.subject["moved_cents"] == 0
