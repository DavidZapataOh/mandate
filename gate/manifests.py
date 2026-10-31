"""Least-privilege manifest generator from observed server surfaces."""

from dataclasses import dataclass

from gate.mcp_proxy import Manifest, ToolGrant


@dataclass(frozen=True)
class ToolDescriptor:
    """Observed tool with the scopes it needs."""

    tool: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class ServerDescriptor:
    """Observed server surface to least-privilege."""

    server: str
    tools: tuple[ToolDescriptor, ...]


def generate(descriptor: ServerDescriptor) -> Manifest:
    """Least-privilege manifest: exactly the described grants."""
    grants = tuple(
        ToolGrant(tool=t.tool, scopes=tuple(sorted(set(t.scopes))))
        for t in sorted(descriptor.tools, key=lambda t: t.tool)
    )
    return Manifest(v=1, server=descriptor.server, grants=grants)
