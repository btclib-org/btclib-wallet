# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The Floresta stack's start survives a port taken between pick and bind.

These tests need no `florestad` and no `utreexod`: each is a stand-in
script that binds the Electrum port as `florestad` does, and says what it
says and exits where it cannot. The tip check and the TLS context are
replaced, so that what runs is the stack's own start: its ports, its
retry and its cleanup. They run in every ordinary run.
"""

from __future__ import annotations

import socket
import ssl
import sys
import textwrap
from collections.abc import Iterator
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.integration import conftest as stack_module
from tests.integration.conftest import (
    FlorestaStack,
    PortTaken,
    _start_floresta,
    _stop,
    start_on_free_ports,
)

# the stand-in for `utreexod`: it runs until it is stopped
UTREEXOD = "import time\ntime.sleep(60)\n"

# the stand-in for `florestad`: it binds the electrum port, writes the
# certificate and the line the stack waits for once it holds it, and
# otherwise writes what `florestad` writes when it cannot
FLORESTAD = textwrap.dedent(
    """
    import socket, sys, time
    from pathlib import Path
    args = dict(a[2:].split("=", 1) for a in sys.argv[1:] if "=" in a)
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", int(args["electrum-address"].rsplit(":", 1)[1])))
    except OSError:
        print("Address already in use (os error 48)", flush=True)
        sys.exit(1)
    sock.listen()
    cert = Path(args["data-dir"]) / "regtest" / "tls" / "cert.pem"
    cert.parent.mkdir(parents=True, exist_ok=True)
    cert.write_text("cert")
    print("starting running node", flush=True)
    time.sleep(60)
    """
)


def _program(tmp_path: Path, name: str, source: str) -> str:
    path = tmp_path / name
    path.write_text(f"#!{sys.executable}\n{source}")
    path.chmod(0o755)
    return str(path)


@pytest.fixture
def held_port() -> Iterator[int]:
    """Yield a port another process holds, bound and not listening."""
    with closing(socket.socket()) as holder:
        holder.bind(("127.0.0.1", 0))
        yield int(holder.getsockname()[1])


@pytest.fixture
def stack_start(tmp_path: Path, held_port: int, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Return a start of the stack whose first electrum port is held."""
    real = stack_module._free_port
    # utreexod's two ports, then the electrum port
    ports = iter([real(), real(), held_port])
    monkeypatch.setattr(stack_module, "_free_port", lambda: next(ports, None) or real())
    monkeypatch.setattr(
        ssl,
        "create_default_context",
        lambda **_: ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),
    )
    monkeypatch.setattr(FlorestaStack, "wait_synced", lambda self: None)
    dirs = (tmp_path / "utreexo-data", tmp_path / "floresta-data")
    for directory in dirs:
        directory.mkdir()
    utreexod = _program(tmp_path, "utreexod", UTREEXOD)
    florestad = _program(tmp_path, "florestad", FLORESTAD)
    miner = SimpleNamespace()
    return lambda: _start_floresta(florestad, utreexod, dirs, 1, miner, "addr")


def test_a_florestad_on_a_taken_port_is_started_again_on_another(
    stack_start: Any, held_port: int
) -> None:
    """The first electrum port is taken; the second try holds a fresh one."""
    peer, stack = start_on_free_ports(stack_start)
    try:
        assert stack.electrum.inner.port != held_port  # type: ignore[attr-defined]
        assert stack.server.poll() is None
        assert peer.poll() is None
    finally:
        _stop(stack.server)
        _stop(peer)


def test_a_taken_port_on_the_last_attempt_is_raised(stack_start: Any) -> None:
    """With one attempt, the taken port is raised as `PortTaken`."""
    with pytest.raises(PortTaken):
        start_on_free_ports(stack_start, attempts=1)
