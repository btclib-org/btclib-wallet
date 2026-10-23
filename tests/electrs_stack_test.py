# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The stack's starts survive a port taken between pick and bind.

`_free_port` closes the port it picked, so a process that binds it first
makes `electrs` exit with `AddrInUse`, and `bitcoind` exit with
`Unable to bind any endpoint for RPC server` in its `debug.log`. These
tests need no `bitcoind` and no `electrs`: each is a stand-in script that
binds its port as the program does, and says what the program says and
exits where it cannot. They run in every ordinary run.
"""

from __future__ import annotations

import socket
import subprocess
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
    PlainLineTransport,
    PortTaken,
    Stack,
    _start,
    _start_node,
    _start_server,
    _stop,
    port_was_taken,
    start_on_free_ports,
)

# the stand-in for `electrs`: it binds the electrum port, writes `ready`
# once it holds it, and otherwise writes what `electrs` writes when it
# cannot
SERVER = textwrap.dedent(
    """
    import socket, sys, time
    port = int(next(a for a in sys.argv if a.startswith("--electrum-rpc-addr="))
               .rsplit(":", 1)[1])
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", port))
    except OSError:
        print("cannot bind: Os { code: 98, kind: AddrInUse }", flush=True)
        sys.exit(101)
    sock.listen()
    print("ready", flush=True)
    time.sleep(60)
    """
)


# the stand-in for `bitcoind`: it binds the `-rpcport` port and, given one,
# the `-port` port, and otherwise writes to `regtest/debug.log`, under
# `-datadir`, what `bitcoind` writes
NODE = textwrap.dedent(
    """
    import socket, sys, time
    from pathlib import Path
    args = dict(a[1:].split("=", 1) for a in sys.argv[1:] if "=" in a)
    sock = socket.socket()
    try:
        sock.bind(("127.0.0.1", int(args["rpcport"])))
    except OSError:
        log = Path(args["datadir"]) / "regtest" / "debug.log"
        log.parent.mkdir(exist_ok=True)
        with log.open("a") as f:
            f.write("Unable to bind any endpoint for RPC server\\n")
        sys.exit(1)
    sock.listen()
    if "port" in args:
        p2p = socket.socket()
        try:
            p2p.bind(("127.0.0.1", int(args["port"])))
        except OSError:
            log = Path(args["datadir"]) / "regtest" / "debug.log"
            log.parent.mkdir(exist_ok=True)
            with log.open("a") as f:
                f.write(
                    "[error] Unable to bind to 127.0.0.1:%s on this computer. "
                    "Bitcoin Core is probably already running.\\n" % args["port"]
                )
            sys.exit(1)
        p2p.listen()
    time.sleep(60)
    """
)


@pytest.fixture
def server_script(tmp_path: Path) -> Path:
    """Return the stand-in server, as a file."""
    path = tmp_path / "server.py"
    path.write_text(SERVER)
    return path


@pytest.fixture
def synced_when_ready(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make the tip checks answer the node's tip once `ready` is logged."""

    def tip_hash(self: Stack) -> str:
        if "ready" not in self.server_log.read_text():
            raise OSError("not listening")
        return "ab"

    monkeypatch.setattr(Stack, "_tip_hash", tip_hash)
    monkeypatch.setattr(Stack, "_electrum_tip", lambda self: (1, "ab"))


def _node() -> Any:
    return SimpleNamespace(
        call=lambda method, *_: {"getbestblockhash": "ab", "getblockcount": 1}[method]
    )


@pytest.fixture
def held_port() -> Iterator[int]:
    """Yield a port another process holds, bound and not listening."""
    with closing(socket.socket()) as holder:
        holder.bind(("127.0.0.1", 0))
        yield int(holder.getsockname()[1])


def _first_port_is(monkeypatch: pytest.MonkeyPatch, port: int) -> None:
    real = stack_module._free_port
    ports = iter([port])
    monkeypatch.setattr(stack_module, "_free_port", lambda: next(ports, None) or real())


def _run(tmp_path: Path, server_script: Path, attempts: int = 5) -> Stack:
    return start_on_free_ports(
        lambda: _start_server(
            [sys.executable, str(server_script)],
            tmp_path,
            tmp_path,
            1,
            _node(),
            "addr",
        ),
        attempts,
    )


def test_a_server_on_a_taken_port_is_started_again_on_another(
    tmp_path: Path,
    server_script: Path,
    held_port: int,
    synced_when_ready: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first electrum port is taken; the second try holds a fresh one."""
    _first_port_is(monkeypatch, held_port)
    stack = _run(tmp_path, server_script)
    try:
        assert stack.electrum.port != held_port
        assert stack.server.poll() is None
    finally:
        _stop(stack.server)


def test_a_taken_port_on_the_last_attempt_is_raised(
    tmp_path: Path,
    server_script: Path,
    held_port: int,
    synced_when_ready: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With one attempt, the taken port is raised as `PortTaken`."""
    _first_port_is(monkeypatch, held_port)
    with pytest.raises(PortTaken, match="AddrInUse"):
        _run(tmp_path, server_script, attempts=1)


def test_a_server_that_exits_for_another_reason_fails_the_run(
    tmp_path: Path,
) -> None:
    """An exit that does not name a taken port is not retried."""
    log = tmp_path / "log"
    log.write_text("panic: something else\n")
    server = _start([sys.executable, "-c", "pass"], tmp_path / "out")
    server.wait()
    stack = Stack(
        _node(),
        "addr",
        PlainLineTransport("127.0.0.1", 1),
        "http://127.0.0.1:1",
        server,
        log,
    )
    with pytest.raises(pytest.fail.Exception, match="something else"):
        stack.wait_synced()


def test_start_on_free_ports_calls_start_again_after_each_taken_port() -> None:
    """Two takes then a success is three calls and the success returned."""
    calls = []

    def start() -> str:
        calls.append(1)
        if len(calls) < 3:
            raise PortTaken
        return "up"

    assert start_on_free_ports(start) == "up"
    assert len(calls) == 3


def test_start_on_free_ports_gives_up_after_its_attempts() -> None:
    """Every call taken: `attempts` calls, then the last `PortTaken`."""
    calls = []

    def start() -> str:
        calls.append(1)
        raise PortTaken

    with pytest.raises(PortTaken):
        start_on_free_ports(start, attempts=4)
    assert len(calls) == 4


@pytest.mark.parametrize(
    "log, taken",
    [
        ("cannot bind: Os { code: 98, kind: AddrInUse }", True),
        ("error: Address already in use (os error 48)", True),
        ("panicked: failed to start monitoring HTTP server at 127.0.0.1:1", True),
        ("listen tcp 127.0.0.1:1: bind: address already in use", True),
        ("panic: something else", False),
    ],
)
def test_port_was_taken_reads_the_servers_complaint(log: str, taken: bool) -> None:
    """Each wording the server uses for a taken port is read as one."""
    assert port_was_taken(log) is taken


def test_a_server_that_does_not_sync_is_stopped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A server that never logs `ready` has exited after the failure."""
    silent = tmp_path / "silent.py"
    silent.write_text("import time\ntime.sleep(60)\n")
    started = []

    def record(command: list[str], log: Path) -> subprocess.Popen[bytes]:
        process = _start(command, log)
        started.append(process)
        return process

    monkeypatch.setattr(stack_module, "_start", record)
    monkeypatch.setattr(stack_module, "_SYNC_TIMEOUT", 0.5)
    monkeypatch.setattr(Stack, "_tip_hash", _not_listening)
    with pytest.raises(pytest.fail.Exception, match="did not reach"):
        _start_server(
            [sys.executable, str(silent)], tmp_path, tmp_path, 1, _node(), "addr"
        )
    (process,) = started
    assert process.poll() is not None


def _not_listening(self: Stack) -> str:
    raise OSError("not listening")


class _ListeningClient:
    """Stand in for the rpc client: it answers where the port is listening."""

    def __init__(self, url: str, cookie_path: Path) -> None:
        self.port = int(url.rsplit(":", 1)[1])

    def call(self, method: str) -> None:
        socket.create_connection(("127.0.0.1", self.port), timeout=1).close()


@pytest.fixture
def node_script(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Return the command of the stand-in node, and swap in its client."""
    path = tmp_path / "bitcoind.py"
    path.write_text(NODE)
    monkeypatch.setattr(stack_module, "BitcoinCoreRpcClient", _ListeningClient)
    return [sys.executable, str(path)]


def test_a_node_on_a_taken_port_is_started_again_on_another(
    tmp_path: Path,
    node_script: list[str],
    held_port: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first rpc port is taken; the second try holds a fresh one."""
    _first_port_is(monkeypatch, held_port)
    process, _, port = start_on_free_ports(
        lambda: _start_node(node_script, tmp_path, None)
    )
    try:
        assert port != held_port
        assert process.poll() is None
    finally:
        _stop(process)


def test_a_taken_rpc_port_on_the_last_attempt_is_raised(
    tmp_path: Path,
    node_script: list[str],
    held_port: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With one attempt, the taken port is raised as `PortTaken`."""
    _first_port_is(monkeypatch, held_port)
    with pytest.raises(PortTaken, match="Unable to bind any endpoint"):
        start_on_free_ports(
            lambda: _start_node(node_script, tmp_path, None), attempts=1
        )


def test_a_node_on_a_taken_p2p_port_is_started_again_on_another(
    tmp_path: Path, node_script: list[str], held_port: int
) -> None:
    """The first p2p port is taken; the second try holds a fresh one."""
    ports = iter([held_port])

    def start() -> tuple[Any, Any, int]:
        p2p_port = next(ports, None) or stack_module._free_port()
        process, client, _ = _start_node(node_script, tmp_path, p2p_port)
        return process, client, p2p_port

    process, _, p2p_port = start_on_free_ports(start)
    try:
        assert p2p_port != held_port
        assert process.poll() is None
    finally:
        _stop(process)


def test_a_taken_p2p_port_on_the_last_attempt_is_raised(
    tmp_path: Path, node_script: list[str], held_port: int
) -> None:
    """With one attempt, the taken p2p port is raised as `PortTaken`."""
    with pytest.raises(PortTaken, match="Unable to bind to"):
        start_on_free_ports(
            lambda: _start_node(node_script, tmp_path, held_port), attempts=1
        )


def test_a_node_that_exits_for_another_reason_fails_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An exit that does not name a taken port is not retried."""
    monkeypatch.setattr(stack_module, "BitcoinCoreRpcClient", _ListeningClient)
    with pytest.raises(pytest.fail.Exception, match="bitcoind exited with 0"):
        _start_node([sys.executable, "-c", "pass"], tmp_path, None)


def test_a_complaint_of_an_earlier_try_is_not_read_as_the_next_ones(
    tmp_path: Path,
    node_script: list[str],
    held_port: int,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A try that exits quietly after one on a taken port is no `PortTaken`."""
    _first_port_is(monkeypatch, held_port)
    with pytest.raises(PortTaken):
        _start_node(node_script, tmp_path, None)
    with pytest.raises(pytest.fail.Exception, match="bitcoind exited with 0"):
        _start_node([sys.executable, "-c", "pass"], tmp_path, None)
