# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""The real `bitcoind` is started again where its rpc port is taken.

`tests/electrs_stack_test.py` drives the same start with a stand-in node;
this is the program itself, so that what it logs and where it binds is
read from `bitcoind` and not from the stand-in.
"""

from __future__ import annotations

import socket
from contextlib import closing

import pytest

from tests.integration import conftest as stack_module
from tests.integration.conftest import _start_node, _stop, start_on_free_ports


def test_bitcoind_is_started_again_where_its_rpc_port_is_taken(
    bitcoind_path: str,
    tmp_path_factory: pytest.TempPathFactory,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The first rpc port is held on `127.0.0.1`; the second try is up."""
    datadir = tmp_path_factory.mktemp("held-port-node")
    real = stack_module._free_port
    with closing(socket.socket()) as holder:
        holder.bind(("127.0.0.1", 0))
        held = int(holder.getsockname()[1])
        ports = iter([held])
        monkeypatch.setattr(
            stack_module, "_free_port", lambda: next(ports, None) or real()
        )
        process, client, port = start_on_free_ports(
            lambda: _start_node([bitcoind_path], datadir, None)
        )
    try:
        assert port != held
        assert client.call("getblockcount") == 0
    finally:
        _stop(process)
