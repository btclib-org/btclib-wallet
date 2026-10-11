# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

"""What the integration tests need, and what makes them skip.

Two switches for the node's tests, and both have to be on.
`BTCLIB_INTEGRATION` in the environment is the opt-in: these tests
start programs, listen on a socket and write to disk, which is not what
`uv run pytest` should do to somebody who asked for the unit suite.
The second is the program itself -- `bitcoind` here -- because an
opt-in that fails for a missing binary would report a defect that is not
one.

So the ordinary run reports them skipped and says which switch was off,
and the whole flow is one command:

    BTCLIB_INTEGRATION=1 uv run pytest tests/integration

The node is this session's own: a regtest data directory under pytest's
tmp_path, an ephemeral rpc port, and a cookie file for the
credentials. It never touches a node the maintainer is running, which is
the reason none of the defaults -- port 18443, ~/.bitcoin -- is used.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import ssl
import subprocess
import time
import urllib.request
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from socket import create_connection
from typing import Any, TypeVar

import pytest
from bitcoin_core_rpc import BitcoinCoreRpcClient, FetchError
from btclib import electrum
from btclib.amount import sats_from_btc
from btclib.block.block_header import BlockHeader
from btclib.tx import OutPoint, Tx, TxIn, TxOut

from btclib_wallet.descriptors import Descriptor, add_checksum, parse
from btclib_wallet.fetch.bitcoin_core import BitcoinCoreFetcher
from btclib_wallet.fetch.electrum import ElectrumFetcher
from btclib_wallet.fetch.esplora import EsploraFetcher
from btclib_wallet.fetch.fetcher import NetworkVerifyingFetcher
from btclib_wallet.fetch.transport import LineTransport, TlsLineTransport
from btclib_wallet.psbt.psbt import Psbt, extract_tx, finalize

# how long the node is given to answer its first rpc call: a regtest
# bitcoind is up in well under a second on any machine that can run this
# suite, and the wait is a poll rather than a sleep, so this bounds only
# the failure case
_STARTUP_TIMEOUT = 30.0

_T = TypeVar("_T")


def _free_port() -> int:
    """Return a port nothing is listening on, by letting the OS pick one.

    Bound and closed rather than guessed: a fixed port is what makes two
    runs of a test suite fight each other, and the maintainer's own
    regtest node is exactly the kind of thing already on 18443.
    """
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


@pytest.fixture(scope="session")
def bitcoind_path() -> str:
    """Return the bitcoind to run, skipping the whole module without one."""
    if not os.environ.get("BTCLIB_INTEGRATION"):
        pytest.skip("set BTCLIB_INTEGRATION=1 to run the integration tests")
    path = os.environ.get("BTCLIB_BITCOIND") or shutil.which("bitcoind")
    if path is None:
        pytest.skip("no bitcoind: name one in BTCLIB_BITCOIND or put it on PATH")
    return path


def _bitcoind_args(
    bitcoind: Sequence[str], datadir: Path, port: int, p2p_port: int | None
) -> list[str]:
    """Return the command line of a throwaway regtest node, `node`'s own.

    `bitcoind` is the command that runs the program, as `electrs` is to
    `_start_server`: the program's path, for the real one. With a
    `p2p_port` the node listens on it, on loopback, for a peer that syncs
    from it.
    """
    listen = ["-listen=0"]
    if p2p_port is not None:
        listen = ["-listen=1", f"-port={p2p_port}", "-bind=127.0.0.1"]
    return [
        *bitcoind,
        "-regtest",
        f"-datadir={datadir}",
        f"-rpcport={port}",
        "-rpcbind=127.0.0.1",
        # without it bitcoind ignores `-rpcbind` and binds `::1` as well as
        # `127.0.0.1` (src/httpserver.cpp), and keeps running when only
        # `127.0.0.1` is taken, which the start-again on a taken port
        # cannot see
        "-rpcallowip=127.0.0.1",
        *listen,
        "-natpmp=0",
        "-discover=0",
        "-listenonion=0",
        "-fallbackfee=0.0002",
        # so that `getrawtransaction` answers for a confirmed
        # transaction of any wallet: what a psbt needs is the previous
        # transaction whole, and a node without the index answers only
        # for what is still in its mempool
        "-txindex=1",
        "-printtoconsole=0",
    ]


@pytest.fixture(scope="session")
def node(
    bitcoind_path: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[BitcoinCoreRpcClient]:
    """Yield an rpc client of a regtest node started for this session.

    `-fallbackfee` because a regtest chain has no fee history to estimate
    from, and Core refuses to fund a transaction without one; the wallet
    calls here fund nothing, but a caller reading this as a recipe would
    meet that on the first `walletcreatefundedpsbt`.

    `-listen=0` because nothing here dials the node over p2p. `-natpmp`,
    `-discover` and `-listenonion` are switched off by name as well: each
    reaches past this machine -- a port mapping asked of the gateway, a
    public address looked up, a Tor control port dialled -- which is not
    what a throwaway regtest node wants of a developer's own network.
    """
    datadir = tmp_path_factory.mktemp("regtest")
    process, client, _ = start_on_free_ports(
        lambda: _start_node([bitcoind_path], datadir, None)
    )
    try:
        yield client
    finally:
        _stop(process)


def _wait_for(
    client: BitcoinCoreRpcClient, process: subprocess.Popen[bytes], debug_log: Path
) -> None:
    """Poll until the node answers, or fail with what it did instead.

    A node that exited because its rpc port is taken raises `PortTaken`.
    """
    deadline = time.monotonic() + _STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if process.poll() is not None:
            log = (
                debug_log.read_text(encoding="utf-8", errors="replace")
                if debug_log.exists()
                else ""
            )
            if _NODE_PORT_TAKEN in log:
                raise PortTaken(log)
            pytest.fail(f"bitcoind exited with {process.returncode}")
        try:
            client.call("getblockchaininfo")
        # every failure before the node is up is the same failure: the
        # cookie file is not written yet, or the socket is not listening
        except Exception:  # noqa: BLE001
            time.sleep(0.1)
        else:
            return
    pytest.fail(f"bitcoind did not answer within {_STARTUP_TIMEOUT} s")


@pytest.fixture
def wallets(
    node: BitcoinCoreRpcClient,
) -> tuple[BitcoinCoreRpcClient, BitcoinCoreRpcClient]:
    """Return a client of a funded wallet and one of a watch-only wallet.

    Two, because they are the two halves of what is being tested: the
    first holds keys and coins and stands for the rest of the world, and
    the second holds descriptors btclib built and no key at all -- which
    is what a wallet watching a hardware signer is.

    Named after the moment they were made, so that a session running
    several tests has no wallet of one still open in another; and
    `for_wallet` is the client's own way of naming the endpoint, the
    wallet being a path on the url rather than an argument.
    """
    suffix = f"{time.monotonic_ns():x}"
    miner, watcher = f"miner-{suffix}", f"watch-{suffix}"
    node.call("createwallet", [miner])
    # disable_private_keys, which is what makes the second wallet one that
    # can only watch: it is the third parameter of createwallet
    node.call("createwallet", [watcher, True])
    return node.for_wallet(miner), node.for_wallet(watcher)


def as_regtest(descriptor: Descriptor) -> Descriptor:
    """Return the descriptor read again as a regtest one.

    Version bytes cannot say which test chain a key is for -- btclib's
    test networks share them, which `bip44` documents where it refuses to
    guess -- so `account_descriptors` answers with the first,
    testnet, and its addresses are `tb1`. The scripts are the same
    scripts; what differs is the human encoding, and regtest spells it
    `bcrt1`. Reading the text back with the network named is how a caller
    gets the addresses this node prints.
    """
    return parse(add_checksum(str(descriptor)), "regtest")


def fund(miner: BitcoinCoreRpcClient, address: str, amount: str = "1.5") -> str:
    """Mine a spendable balance, pay an address, and confirm the payment.

    101 blocks because a coinbase output is spendable after 100, and the
    amount is a string because json carries no exact decimal -- the rpc
    client refuses a `Decimal` rather than rounding one.
    """
    miner.call("generatetoaddress", [101, miner.call("getnewaddress")])
    tx_id = miner.call("sendtoaddress", [address, amount])
    miner.call("generatetoaddress", [1, miner.call("getnewaddress")])
    return str(tx_id)


def spending_psbt(
    node: BitcoinCoreRpcClient,
    utxo: dict[str, Any],
    receive: Descriptor,
    change: Descriptor,
    pay_to: str,
    fee: int = 1_000,
) -> Psbt:
    """Return the psbt spending one utxo: a payment out, and change back.

    Built and updated by btclib alone -- the node is asked for the
    previous transaction and for nothing else -- so what a signer sees is
    a psbt no Core call composed.
    """
    amount = sats_from_btc(Decimal(str(utxo["amount"])))
    prev_tx = Tx.parse(node.call("getrawtransaction", [utxo["txid"]]))
    tx = Tx(
        vin=[TxIn(OutPoint(bytes.fromhex(str(utxo["txid"])), int(utxo["vout"])))],
        vout=[
            TxOut(amount // 2, parse(f"addr({pay_to})", "regtest").script_pub_key()),
            TxOut(amount - amount // 2 - fee, change.script_pub_key(0)),
        ],
    )
    psbt = Psbt.from_tx(tx)
    psbt.inputs[0].non_witness_utxo = prev_tx
    psbt = receive.update_psbt_input(psbt, 0, 0)
    return change.update_psbt_output(psbt, 1, 0)


def broadcast(node: BitcoinCoreRpcClient, psbt: Psbt) -> str:
    """Finalize a signed psbt and hand the transaction to the network.

    Which is the oracle these tests are here for: a signature that does
    not verify, a witness assembled wrong or a fee that is not there are
    all this call failing. `BitcoinCoreFetcher.broadcast` is what makes
    the call, `verify_network=True` and `regtest` its label -- the one
    chain this suite's node ever serves -- so a fixture pointed at the
    wrong node fails here rather than mining a transaction nobody meant
    to send it.
    """
    final = extract_tx(finalize(psbt), check_validity=True)
    tx_id = BitcoinCoreFetcher(node, "regtest").broadcast(final)
    assert tx_id == final.id
    return tx_id.hex()


# The fetcher tests' stack: a `bitcoind` of its own and an index server
# reading it. `node` above is one for the whole session and the reorg test
# invalidates blocks, which would change the chain under every other test.
#
# The server is Blockstream's `electrs`, which answers the Electrum
# protocol and Esplora's HTTP api from one index. Its switch is
# `BTCLIB_ELECTRS`, the path of the binary, with no `PATH` fallback:
# romanz's `electrs` has the same name and serves no HTTP, so a binary
# found by name could be the wrong program.
# `.github/workflows/integration-electrs.yml` builds the commit it pins.
# The wait for the server to follow the node is a poll: `electrs` polls its
# node for new blocks.

ELECTRS_ENV = "BTCLIB_ELECTRS"

# how long the server is given to catch up with the node: a generous bound
# on the failure case only
_SYNC_TIMEOUT = 60.0


# how many times the program (the node or the server) is started, each on
# fresh ports, while a port it was given is taken
_BIND_ATTEMPTS = 5

# what the server's log says of a port that is taken: Rust's `AddrInUse`,
# the operating system's own words, and the panic message of the monitoring
# server, which electrs raises without the cause (src/metrics.rs)
_PORT_TAKEN_MARKERS = (
    "AddrInUse",
    "Address already in use",
    "failed to start monitoring HTTP server",
)


# what bitcoind writes to its `debug.log` when it cannot bind its rpc port
# (src/httpserver.cpp); `-printtoconsole=0` leaves its stdout empty
_NODE_PORT_TAKEN = "Unable to bind any endpoint for RPC server"


class PortTaken(Exception):  # noqa: N818
    """The node or the server exited because a port it was given is taken."""


def port_was_taken(log: str) -> bool:
    """Return whether the server's log says it could not bind a port."""
    return any(marker in log for marker in _PORT_TAKEN_MARKERS)


def start_on_free_ports(start: Callable[[], _T], attempts: int = _BIND_ATTEMPTS) -> _T:
    """Return what `start` returns, calling it again while a port is taken.

    `_free_port` closes the port it picked, so another process can bind
    it before the program (the node or the server) does, and the program
    then exits. `start` picks
    its ports itself, so each call is a fresh try; the last attempt's
    `PortTaken` is not caught.
    """
    for _ in range(attempts - 1):
        try:
            return start()
        except PortTaken:
            continue
    return start()


def electrs_binary() -> str:
    """Return the `electrs` to run, skipping the test without one."""
    path = os.environ.get(ELECTRS_ENV)
    if not path:
        # starts `set BTCLIB_`, as the HWI switches' messages do, which
        # integration-bitcoind.yml exempts from its check that tests ran;
        # a missing bitcoind's does not
        pytest.skip(f"set {ELECTRS_ENV} to Blockstream's electrs binary")
    return path


class PlainLineTransport:
    """A `LineTransport` over plain TCP to one server.

    `TlsLineTransport`, the package's one `LineTransport`, has no plain
    TCP, so the tests that reach an Electrum server without TLS write
    their own. One connection per call, as there.
    """

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Send one request line and return the line answering it."""
        try:
            with create_connection((self.host, self.port), timeout=timeout) as sock:
                sock.sendall(request)
                with sock.makefile("rb") as stream:
                    line = stream.readline()
        except OSError as e:
            raise FetchError(f"no answer from {self.host}:{self.port}: {e}") from e
        if not line.endswith(b"\n"):
            raise FetchError("connection closed before a whole line")
        return line[:-1]


@dataclass
class Stack:
    """A `bitcoind` on regtest and the index server reading it."""

    node: BitcoinCoreRpcClient
    reward_address: str
    electrum: PlainLineTransport
    http_url: str
    server: subprocess.Popen[bytes]
    server_log: Path

    def mine(self, blocks: int = 1) -> list[str]:
        """Mine blocks on the node and wait until the server has them."""
        ids = self.node.call("generatetoaddress", [blocks, self.reward_address])
        self.wait_synced()
        return [str(block_id) for block_id in ids]

    def wait_synced(self) -> None:
        """Poll until both of the server's apis report the node's tip.

        Esplora's tip hash and Electrum's tip height and header hash are
        each compared with the node's.

        The server may not be listening yet, which is the same failure as
        any other answer that is not the tip: asked again, unless it has
        exited.
        """
        deadline = time.monotonic() + _SYNC_TIMEOUT
        while True:
            want = str(self.node.call("getbestblockhash"))
            height = int(self.node.call("getblockcount"))
            try:
                if self._tip_hash() == want and self._electrum_tip() == (height, want):
                    return
            except (OSError, FetchError):
                pass
            if self.server.poll() is not None:
                log = self.server_log.read_text(errors="replace")
                if port_was_taken(log):
                    raise PortTaken(log)
                pytest.fail(f"electrs exited with {self.server.returncode}: {log}")
            if time.monotonic() > deadline:
                pytest.fail(f"electrs did not reach {height} in {_SYNC_TIMEOUT} s")
            time.sleep(0.2)

    def _tip_hash(self) -> str:
        with urllib.request.urlopen(  # noqa: S310
            f"{self.http_url}/blocks/tip/hash", timeout=10
        ) as reply:
            return str(reply.read().decode("ascii").strip())

    def _electrum_tip(self) -> tuple[int, str]:
        line = self.electrum(electrum.headers_subscribe_request(1), 10)
        tip = electrum.headers_subscribe_response(line, 1)
        return tip.height, BlockHeader.parse(tip.header).hash.hex()

    def http_json(self, path: str) -> Any:
        """Return the parsed body of a GET on the Esplora api."""
        with urllib.request.urlopen(  # noqa: S310
            f"{self.http_url}{path}", timeout=10
        ) as reply:
            return json.loads(reply.read())


def make_fetcher(
    kind: str, stack: Stack, network: str = "regtest"
) -> NetworkVerifyingFetcher:
    """Return the `electrum` or `esplora` fetcher on the stack."""
    if kind == "electrum":
        return ElectrumFetcher(network, transport=stack.electrum)
    return EsploraFetcher(stack.http_url, network=network)


def _start(command: list[str], log: Path) -> subprocess.Popen[bytes]:
    with log.open("wb") as sink:
        return subprocess.Popen(  # noqa: S603
            command, stdout=sink, stderr=subprocess.STDOUT
        )


def _stop(process: subprocess.Popen[bytes]) -> None:
    process.terminate()
    try:
        process.wait(timeout=30)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()


def _start_node(
    bitcoind: Sequence[str], datadir: Path, p2p_port: int | None
) -> tuple[subprocess.Popen[bytes], BitcoinCoreRpcClient, int]:
    """Return a node, a client of it and its rpc port, once it answers.

    `p2p_port` is `_bitcoind_args`'s.

    The node is stopped again where it does not get there, `PortTaken`
    included, so that the next try does not leave it behind.
    """
    port = _free_port()
    # a try that failed left its log behind, and its complaint must not be
    # read as this one's
    (datadir / "regtest" / "debug.log").unlink(missing_ok=True)
    process = _start(
        _bitcoind_args(bitcoind, datadir, port, p2p_port), datadir / "stdout.log"
    )
    client = BitcoinCoreRpcClient(
        f"http://127.0.0.1:{port}", cookie_path=datadir / "regtest" / ".cookie"
    )
    try:
        _wait_for(client, process, datadir / "regtest" / "debug.log")
    except BaseException:
        _stop(process)
        raise
    return process, client, port


def _start_server(
    electrs: Sequence[str],
    datadir: Path,
    index: Path,
    rpc_port: int,
    miner: BitcoinCoreRpcClient,
    address: str,
) -> Stack:
    """Return a stack whose server, on ports of its own, has indexed the node.

    The server is stopped again where it does not get there, `PortTaken`
    included, so that the next try does not leave it behind.
    """
    electrum_port, http_port = _free_port(), _free_port()
    log = index / "electrs.log"
    server = _start(
        [
            *electrs,
            "--network=regtest",
            f"--daemon-dir={datadir}",
            f"--db-dir={index}",
            f"--daemon-rpc-addr=127.0.0.1:{rpc_port}",
            f"--electrum-rpc-addr=127.0.0.1:{electrum_port}",
            f"--http-addr=127.0.0.1:{http_port}",
            f"--monitoring-addr=127.0.0.1:{_free_port()}",
            "--jsonrpc-import",
        ],
        log,
    )
    stack = Stack(
        miner,
        address,
        PlainLineTransport("127.0.0.1", electrum_port),
        f"http://127.0.0.1:{http_port}",
        server,
        log,
    )
    try:
        stack.wait_synced()
    except BaseException:
        _stop(server)
        raise
    return stack


@contextmanager
def running_stack(
    bitcoind: str, electrs: str, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[Stack]:
    """Yield a node with 101 blocks and a server that has indexed them.

    The node is started as `node` starts its own, and `electrs` is
    told to read blocks over rpc rather than from the node's block files,
    which a node that has not flushed them yet would not have written.
    """
    datadir = tmp_path_factory.mktemp("stack-node")
    index = tmp_path_factory.mktemp("stack-index")
    node_process, client, rpc_port = start_on_free_ports(
        lambda: _start_node([bitcoind], datadir, None)
    )
    stack: Stack | None = None
    try:
        client.call("createwallet", ["miner"])
        miner = client.for_wallet("miner")
        address = str(miner.call("getnewaddress"))
        # a coinbase output is spendable after 100 blocks
        miner.call("generatetoaddress", [101, address])
        stack = start_on_free_ports(
            lambda: _start_server([electrs], datadir, index, rpc_port, miner, address)
        )
        yield stack
    finally:
        if stack is not None:
            _stop(stack.server)
        _stop(node_process)


# The Floresta stack: a `bitcoind` that mines, `utreexod` that syncs from
# it, and `florestad` whose only peer is `utreexod`.
#
# Floresta validates blocks with utreexo proofs, which `bitcoind` does not
# serve, so given `bitcoind` alone it follows headers and no blocks.
# `utreexod` serves them. Each program's switch is the path of its binary.
# `.github/workflows/integration-floresta.yml` builds one and downloads the
# other.
#
# Floresta's Electrum server is a wallet's: it answers for the scripts it
# watches and no others. The first `blockchain.scriptpubkey.get_history`
# for a script queues it for a scan and answers `null`, which is how a
# test makes the server watch one.

FLORESTAD_ENV = "BTCLIB_FLORESTAD"
UTREEXOD_ENV = "BTCLIB_UTREEXOD"


def floresta_binaries() -> tuple[str, str]:
    """Return the `florestad` and `utreexod` to run, skipping without both."""
    paths = []
    for name, what in ((FLORESTAD_ENV, "florestad"), (UTREEXOD_ENV, "utreexod")):
        path = os.environ.get(name)
        if not path:
            pytest.skip(f"set {name} to the {what} binary")
        paths.append(path)
    return paths[0], paths[1]


class JsonRpc2Transport:
    """A `LineTransport` that marks its requests JSON-RPC 2.0.

    Floresta answers a request without `"jsonrpc": "2.0"` with a parse
    error, and `btclib.electrum` does not write the member. The Electrum
    spec does not require it either (spesmilo/electrum-protocol,
    `docs/protocol-basics.rst`), so the fetcher reaches Floresta only
    through this wrapper.
    """

    def __init__(self, inner: LineTransport) -> None:
        self.inner = inner

    def __call__(self, request: bytes, timeout: float) -> bytes:
        """Send the request as JSON-RPC 2.0 and return the line answering."""
        body = json.loads(request)
        body["jsonrpc"] = "2.0"
        return self.inner(json.dumps(body).encode("utf-8") + b"\n", timeout)


@dataclass
class FlorestaStack:
    """A `bitcoind` on regtest and the `florestad` following it."""

    node: BitcoinCoreRpcClient
    reward_address: str
    electrum: LineTransport
    tls: LineTransport
    server: subprocess.Popen[bytes]
    server_log: Path
    peer_log: Path

    def mine(self, blocks: int = 1) -> list[str]:
        """Mine blocks on the node and wait until the server has them."""
        ids = self.node.call("generatetoaddress", [blocks, self.reward_address])
        self.wait_synced()
        return [str(block_id) for block_id in ids]

    def wait_synced(self) -> None:
        """Poll until the server's tip is the node's, by height and hash."""
        deadline = time.monotonic() + _FLORESTA_SYNC_TIMEOUT
        while True:
            want = str(self.node.call("getbestblockhash"))
            height = int(self.node.call("getblockcount"))
            try:
                line = self.electrum(electrum.headers_subscribe_request(1), 10)
                tip = electrum.headers_subscribe_response(line, 1)
                if (tip.height, BlockHeader.parse(tip.header).hash.hex()) == (
                    height,
                    want,
                ):
                    return
            except (OSError, FetchError, ValueError):
                pass
            if self.server.poll() is not None:
                log = self.server_log.read_text(encoding="utf-8", errors="replace")
                pytest.fail(f"florestad exited with {self.server.returncode}: {log}")
            if time.monotonic() > deadline:
                # drop the electrum_protocol lines this loop's own connections
                # write
                kept = [
                    line
                    for line in self.server_log.read_text(
                        encoding="utf-8", errors="replace"
                    ).splitlines()
                    if "electrum_protocol" not in line
                ]
                log = "\n".join(kept)[-6000:]
                log += (
                    "\n--\n"
                    + self.peer_log.read_text(encoding="utf-8", errors="replace")[
                        -6000:
                    ]
                )
                err_msg = (
                    f"florestad did not reach {height} in {_FLORESTA_SYNC_TIMEOUT} s"
                )
                pytest.fail(f"{err_msg}: {log}")
            time.sleep(0.5)

    def request(self, method: str, params: list[Any], *, tls: bool = False) -> Any:
        """Return the result of one Electrum call, plain or over TLS."""
        line = (self.tls if tls else self.electrum)(
            electrum.encode_request(1, method, params), 10
        )
        return electrum.decode_response(line, 1)


def _wait_for_file(path: Path, process: subprocess.Popen[bytes]) -> None:
    """Poll until `path` exists, or fail with what the process did instead."""
    deadline = time.monotonic() + _STARTUP_TIMEOUT
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            pytest.fail(f"{path.name} not written: exit {process.returncode}")
        time.sleep(0.1)
    pytest.fail(f"{path} not written within {_STARTUP_TIMEOUT} s")


def _wait_for_log(path: Path, text: str, process: subprocess.Popen[bytes]) -> None:
    """Poll until `text` is in the log at `path`, or fail with the log."""
    deadline = time.monotonic() + _FLORESTA_SYNC_TIMEOUT
    while time.monotonic() < deadline:
        log = path.read_text(encoding="utf-8", errors="replace")
        if text in log:
            return
        if process.poll() is not None:
            pytest.fail(f"exit {process.returncode} before {text!r}: {log[-3000:]}")
        time.sleep(0.2)
    pytest.fail(f"no {text!r} in {path.name} within {_FLORESTA_SYNC_TIMEOUT} s")


# how long the server is given to follow the node: `utreexod` relays a
# block when it has it, so the wait is for the two hops
_FLORESTA_SYNC_TIMEOUT = 120.0


@contextmanager
def running_floresta_stack(
    bitcoind: str,
    florestad: str,
    utreexod: str,
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[FlorestaStack]:
    """Yield a node with 101 blocks and a `florestad` that has followed them."""
    datadir = tmp_path_factory.mktemp("floresta-node")
    utreexo_dir = tmp_path_factory.mktemp("floresta-utreexod")
    floresta_dir = tmp_path_factory.mktemp("floresta-data")
    p2p_port = _free_port()
    utreexo_p2p, utreexo_rpc = _free_port(), _free_port()
    electrum_port, tls_port = _free_port(), _free_port()
    node_process, client, _ = start_on_free_ports(
        lambda: _start_node([bitcoind], datadir, p2p_port)
    )
    processes = [node_process]
    try:
        client.call("createwallet", ["miner"])
        miner = client.for_wallet("miner")
        address = str(miner.call("getnewaddress"))
        miner.call("generatetoaddress", [101, address])
        processes.append(
            _start(
                [
                    utreexod,
                    "--regtest",
                    f"--datadir={utreexo_dir}",
                    "--rpcuser=u",
                    "--rpcpass=p",
                    f"--rpclisten=127.0.0.1:{utreexo_rpc}",
                    "--utreexoproofindex",
                    "--prune=0",
                    f"--listen=127.0.0.1:{utreexo_p2p}",
                    f"--connect=127.0.0.1:{p2p_port}",
                    "--notls",
                    "--nobanning",
                ],
                utreexo_dir / "utreexod.log",
            )
        )
        server = _start(
            [
                florestad,
                "--network=regtest",
                f"--data-dir={floresta_dir}",
                f"--connect=127.0.0.1:{utreexo_p2p}",
                "--allow-v1-fallback",
                f"--electrum-address=127.0.0.1:{electrum_port}",
                "--enable-electrum-tls",
                f"--electrum-address-tls=127.0.0.1:{tls_port}",
                "--generate-cert",
                f"--rpc-address=127.0.0.1:{_free_port()}",
            ],
            floresta_dir / "florestad.log",
        )
        processes.append(server)
        # florestad writes the certificate it generates under its data
        # directory, and signs it for `localhost`
        cert = floresta_dir / "regtest" / "tls" / "cert.pem"
        _wait_for_file(cert, server)
        context = ssl.create_default_context(cafile=str(cert))
        stack = FlorestaStack(
            miner,
            address,
            JsonRpc2Transport(PlainLineTransport("127.0.0.1", electrum_port)),
            JsonRpc2Transport(TlsLineTransport("localhost", tls_port, context=context)),
            server,
            floresta_dir / "florestad.log",
            utreexo_dir / "utreexod.log",
        )
        stack.wait_synced()
        # a block that arrives while Floresta is still ending its initial
        # sync is never requested, so nothing is mined before it says it
        # is running
        _wait_for_log(floresta_dir / "florestad.log", "starting running node", server)
        yield stack
    finally:
        for process in reversed(processes):
            _stop(process)
