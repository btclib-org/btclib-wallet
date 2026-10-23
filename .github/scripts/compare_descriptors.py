# Copyright (c) The btclib developers
# Distributed under the MIT software license, see the accompanying
# LICENSE file or https://opensource.org/license/mit for the full text.

r"""Compare three descriptor parsers over the repository's descriptors.

The three are this package's `parse`, Bitcoin Core's `getdescriptorinfo` and
`deriveaddresses` on a mainnet node with no chain and no peers, and
rust-miniscript through `.github/interop/miniscript-compare`, which prints
what the library makes of each descriptor it reads. For each input the
script says whether each one accepts or refuses it, and, where more than one
accepts, whether the scriptPubKey and the addresses agree. Core derives
addresses only, so a script is compared between `parse` and rust-miniscript,
and an address among all three that give one.

The inputs are the ones the repository already holds:

- `tests/_data/miniscript_fixed_tests.json`, each miniscript as the argument
  of ``wsh()`` and, with its keys x-only, as the one leaf of a ``tr()``;
- the descriptors of `tests/descriptors/bitcoin_s_test.py`, read from its
  source without running it;
- `tests/_data/descriptor_checksums.json`, each with its checksum;
- `fuzz/corpus/fuzz_descriptor/`;
- the `descriptor_parse` corpus of a Bitcoin Core qa-assets checkout, if
  `--qa-assets` names one. rust-bitcoin's qa-assets holds no descriptor
  corpus;
- the lines of the files `--extra` names, one descriptor per line, for a
  case being narrowed down by hand.

An input that is not UTF-8 is counted and left out: JSON-RPC carries text,
so Core would be handed other octets than the ones read.

`tests/README.md` gives the command to build the Rust program and to run this
script.

It exits 0 when every input was compared, whatever the comparison found, and
1 when a comparison could not run. `--report` writes every input's verdicts
as JSON lines, for a reader who wants more than the disagreements.
"""

from __future__ import annotations

import argparse
import ast
import base64
import http.client
import json
import re
import socket
import subprocess
import sys
import tempfile
import time
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path

from btclib_wallet.descriptors import multipath_descriptors, parse

ROOT = Path(__file__).resolve().parents[2]

# the x coordinate of the generator, an internal key that every parser takes
_INTERNAL_KEY = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
# a compressed key in a miniscript, which a tapscript spells without its parity
_COMPRESSED = re.compile(r"(?<![0-9a-fA-F])0[23]([0-9a-fA-F]{64})(?![0-9a-fA-F])")
_BATCH = 100
_NODE_STARTUP_SECONDS = 180.0


@dataclass(frozen=True)
class Case:
    """One input: where it came from, and the text every parser reads."""

    source: str
    name: str
    text: str


@dataclass(frozen=True)
class Verdict:
    """What one parser made of one input.

    `scripts` is empty where the parser does not derive scripts, as Core,
    or where the derivation failed; `addresses` is empty where none was
    given. `note` is the error of a refusal or of a derivation.
    """

    accepted: bool
    scripts: tuple[str, ...] = ()
    addresses: tuple[str, ...] = ()
    note: str = ""


def _text_cases(source: str, items: Sequence[tuple[str, bytes]]) -> Iterator[Case]:
    """Yield the cases whose octets are UTF-8, counting the others on stderr."""
    skipped = 0
    for name, data in items:
        try:
            yield Case(source, name, data.decode("utf-8"))
        except UnicodeDecodeError:
            skipped += 1
    if skipped:
        print(f"{source}: {skipped} inputs are not UTF-8, left out", file=sys.stderr)


def _fixed_cases() -> Iterator[Case]:
    """Yield each fixed test of Core's miniscript tests, in both contexts."""
    path = ROOT / "tests" / "_data" / "miniscript_fixed_tests.json"
    vectors = json.loads(path.read_text(encoding="utf-8"))
    for index, vector in enumerate(vectors):
        miniscript = vector["miniscript"]
        yield Case("fixed", f"{index} wsh", f"wsh({miniscript})")
        xonly = _COMPRESSED.sub(r"\1", miniscript)
        yield Case("fixed", f"{index} tr", f"tr({_INTERNAL_KEY},{xonly})")


def _bitcoin_s_cases() -> Iterator[Case]:
    """Yield the descriptors of the bitcoin-s test, read without running it."""
    path = ROOT / "tests" / "descriptors" / "bitcoin_s_test.py"
    wanted = {"ACCEPTED", "REFUSED"}
    found: dict[str, list[tuple[str, ...]]] = {}
    for node in ast.parse(path.read_text(encoding="utf-8")).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            target = node.target
        else:
            continue
        if isinstance(target, ast.Name) and target.id in wanted:
            assert node.value is not None  # noqa: S101 -- narrowed above
            found[target.id] = ast.literal_eval(node.value)
    for table, rows in found.items():
        for index, row in enumerate(rows):
            yield Case("bitcoin-s", f"{table} {index}", row[0])


def _checksum_cases() -> Iterator[Case]:
    """Yield each descriptor of the checksum vectors, with its checksum."""
    path = ROOT / "tests" / "_data" / "descriptor_checksums.json"
    for index, vector in enumerate(json.loads(path.read_text(encoding="utf-8"))):
        yield Case("checksums", str(index), f"{vector['desc']}#{vector['checksum']}")


def _directory_cases(source: str, directory: Path) -> Iterator[Case]:
    """Yield the cases of the files of `directory`, in name order."""
    paths = sorted(path for path in directory.iterdir() if path.is_file())
    if not paths:
        raise SystemExit(f"{directory} holds no file")
    yield from _text_cases(source, [(path.name, path.read_bytes()) for path in paths])


def cases(qa_assets: Path | None, extras: Sequence[Path]) -> list[Case]:
    """Return every input, in the order the module docstring lists them."""
    found = [*_fixed_cases(), *_bitcoin_s_cases(), *_checksum_cases()]
    found.extend(
        _directory_cases("fuzz-corpus", ROOT / "fuzz" / "corpus" / "fuzz_descriptor")
    )
    if qa_assets is not None:
        found.extend(
            _directory_cases(
                "qa-assets", qa_assets / "fuzz_corpora" / "descriptor_parse"
            )
        )
    for extra in extras:
        lines = extra.read_text(encoding="utf-8").splitlines()
        found.extend(
            Case("extra", f"{extra.name} {n}", line) for n, line in enumerate(lines)
        )
    return found


def read_with_parse(text: str) -> Verdict:
    """Return what this package makes of `text`, at the first of its paths.

    `parse` reads one path, and `multipath_descriptors` is where a BIP389
    descriptor is expanded, as Core and rust-miniscript do in one call.
    """
    prv_keys: dict[str, str] = {}
    try:
        descriptor = parse(multipath_descriptors(text, "mainnet")[0], prv_keys=prv_keys)
    except Exception as error:  # noqa: BLE001 -- any refusal is a verdict
        return Verdict(False, note=f"{type(error).__name__}: {error}")
    try:
        scripts = descriptor.script_pub_keys(0, prv_keys)
    except Exception as error:  # noqa: BLE001 -- a derivation that failed
        return Verdict(True, note=f"{type(error).__name__}: {error}")
    return Verdict(
        True,
        scripts=tuple(script.script.hex() for script in scripts),
        addresses=tuple(script.address for script in scripts if script.address),
    )


class Node:
    """A mainnet `bitcoind` with no chain and no peers, asked over JSON-RPC."""

    def __init__(self, bitcoind: Path) -> None:
        """Start the node in a directory of its own, and wait for its RPC."""
        self._directory = tempfile.TemporaryDirectory(prefix="compare-descriptors-")
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self._port = probe.getsockname()[1]
        self._process = subprocess.Popen(  # noqa: S603 -- the path the caller named
            [
                str(bitcoind),
                "-chain=main",
                f"-datadir={self._directory.name}",
                f"-rpcport={self._port}",
                "-listen=0",
                "-connect=0",
                "-dnsseed=0",
                "-fixedseeds=0",
                "-discover=0",
                "-disablewallet",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._wait()

    def _authorization(self) -> str:
        """Return the cookie's credentials as an HTTP header value."""
        cookie = Path(self._directory.name, ".cookie").read_text(encoding="utf-8")
        return "Basic " + base64.b64encode(cookie.strip().encode()).decode()

    def _post(self, body: list[dict[str, object]]) -> list[dict[str, object]]:
        """Return the answers to a batch of requests, in the order asked."""
        connection = http.client.HTTPConnection("127.0.0.1", self._port, timeout=600)
        try:
            connection.request(
                "POST",
                "/",
                json.dumps(body),
                {"Authorization": self._authorization()},
            )
            response = connection.getresponse()
            payload = response.read()
        finally:
            connection.close()
        answers: list[dict[str, object]] = json.loads(payload)
        return sorted(answers, key=lambda answer: int(str(answer["id"])))

    def _wait(self) -> None:
        """Poll until the node answers, or say why it did not."""
        deadline = time.monotonic() + _NODE_STARTUP_SECONDS
        while time.monotonic() < deadline:
            if self._process.poll() is not None:
                raise SystemExit(f"bitcoind exited with {self._process.returncode}")
            try:
                answer = self._post(
                    [{"method": "getblockchaininfo", "params": [], "id": 0}]
                )[0]
            except (OSError, ValueError, http.client.HTTPException):
                time.sleep(0.5)
                continue
            if answer.get("error") is None:
                return
            time.sleep(0.5)
        self.stop()
        raise SystemExit("bitcoind did not answer in time")

    def call(self, method: str, params: Sequence[Sequence[object]]) -> list[Verdict]:
        """Return one verdict per parameter list, `None` results as refusals."""
        verdicts: list[Verdict] = []
        for start in range(0, len(params), _BATCH):
            chunk = params[start : start + _BATCH]
            answers = self._post(
                [
                    {"method": method, "params": list(each), "id": index}
                    for index, each in enumerate(chunk)
                ]
            )
            for answer in answers:
                error = answer.get("error")
                if error is None:
                    verdicts.append(Verdict(True, note=json.dumps(answer["result"])))
                else:
                    verdicts.append(Verdict(False, note=str(error["message"])))  # type: ignore[index]
        return verdicts

    def stop(self) -> None:
        """Stop the node and remove its directory."""
        try:
            self._post([{"method": "stop", "params": [], "id": 0}])
            self._process.wait(timeout=60)
        except (
            OSError,
            ValueError,
            http.client.HTTPException,
            subprocess.TimeoutExpired,
        ):
            self._process.kill()
            self._process.wait()
        self._directory.cleanup()


def _first_path(addresses: list[object]) -> tuple[str, ...]:
    """Return the addresses of the first path of a multipath answer."""
    if addresses and isinstance(addresses[0], list):
        addresses = addresses[0]
    return tuple(str(address) for address in addresses)


def read_with_core(node: Node, texts: Sequence[str]) -> list[Verdict]:
    """Return what Core makes of each text: accepted, and its addresses.

    Core derives from the text it was given, with its checksum, so that a
    hardened step under an extended private key is derived as `parse` does,
    and not from the public form `getdescriptorinfo` hands back. A multipath
    descriptor answers a list per path, of which the first is kept.
    """
    infos = node.call("getdescriptorinfo", [[text] for text in texts])
    asked = [
        (index, json.loads(info.note))
        for index, info in enumerate(infos)
        if info.accepted
    ]
    requests = []
    for index, info in asked:
        signed = f"{texts[index].split('#')[0]}#{info['checksum']}"
        requests.append([signed, [0, 0]] if info["isrange"] else [signed])
    derived = node.call("deriveaddresses", requests)
    verdicts = [Verdict(False, note=info.note) for info in infos]
    for (index, _), answer in zip(asked, derived, strict=True):
        verdicts[index] = (
            Verdict(True, addresses=_first_path(json.loads(answer.note)))
            if answer.accepted
            else Verdict(True, note=answer.note)
        )
    return verdicts


def _unhex(text: str) -> str:
    """Return the message a hex field holds, or the field if it is `-`."""
    return "" if text == "-" else bytes.fromhex(text).decode("utf-8", "replace")


def _rust_row(line: str) -> tuple[int, Verdict]:
    """Return the index and verdict of one line of the Rust program."""
    index, status, script, address, note = line.rstrip("\n").split("\t")
    return int(index), Verdict(
        status == "accepted",
        scripts=() if script == "-" else (script,),
        addresses=() if address == "-" else (address,),
        note=_unhex(note),
    )


def read_with_rust(program: Path, texts: Sequence[str]) -> list[Verdict]:
    """Return what rust-miniscript makes of each text.

    A run that ends before it has answered every input is a crash of the
    input it stopped on, and the rest are asked again.
    """
    verdicts: list[Verdict | None] = [None] * len(texts)
    start = 0
    while start < len(texts):
        lines = "".join(text.encode().hex() + "\n" for text in texts[start:])
        run = subprocess.run(  # noqa: S603 -- the path the caller named
            [str(program)],
            input=lines,
            capture_output=True,
            encoding="utf-8",
            check=False,
        )
        answered = 0
        for line in run.stdout.splitlines():
            index, verdict = _rust_row(line)
            verdicts[start + index] = verdict
            answered = index + 1
        start += answered
        if start < len(texts):
            note = f"rust-miniscript stopped with {run.returncode}"
            verdicts[start] = Verdict(False, note=note)
            start += 1
    return [verdict or Verdict(False, note="no answer") for verdict in verdicts]


def disagreements(core: Verdict, ours: Verdict, rust: Verdict) -> list[str]:
    """Return what the verdicts of one input disagree on, empty if nothing."""
    found: list[str] = []
    accepting = {
        name
        for name, verdict in (("core", core), ("parse", ours), ("rust", rust))
        if verdict.accepted
    }
    if accepting not in (set(), {"core", "parse", "rust"}):
        found.append("acceptance")
    if len(ours.scripts) == 1 == len(rust.scripts) and ours.scripts != rust.scripts:
        found.append("script parse/rust")
    pairs = (
        ("parse/core", ours.addresses, core.addresses),
        ("rust/core", rust.addresses, core.addresses[:1] if core.addresses else ()),
        ("parse/rust", ours.addresses[:1], rust.addresses),
    )
    for name, left, right in pairs:
        if left and right and left != right:
            found.append(f"address {name}")
    return found


def _word(verdict: Verdict) -> str:
    """Return `accept` or `refuse`."""
    return "accept" if verdict.accepted else "refuse"


def _show(case: Case, kinds: list[str], verdicts: Sequence[Verdict]) -> str:
    """Return the lines that report one input's disagreements."""
    core, ours, rust = verdicts
    text = case.text if len(case.text) <= 120 else case.text[:117] + "..."
    lines = [
        f"{case.source} {case.name}: {', '.join(kinds)}",
        f"    input  {text!r}",
        f"    core   {_word(core)}  {core.addresses or core.note[:200]}",
        f"    parse  {_word(ours)}  {ours.scripts or ours.note[:200]}",
        f"    rust   {_word(rust)}  {rust.scripts or rust.note[:200]}",
    ]
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Compare the three parsers over the inputs, print the disagreements."""
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--bitcoind", type=Path, required=True)
    parser.add_argument("--miniscript-compare", type=Path, required=True)
    parser.add_argument("--qa-assets", type=Path)
    parser.add_argument("--extra", type=Path, action="append", default=[])
    parser.add_argument("--report", type=Path)
    arguments = parser.parse_args(argv)

    inputs = cases(arguments.qa_assets, arguments.extra)
    texts = [case.text for case in inputs]
    node = Node(arguments.bitcoind)
    try:
        cores = read_with_core(node, texts)
    finally:
        node.stop()
    rusts = read_with_rust(arguments.miniscript_compare, texts)
    ours = [read_with_parse(text) for text in texts]

    tally: Counter[tuple[str, str]] = Counter()
    differing = 0
    report = []
    for case, core, mine, rust in zip(inputs, cores, ours, rusts, strict=True):
        kinds = disagreements(core, mine, rust)
        tally[(case.source, ", ".join(kinds) or "agree")] += 1
        report.append(
            {
                "source": case.source,
                "name": case.name,
                "text": case.text,
                "disagreements": kinds,
                "core": asdict(core),
                "parse": asdict(mine),
                "rust": asdict(rust),
            }
        )
        if kinds:
            differing += 1
            print(_show(case, kinds, (core, mine, rust)))
    if arguments.report:
        arguments.report.write_text(
            "".join(json.dumps(row) + "\n" for row in report), encoding="utf-8"
        )
    print()
    for (source, kind), count in sorted(tally.items()):
        print(f"{source:12} {kind:40} {count}")
    print(f"{differing} of {len(inputs)} inputs differ")
    return 0


if __name__ == "__main__":
    sys.exit(main())
