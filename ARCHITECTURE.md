# Architecture

btclib-wallet is what a wallet does on top of
[btclib](https://github.com/btclib-org/btclib): from a seed to a signed,
broadcast transaction. This page is its high-level design: which module
holds what, the one dependency direction, and every place a module
crosses out of the process it runs in. What a user can expect of it in
terms of security is [SECURITY](./SECURITY.md), and why those
expectations hold is the [assurance case](./ASSURANCE_CASE.md).

## The one dependency

btclib is the protocol: the curve arithmetic, the signature schemes, the
codecs, scripts and transactions. This package imports it and re-exports
nothing of it — a name btclib defines is imported from btclib, never from
here — and nothing in btclib imports this package. `tests/all_test.py`
holds the first half: a module exporting a name it does not define fails
it unless `REEXPORTED` records the name, and no entry there is btclib's;
`tests/imports_test.py` adds that every import of a unit that moved here
names this package rather than btclib's copy. The second half is
btclib's own: its `pyproject.toml` does not depend on this package. The
edge is btclib-org/btclib#2129's table, row 5 — `btclib_wallet`, under
`src/btclib_wallet/` — sitting above `btclib`, row 4, and depending on it
and on [bitcoin-core-rpc](https://github.com/btclib-org/bitcoin-core-rpc),
row 6: dependencies point one way, down that table, so nothing in
`btclib` or in `bitcoin-core-rpc` imports this package either.
`btclib_wallet.fetch` publishes `bitcoin-core-rpc`'s clients and
transport under its own names, and `tests/all_test.py`'s `REEXPORTED`
records each of them.

The line between this package and btclib is Bitcoin Core's between
`src/consensus` and `src/wallet`: what places a module here is everything
from a seed to a signed, broadcast transaction, and every module with a
counterparty outside the process — a socket, a subprocess, a node, a
device — where the codec of a protocol stays btclib's and opens nothing.

What this package signs, it signs through `btclib.ecc`, so the dispatch
to the libsecp256k1 bindings and where constant time ends are btclib's,
read in its own
[ARCHITECTURE](https://github.com/btclib-org/btclib/blob/main/ARCHITECTURE.md)
and
[SECURITY](https://github.com/btclib-org/btclib/blob/main/SECURITY.md).
`src/btclib_wallet/bip32/bip32.py` and `src/btclib_wallet/silent_payments.py`
are the two modules that reach past that dispatch and call the
`btclib_secp256k1` bindings directly, for a private-key tweak and a
silent-payment key agreement the general dispatch does not cover.

`btclib_wallet/__init__.py`'s `__all__` is the root of the public tree,
written out rather than discovered; nothing is imported eagerly, and a
submodule loads on first attribute access through the package's own
`__getattr__`, so `import btclib_wallet` alone pulls in none of it.

## From a seed to a key

- `bip32/` derives extended keys along a BIP32 path, and `bip32.der_path`
  and `bip32.key_origin` are its two notations — a `der_path` string and
  the fingerprint-plus-path pair a psbt or a descriptor carries.
- `mnemonic/` turns entropy into a sentence and a sentence into a seed,
  for BIP39, Electrum's own scheme and SLIP39, `mnemonic.dispatch`
  answering which scheme a sentence belongs to and `mnemonic.entropy` and
  `mnemonic.mnemonic` being the word-list codec every scheme is built on.
- `bip85.py` derives another wallet's entropy — a BIP39 sentence among
  other formats — from one BIP32 root, so one backup stands behind
  several keychains that share no key with each other.
- `slip132.py` and `bip44.py` turn an extended key into an address:
  SLIP132's key-version table for which curve and script type an xpub
  prefix names, BIP44's `m/purpose'/coin_type'/account'/change/index`
  for which key a path derives.
- `bip38.py` and `minikey.py` spell a single private key that no seed
  derives: BIP38 encrypts it under a password with scrypt and AES, and a
  Casascius minikey is a short string whose `sha256` is the key itself.

## Watching, not holding: descriptors and PSBTs

- `descriptors/` reads BIP380's output-descriptor grammar —
  `descriptors.key_expression` for the KEY expressions and
  `descriptors.miniscript` for BIP379's SCRIPT language, a tree of
  fragments a descriptor's own module composes into the scripts and the
  psbt fields an account produces — and hands back what a wallet needs to
  watch somebody else's keys, never a private one of its own.
- `psbt/` is BIP174 and BIP370: the three maps a psbt is made of, the
  Combiner, the Finalizer and the Extractor, and the size estimation a
  fee rate is applied to. `psbt.musig2`, `psbt.frost` and
  `psbt.silent_payments` are the later BIPs' own roles over the fields
  each adds — BIP373, BIP445 and BIP375 respectively — `frost`'s own
  fields being proprietary records under a btclib identifier until a BIP
  assigns them the bytes.
- `tx_or_psbt.py` sniffs BIP174's five-byte magic and dispatches to
  `Tx.parse`, `Psbt.parse` or `Psbt.b64decode` accordingly, so a caller
  holding hex, base64 or raw bytes from an unknown source does not answer
  that question itself.
- `tx_builder.py` composes a psbt at a fee rate with change, out of parts
  that live elsewhere — `Psbt.prevouts`, `Psbt.vsize_estimate`,
  `btclib.fee.fee_from_vsize`, `btclib.fee.dust_threshold` — and `coin_selection.py`
  is what chooses the inputs it spends: Bitcoin Core's own three
  algorithms, `branch_and_bound`, `knapsack` and `single_random_draw`,
  `select_coins` running whichever the caller names — every one of them
  by default — and keeping the result of lowest waste, Core's own
  `SelectionResult::GetWaste` metric.
- `core_import.py` is the request Bitcoin Core's `importdescriptors`
  takes, built and validated here so that a wrong field is caught before
  it reaches a node — no RPC call and no client of its own, the caller
  already holding one.

## The wallets, and the state they remember

`wallet/wallet.py` holds the vocabulary every wallet in the package
answers to — which addresses have been handed out, what is remembered
about each, whether any private key is held — and no key, descriptor or
script of its own. `wallet.key_wallet.KeyWallet` derives no address from
a position and holds individual keys instead; `wallet.descriptor_wallet`
and `wallet.script_wallet` are addressed by the BIP44 branch and index a
`RangedWallet` puts below an account, one from an output descriptor and
one from a script template.

## The signing boundary

`psbt_signer.py` declares the `PsbtSigner` protocol every external
signer answers to — what a caller may ask and what has to come back —
distinct from `psbt.sign`, which plays the Signer role over a
`KeyManager` btclib calls in-process and whose answers are already
btclib's own. `psbt_signer_contract.assert_psbt_signer` checks an
implementation of the protocol against it from outside, for any
implementer: a command-line adapter, an in-process driver, a signing
service. `psbt_signer.SoftwareSigner` is this package's own in-process
implementation, and `hwi.py`'s `HwiSigner` a second one that runs Bitcoin
Core's [HWI](https://github.com/bitcoin-core/HWI) as a subprocess,
selecting a device by fingerprint and passing five of the protocol's
calls through HWI's JSON command line; nothing of `hwilib` itself is
imported, so the subprocess is the whole of the dependency.

`bip322.py` signs a message by satisfying the address's script rather
than by a key the verifier recovers, as `btclib.ecc.bms` does: the
signature spends a virtual output paying to that address, and
`script.engine` verifies it, so a taproot, p2wsh or multisig address can
sign. `fuzz/fuzz_bip322.py` fuzzes its decoder.

## Reaching outside the process

`fetch/` is the one package that goes and asks where the chain is, and
it answers in btclib's own types, `Tx`, `TxOut` and `BlockHeader`.
`Fetcher` is the interface, implemented once per backend —
`BitcoinCoreFetcher` over a full node's JSON-RPC, `BitcoinCoreRestFetcher`
over the same node's unauthenticated `-rest` interface, `EsploraFetcher`
over a block explorer's HTTP API, `ElectrumFetcher` over an Electrum
server — so calling code takes a `Fetcher` and never branches on which
one it got. `Broadcaster` and `FeeEstimator` are two further protocols a
backend may or may not satisfy: `BitcoinCoreRestFetcher` answers neither,
Core's `-rest` interface being read-only and carrying no fee estimation.
`fetch.transport` is the client seam — one HTTP connection per call, one
kept open across calls, and `TlsLineTransport` for the Electrum line
protocol — and the codec each backend speaks belongs to `btclib.p2p` or
`btclib.electrum`, outside this package: importing `fetch` costs
`urllib`, `ssl` and `socket`, never the reverse.

A fetcher raises btclib's `FetchError`, `HttpError` and `RpcError`.
`bitcoin-core-rpc` declares classes of the same names that are not
btclib's, and `fetcher.client_errors` is where every fetcher re-raises
those as btclib's. `BitcoinCoreRpcClient` and `BitcoinCoreRestClient`
are re-exported unchanged rather than wrapped, so calling them directly
raises `bitcoin-core-rpc`'s own exceptions.

`bip21.py` and `bolt11.py`/`bolt9.py` sit above every layer named here:
a BIP21 URI names an address, an amount and, through `lightning=`, a
BOLT11 invoice carrying BOLT9's feature bits, and nothing else in the
package imports them back.

## What is delegated, and what is not

Every primitive — the curve, a signature, a script, a transaction's
serialization — is btclib's; this package does not reimplement any of
it. What is here is the key-derivation and mnemonic schemes above
btclib, the formats that cross a wallet's own boundary — descriptors,
PSBTs, extended keys, mnemonics, payment URIs — the wallets that
remember what they have handed out, the one contract an external signer
answers to, and the clients that reach a node, an explorer or an
Electrum server for what the chain currently holds.
`tests/imports_test.py` mirrors the edges above, and `tests/fuzz_test.py`
and the harnesses under `fuzz/` hold every parser named here to one
contract: it fails the way the library says it fails, whatever it is
handed, never with a bare `IndexError` or `OverflowError` a caller's
`except BTClibValueError` does not catch.
