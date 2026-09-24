# btclib-wallet

From a seed to a signed, broadcast bitcoin transaction, on top of the
btclib library.

<!-- The badges are what the reader decides with, in three groups: what the
software is and whether it can be used, whether it works, and what the
OpenSSF makes of it.

Inside the second group the gates come first, in the order a commit meets
them, and the sentinels follow in the order section 10 of the organization
standard schedules them -- the badge order *is* the calendar order over
that subset, which is why the two move together or not at all. The day and
hour each sentinel owns live in that section and are not copied here: a
reader wanting the schedule reads it there, where it is still true.

One badge per line keeps a change to one line and every line inside MD013,
whose 80 columns bind only where a space follows them.

A badge that reports no state -- "we use ruff", "we use uv" -- reports a
choice instead, and those are in CONTRIBUTING.md, beside the prose that
says how the choice is enforced.
-->
[![PyPI version](https://img.shields.io/pypi/v/btclib-wallet.svg?logo=pypi)](https://pypi.org/project/btclib-wallet/)
[![GitHub release](https://img.shields.io/github/v/release/btclib-org/btclib-wallet.svg)](https://github.com/btclib-org/btclib-wallet/releases)
[![development status](https://img.shields.io/pypi/status/btclib-wallet.svg)](https://pypi.org/project/btclib-wallet/)
[![license](https://img.shields.io/github/license/btclib-org/btclib-wallet.svg)](https://github.com/btclib-org/btclib-wallet/blob/main/LICENSE)
[![downloads](https://static.pepy.tech/badge/btclib-wallet)](https://pepy.tech/projects/btclib-wallet)
[![supported Python versions](https://img.shields.io/pypi/pyversions/btclib-wallet.svg?logo=python)](https://pypi.org/project/btclib-wallet/)
[![implementation](https://img.shields.io/pypi/implementation/btclib-wallet.svg)](https://pypi.org/project/btclib-wallet/)
[![wheel](https://img.shields.io/pypi/wheel/btclib-wallet.svg)](https://pypi.org/project/btclib-wallet/)

[![pre-commit.ci status](https://results.pre-commit.ci/badge/github/btclib-org/btclib-wallet/main.svg)](https://results.pre-commit.ci/latest/github/btclib-org/btclib-wallet/main)
[![lint workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/lint.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/lint.yml?query=branch%3Amain)
[![test workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/test.yml?query=branch%3Amain)
[![docs workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/docs.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/docs.yml?query=branch%3Amain)
[![documentation build](https://app.readthedocs.org/projects/btclib-wallet/badge/?version=latest)](https://btclib-wallet.readthedocs.io)
[![vendored-vectors workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/vendored-vectors.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/vendored-vectors.yml?query=branch%3Amain)
[![mutation workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/mutation.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/mutation.yml?query=branch%3Amain)
[![fuzz workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/fuzz.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/fuzz.yml?query=branch%3Amain)
[![integration-bitcoind workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/integration-bitcoind.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/integration-bitcoind.yml?query=branch%3Amain)
[![integration-hwi workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/integration-hwi.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/integration-hwi.yml?query=branch%3Amain)
[![deps-latest workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/deps-latest.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/deps-latest.yml?query=branch%3Amain)
[![pypi-install workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/pypi-install.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/pypi-install.yml?query=branch%3Amain)
[![deps-oldest workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/deps-oldest.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/deps-oldest.yml?query=branch%3Amain)
[![os-macos workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/os-macos.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/os-macos.yml?query=branch%3Amain)
[![os-ubuntu workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/os-ubuntu.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/os-ubuntu.yml?query=branch%3Amain)
[![os-windows workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/os-windows.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/os-windows.yml?query=branch%3Amain)
[![links workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/links.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/links.yml?query=branch%3Amain)
[![sdist-rebuild workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/sdist-rebuild.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/sdist-rebuild.yml?query=branch%3Amain)
[![codeql workflow status](https://github.com/btclib-org/btclib-wallet/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/btclib-org/btclib-wallet/actions/workflows/codeql.yml?query=branch%3Amain)

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/btclib-org/btclib-wallet/badge)](https://scorecard.dev/viewer/?uri=github.com/btclib-org/btclib-wallet)

[btclib](https://github.com/btclib-org/btclib) is the protocol: the
encodings, the scripts, the transactions and the signature schemes, what
a node consumes. This package is what a wallet does with them, and every
module with a counterparty outside the process — a device, a node, a
server, a file from another wallet. It depends on btclib and on
[bitcoin-core-rpc](https://github.com/btclib-org/bitcoin-core-rpc), and
re-exports nothing of btclib's: a name btclib defines is imported from
btclib.

It is fully annotated and ships `py.typed`, and the test suite answers
to vectors their authors publish: the BIPs' and the SLIPs' own, HWI's, and
trezor's for BIP39 and SLIP39. `tests/_data/README.md` pins each vendored
file to the upstream commit it was copied from, and says whether the two
still match.

## Installing

```shell
python -m pip install --upgrade btclib-wallet
```

Signing and verifying run where btclib runs them, so its
[libsecp256k1 bindings](https://github.com/btclib-org/btclib-secp256k1)
are the recommended install beside it, and btclib's
[SECURITY.md](https://github.com/btclib-org/btclib/blob/main/SECURITY.md)
says what happens without them.

## An address from a mnemonic

```python
from btclib_wallet import bip44
from btclib_wallet.mnemonic import bip39

words = "abandon " * 11 + "about"
xprv = bip39.mxprv_from_mnemonic(words)
assert (
    bip44.address_from_der_path(xprv, "m/84h/0h/0h/0/0")
    == "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
)
```

The address is the first one BIP84 lists for that mnemonic.

## What is here

- [BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
  hierarchical deterministic key chains, and
  [SLIP132](https://github.com/satoshilabs/slips/blob/master/slip-0132.md)
  key versions with their mapping to address types
- [BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki),
  [Electrum](https://electrum.org/#home) and
  [SLIP39](https://github.com/satoshilabs/slips/blob/master/slip-0039.md)
  mnemonics, and the seed-to-key functions over them
- [BIP44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
  addresses from an extended key and a
  `m/purpose'/coin_type'/account'/change/address_index` path
- [BIP85](https://github.com/bitcoin/bips/blob/master/bip-0085.mediawiki)
  deterministic entropy, one root key behind many wallets
- [BIP38](https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki)
  password-protected private keys, and Casascius minikeys
- [BIP380](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki)
  output descriptors and
  [BIP379](https://github.com/bitcoin/bips/blob/master/bip-0379.md)
  miniscript
- [BIP174](https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
  and [BIP370](https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki)
  partially signed transactions, with the taproot, MuSig2, FROST and
  silent payment fields
- [BIP352](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
  silent payments
- [BIP322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)
  signed messages
- [BIP21](https://github.com/bitcoin/bips/blob/master/bip-0021.mediawiki)
  payment URIs, and the BOLT11 invoices and BOLT9 feature bits they carry
- coin selection and a transaction builder
- wallets: an extended key at a BIP44 account, a set of individual keys,
  an output descriptor per chain, a script template
- an external signer behind one contract, with Bitcoin Core's
  [HWI](https://github.com/bitcoin-core/HWI) behind it for a hardware
  wallet, and the requests that import a wallet into Bitcoin Core
- a chain backend behind one interface, over a full node's JSON-RPC or a
  block explorer's or an Electrum server's API

## Security

A mnemonic, an extended private key and a PSBT being signed are secrets,
and where they are handled is this package. [SECURITY.md](./SECURITY.md)
says what that promises, where constant time ends, and how to report a
vulnerability.

## Contributing

[CONTRIBUTING.md](./CONTRIBUTING.md) has the commands each CI job runs,
verbatim. `uv sync` creates the environment; uv is the only tool that has
to be installed. [REVIEWING.md](./REVIEWING.md) is what a pull request is
answered against.

## Links

- Documentation: <https://btclib-wallet.readthedocs.io/>
- Source: <https://github.com/btclib-org/btclib-wallet>
- Releases: <https://github.com/btclib-org/btclib-wallet/releases>
- [CHANGELOG.md](./CHANGELOG.md), and [RELEASE_NOTES.md](./RELEASE_NOTES.md)
  for what a release asks a user to act on

---

The btclib organization and its projects are actively supported by
[DGI](https://dgi.io) and [CheckSig](https://checksig.com).
