# Security policy

## Reporting a vulnerability

If you have found a security vulnerability, please do not open a GitHub
issue: an issue is public from the moment it is filed, and so is the
window between filing it and a fix being released.

Report it privately instead, by
[opening a security advisory](https://github.com/btclib-org/btclib-wallet/security/advisories/new).
Only the maintainers can see it, the discussion stays private until an
advisory is published, and a CVE can be requested from it if the
vulnerability warrants one.

If you have no GitHub account, or would rather not use it for this,
responsible disclosure by email to *security at btclib dot org* is
equally welcome.

## What belongs here, and what belongs upstream

This package is built on [btclib](https://github.com/btclib-org/btclib),
which holds the primitives — the curve arithmetic, the signature
schemes, the codecs, scripts and transactions — and on
[bitcoin-core-rpc](https://github.com/btclib-org/bitcoin-core-rpc), which
is the client the Bitcoin Core backends of `btclib_wallet.fetch` talk
through. secp256k1 arithmetic is delegated further down, through btclib,
to [btclib-secp256k1](https://github.com/btclib-org/btclib-secp256k1) and
[libsecp256k1](https://github.com/bitcoin-core/secp256k1). A flaw in a
signature, in the curve arithmetic or in how rpc credentials are handled
most likely belongs to one of those, each with its own security policy.

What belongs here is everything this package does on top of them:

- the key derivation paths: BIP32, BIP39, Electrum mnemonics, SLIP132,
    BIP85, BIP38
- the parsing and serialization of what comes from outside — extended
    keys, output descriptors, PSBTs, payment requests — and the
    validation that decides what is accepted
- the signing boundary: the PSBT signer, the wallets, and the HWI bridge
- the node and indexer clients of `btclib_wallet.fetch`, and what each
    does with a reply
- the distributions published to PyPI and their provenance

Report it wherever you found it, though: routing a report is the
maintainers' job, not the reporter's, and a doubt about which project
owns a flaw is not a reason to keep it to yourself.

## Supported versions

Only the latest release is supported. Versions are calendar-based
(`YYYY.M.D`), a fix is published as a new release, and nothing is
backported.

Wheels and sdist are published to PyPI with PEP 740 attestations, through
a workflow that no long-lived token can authenticate for (PyPI Trusted
Publishing), so a distribution can be traced back to the workflow run and
the commit it was built from.

The same files are attached to the GitHub release, and those copies carry
a build provenance attestation of their own, signed in the run that built
them:

```shell
gh attestation verify --repo btclib-org/btclib-wallet \
  --signer-workflow btclib-org/.github/.github/workflows/reusable-attest.yml \
  <a distribution file from the release>
```

`--signer-workflow` is what makes that say which workflow signed, rather
than accepting any attestation this repository has: the signing runs in
`btclib-org/.github`'s `reusable-attest.yml`, which `release.yml` calls.
A CycloneDX bill of materials is attached beside them, generated from the
built wheel and covered by the same attestation. Either distribution file
can also be rebuilt from its tag and compared, the build being
reproducible: RELEASING.md has that command.

## Where constant time ends

These are known and inherent, and worth stating because this package is
used to teach and to prototype as much as to build.

- **The arithmetic is btclib's, and so is its notice.** Signing,
    verification, BIP32's private derivation and the silent-payment key
    agreement reach libsecp256k1 where btclib's own predicate lets them,
    through btclib or through the bindings `bip32` and `silent_payments`
    call directly, and run btclib's Python arithmetic otherwise — which
    is validated against the bindings but is not constant-time.
    Which operations cross the boundary, under which conditions, and
    what the Python path leaks is
    [btclib's SECURITY.md](https://github.com/btclib-org/btclib/blob/main/SECURITY.md),
    and this file does not restate it.
- **An install decides whether the boundary is there.**
    `pip install "btclib-wallet[secp256k1]"` installs the bindings,
    through btclib's own extra and by name; `pip install btclib-wallet`
    installs no C, and every secret then meets the Python arithmetic.
    Nothing raises to say so, and `btclib.curves.is_libsecp256k1_serving()`
    is how a caller asks which of the two it has.
- **Where this package combines secret scalars itself, the arithmetic
    is on Python integers**, variable in time with the operands, whether
    or not the bindings are installed: BIP352's sum of input keys and
    BIP38's EC-multiply factor are computed that way before the result
    reaches a btclib call. BIP32's private derivation is the exception
    that delegates: with the bindings serving, the child key is
    `secp256k1_ec_seckey_tweak_add`'s.
- **Secret material lives in Python objects**, which are immutable and
    not zeroized: an extended private key, a mnemonic or a seed stays in
    the process memory until garbage collection, and may have been
    copied by the interpreter meanwhile. `bip32._cached_base58_decode`
    extends this by one step for an xprv string handed to a derivation:
    the decoded key stays reachable from that cache, bounded by its
    `maxsize`, past whatever reference the caller itself still holds.
- **`btclib_wallet.bip38` has no MAC.** It takes AES-256 as two callables,
    for the reason btclib's `ecies` takes its cipher that way, and its
    cipher's resistance to side channels is whatever the caller passed
    in. BIP38 carries no MAC, so `decrypt` calls that cipher before it can
    tell a wrong password from a right one — the check is a re-derived
    address, compared against the record's four-byte hash only after
    decryption. `scrypt`'s cost is what BIP38 relies on to make each guess
    expensive.
- **Randomness comes from the operating system** through the `secrets`
    module, and nothing here seeds a generator of its own.

## A backend is trusted, and not every backend alike

- **Each `btclib_wallet.fetch` backend asks by default which chain it is
    talking to**, through `verify_network`, and they do not ask the same
    question. The Bitcoin Core backends talk to a node that validated the
    chain it reports, and `signet_challenge` holds them to one signet;
    `-rest` authenticates nobody who reaches it, so that endpoint is
    trusted on whoever handed it over. `EsploraFetcher` and
    `ElectrumFetcher` talk to a host that says it validated, and compare
    the genesis block against the one the network names, which cannot
    tell two signets apart.
- **The answers a fetch makes are checked to different degrees.** A
    transaction's id is recomputed from the bytes that came back and
    refused unless it matches, and an output's amount is derived from
    that same transaction. A block header is parsed and checked for a
    real proof of work, which says it cost real work and not that it is
    the header at the height asked for. A height, and the tip hash from
    every backend but `ElectrumFetcher`, rest on the backend's word.
- **`ElectrumFetcher` is the one backend that can prove an answer.**
    `get_tx_merkle` and `verify_tx` check a transaction's branch against
    a header the fetcher fetched itself, so a caller who runs the check
    learns that the transaction is in the block that header names. That
    is the trade the Esplora backend's fallback makes: it cannot say a
    transaction is confirmed. `TlsLineTransport` verifies the server's
    certificate and host name by default.
- **An explorer learns every txid and outpoint you look up**, which is a
    good deal of what a wallet is. A public deployment is named as a
    constant and never as a default, so nothing here contacts anyone
    until a caller writes the endpoint down. `Broadcaster.broadcast`
    checks that the backend named the txid this code computed, and
    nothing checks that the transaction went on to propagate.
