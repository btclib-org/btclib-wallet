// Copyright (c) The btclib developers
// Distributed under the MIT software license, see the accompanying
// LICENSE file or https://opensource.org/license/mit for the full text.

// Command sign_bip373 signs BIP373's participants-only psbts with btcd.
//
// It is built inside the psbt module of btcsuite/btcd#2198, reads that
// module's copy of the BIP373 vectors, and prints as JSON each psbt that
// carries participant public keys only, once all three participants have
// added a public nonce and a partial signature. Every step is btcd's:
// MuSig2SigningInfos says what to sign, musig2 makes the nonces and the
// signatures, and the Updater writes them into the psbt. The nonces are
// random, so each run prints different signatures.
// tests/_data/README.md has the commands that run it.
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/btcsuite/btcd/psbt/v2"
)

// the private keys BIP373 publishes for its participants, as hex
var participantPrvKeys = []string{
	"9e3d0fd1845e73fc5eb4202c047631e9bd45aee639c93de0e21ef7efe1100812",
	"754f619cf0f5a9cce70168bb4ea613804e53e4c2487a967d1e2564cf8007ad25",
	"0000000000000000000000000000000000000000000000000000000000000003",
}

type vector struct {
	Name  string `json:"name"`
	Hex   string `json:"hex"`
	Valid bool   `json:"valid"`
}

type signed struct {
	Description string `json:"description"`
	EncodedPsbt string `json:"encoded psbt"`
}

func sign(p *psbt.Packet, privs []*btcec.PrivateKey) error {
	for inIndex := range p.Inputs {
		infos := make([]*psbt.MuSig2SigningInfo, len(privs))
		secNonces := make([][musig2.SecNonceSize]byte, len(privs))
		pubNonces := make([][musig2.PubNonceSize]byte, len(privs))
		for i, priv := range privs {
			found, err := psbt.MuSig2SigningInfos(p, inIndex, priv.PubKey())
			if err != nil {
				return err
			}
			if len(found) != 1 {
				return fmt.Errorf("input %d: %d contexts", inIndex, len(found))
			}
			infos[i] = found[0]
			nonces, err := musig2.GenNonces(musig2.WithPublicKey(priv.PubKey()))
			if err != nil {
				return err
			}
			secNonces[i] = nonces.SecNonce
			pubNonces[i] = nonces.PubNonce
		}
		aggNonce, err := musig2.AggregateNonces(pubNonces)
		if err != nil {
			return err
		}
		updater, err := psbt.NewUpdater(p)
		if err != nil {
			return err
		}
		for i, priv := range privs {
			err := updater.AddInMuSig2PubNonce(inIndex, &psbt.MuSig2PubNonce{
				PubKey:       priv.PubKey(),
				AggregateKey: infos[i].ContextKey,
				TapLeafHash:  infos[i].TapLeafHash,
				PubNonce:     pubNonces[i],
			})
			if err != nil {
				return err
			}
		}
		for i, priv := range privs {
			var opts []musig2.SignOption
			if len(infos[i].Tweaks) > 0 {
				opts = append(opts, musig2.WithTweaks(infos[i].Tweaks...))
			}
			keys := append([]*btcec.PublicKey(nil), infos[i].Participants.Keys...)
			partialSig, err := musig2.Sign(
				secNonces[i], priv, aggNonce, keys, infos[i].SigHash, opts...,
			)
			if err != nil {
				return err
			}
			outcome, err := updater.SignMuSig2(inIndex, &psbt.MuSig2PartialSig{
				PubKey:       priv.PubKey(),
				AggregateKey: infos[i].ContextKey,
				TapLeafHash:  infos[i].TapLeafHash,
				PartialSig:   *partialSig,
			})
			if err != nil {
				return err
			}
			if outcome != psbt.SignSuccesful {
				return fmt.Errorf("input %d: sign outcome %d", inIndex, outcome)
			}
		}
	}
	return nil
}

func run(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var vectors []vector
	if err := json.Unmarshal(data, &vectors); err != nil {
		return err
	}
	privs := make([]*btcec.PrivateKey, len(participantPrvKeys))
	for i, key := range participantPrvKeys {
		raw, err := hex.DecodeString(key)
		if err != nil {
			return err
		}
		privs[i], _ = btcec.PrivKeyFromBytes(raw)
	}
	var out []signed
	for _, v := range vectors {
		if !v.Valid || !strings.HasSuffix(v.Name, "participant pubkeys only") {
			continue
		}
		raw, err := hex.DecodeString(v.Hex)
		if err != nil {
			return err
		}
		p, err := psbt.NewFromRawBytes(bytes.NewReader(raw), false)
		if err != nil {
			return err
		}
		if err := sign(p, privs); err != nil {
			return fmt.Errorf("%s: %w", v.Name, err)
		}
		encoded, err := p.B64Encode()
		if err != nil {
			return err
		}
		out = append(out, signed{v.Name, encoded})
	}
	text, err := json.MarshalIndent(map[string][]signed{"signed psbts": out}, "", "    ")
	if err != nil {
		return err
	}
	_, err = fmt.Println(string(text))
	return err
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sign_bip373 <bip-373-test-vectors.json>")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
