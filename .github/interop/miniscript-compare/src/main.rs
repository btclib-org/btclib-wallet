// Copyright (c) The btclib developers
// Distributed under the MIT software license, see the accompanying
// LICENSE file or https://opensource.org/license/mit for the full text.

//! Reads descriptors off stdin and prints what rust-miniscript makes of each.
//!
//! Each input line is the hex of one descriptor's bytes, so that any octet
//! reaches the parser and no newline splits an input. Each output line is
//! five tab-separated fields, in the order of the input:
//!
//! 1. the index of the input line, from 0;
//! 2. `accepted` where the parser read the descriptor, else `refused`;
//! 3. the hex of the scriptPubKey at derivation index 0, else `-`;
//! 4. the mainnet address of that script, else `-`;
//! 5. the hex of the error message, else `-`: the parser's where it refused,
//!    the derivation's or the address's where it accepted and one failed.
//!
//! A descriptor with several derivation paths is read at its first. Each
//! input runs on a thread of its own with a large stack, and a panic is
//! printed as a refusal that says so.

use std::io::{self, BufRead, Write};
use std::panic;
use std::thread;

use miniscript::bitcoin::secp256k1::Secp256k1;
use miniscript::bitcoin::Network;
use miniscript::{Descriptor, DescriptorPublicKey};

const STACK: usize = 256 * 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn unhex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).ok())
        .collect()
}

/// The four fields after the index.
fn read(bytes: Vec<u8>) -> [String; 4] {
    let refused = |message: String| {
        [
            "refused".to_string(),
            "-".to_string(),
            "-".to_string(),
            hex(message.as_bytes()),
        ]
    };
    let Ok(text) = String::from_utf8(bytes) else {
        return refused("not UTF-8".to_string());
    };
    let secp = Secp256k1::new();
    let descriptor = match Descriptor::<DescriptorPublicKey>::parse_descriptor(&secp, &text) {
        Ok((descriptor, _keys)) => descriptor,
        Err(error) => return refused(error.to_string()),
    };
    let accepted = |script: String, address: String, message: String| {
        ["accepted".to_string(), script, address, message]
    };
    let single = match descriptor.into_single_descriptors() {
        Ok(mut all) => all.remove(0),
        Err(error) => return accepted("-".into(), "-".into(), hex(error.to_string().as_bytes())),
    };
    let definite = match single.derive_at_index(0).or_fallback() {
        Ok(definite) => definite,
        Err(error) => return accepted("-".into(), "-".into(), hex(error.to_string().as_bytes())),
    };
    let derived = definite.derived_descriptor(&secp);
    let script = hex(derived.script_pubkey().as_bytes());
    match derived.address(Network::Bitcoin) {
        Ok(address) => accepted(script, address.to_string(), "-".into()),
        Err(error) => accepted(script, "-".into(), hex(error.to_string().as_bytes())),
    }
}

fn run(bytes: Vec<u8>) -> [String; 4] {
    let handle = thread::Builder::new()
        .stack_size(STACK)
        .spawn(move || read(bytes))
        .expect("a thread");
    match handle.join() {
        Ok(fields) => fields,
        Err(_) => [
            "refused".to_string(),
            "-".to_string(),
            "-".to_string(),
            hex(b"panic"),
        ],
    }
}

fn main() {
    // a panic is reported through its field, not on stderr once per input
    panic::set_hook(Box::new(|_| {}));
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut out = stdout.lock();
    for (index, line) in stdin.lock().lines().enumerate() {
        let line = line.expect("a line of stdin");
        let fields = match unhex(line.trim()) {
            Some(bytes) => run(bytes),
            None => [
                "refused".to_string(),
                "-".to_string(),
                "-".to_string(),
                hex(b"input is not hex"),
            ],
        };
        writeln!(out, "{index}\t{}", fields.join("\t")).expect("stdout");
        out.flush().expect("stdout");
    }
}
