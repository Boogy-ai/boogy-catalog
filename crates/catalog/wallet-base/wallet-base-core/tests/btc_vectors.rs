//! Bitcoin P2WPKH adapter — address KAT + build_unsigned/assemble_signed
//! round-trip + adversarial coverage. External-signer mode throughout: no
//! private key, no local signing — sighashes go out, signatures come back in.

use wallet_base_core::btc::{BtcAdapter, BtcIntent, BtcNetwork, Utxo};
use wallet_base_core::types::{RawTx, Secp256k1Signature, SignRequest, Unsigned};

// ---------------------------------------------------------------------------
// Task 1 — P2WPKH address KAT + adversarial
// ---------------------------------------------------------------------------

/// Authoritative spike vector: this compressed pubkey derives this mainnet
/// P2WPKH address (`bc1q…`). Exact, pinned.
const PUBKEY_HEX: &str = "033bc8c83c52df5712229a2f72206d90192366c36428cb0c12b6af98324d97bfbc";
const ADDR_MAINNET: &str = "bc1qvzvkjn4q3nszqxrv3nraga2r822xjty3ykvkuw";

fn pubkey_bytes() -> Vec<u8> {
    hex::decode(PUBKEY_HEX).unwrap()
}

#[test]
fn btc_address_kat_mainnet() {
    let addr = BtcAdapter::address_from_pubkey(&pubkey_bytes(), BtcNetwork::Mainnet).unwrap();
    assert_eq!(addr, ADDR_MAINNET, "P2WPKH mainnet address KAT");
}

#[test]
fn btc_address_testnet_uses_tb1q_hrp() {
    let addr = BtcAdapter::address_from_pubkey(&pubkey_bytes(), BtcNetwork::Testnet).unwrap();
    assert!(addr.starts_with("tb1q"), "testnet HRP, got {addr}");
    // Same witness program, different HRP → different string from mainnet.
    assert_ne!(addr, ADDR_MAINNET);
}

#[test]
fn btc_address_rejects_uncompressed_pubkey() {
    // 65-byte uncompressed (0x04 || X || Y) — P2WPKH is undefined for these.
    let uncompressed = [0x04u8; 65];
    assert!(BtcAdapter::address_from_pubkey(&uncompressed, BtcNetwork::Mainnet).is_err());
}

#[test]
fn btc_address_rejects_short_pubkey() {
    let thirty_two = [0x02u8; 32];
    assert!(BtcAdapter::address_from_pubkey(&thirty_two, BtcNetwork::Mainnet).is_err());
}

#[test]
fn btc_address_rejects_empty_pubkey() {
    assert!(BtcAdapter::address_from_pubkey(&[], BtcNetwork::Mainnet).is_err());
}

// ---------------------------------------------------------------------------
// Task 2 — build_unsigned + coin-select + assemble_signed + round-trip
// ---------------------------------------------------------------------------

fn utxo(txid_last_byte: u8, value: u64) -> Utxo {
    let mut t = String::from("00000000000000000000000000000000000000000000000000000000000000");
    t.push_str(&format!("{txid_last_byte:02x}"));
    Utxo { txid: t, vout: 0, value_sat: value }
}

/// Fixed single-input fixture (1 UTXO of 100_000 sat, send 50_000 @ 1 sat/vB).
/// build_unsigned must reproduce the pinned BIP143 sighash snapshot exactly.
fn fixture_intent() -> BtcIntent {
    BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 100_000)],
    }
}

/// Pinned BIP143 sighash for `fixture_intent()`'s single input — a stability
/// snapshot (deterministic given the fixed tx + prevout value). Captured on the
/// first green run; locks the BIP143 preimage construction across `bitcoin` revs.
const SIGHASH_SNAPSHOT: &str =
    "8a581d7d027276b61d5e7c265e92228be5f42938ed3f03b97ff208ace46ccb68";

#[test]
fn btc_build_unsigned_matches_sighash_snapshot() {
    let u = BtcAdapter::build_unsigned(&fixture_intent()).unwrap();
    assert_eq!(u.sign_requests.len(), 1, "one input → one sighash");
    let hex_digest = match &u.sign_requests[0] {
        SignRequest::Digest(d) => hex::encode(d),
        other => panic!("expected Digest, got {other:?}"),
    };
    assert_eq!(
        hex_digest, SIGHASH_SNAPSHOT,
        "BIP143 sighash changed (or snapshot not yet captured)"
    );
}

/// A valid compact secp256k1 signature for structural round-trip tests.
/// `Signature::from_compact` validates r and s are in-range scalars; r=1, s=1
/// are valid, so this exercises the full assemble path without a real signer.
fn valid_dummy_sig() -> Secp256k1Signature {
    let mut r = [0u8; 32];
    r[31] = 1;
    let mut s = [0u8; 32];
    s[31] = 1;
    Secp256k1Signature { r, s, recovery_id: 0 }
}

/// Deterministic test private key. assemble_signed now self-verifies each
/// signature against its BIP143 sighash (#7), so round-trip tests must produce
/// REAL signatures from a key whose pubkey is the intent's `from_pubkey_hex`.
fn test_sk() -> bitcoin::secp256k1::SecretKey {
    bitcoin::secp256k1::SecretKey::from_slice(&[0x42u8; 32]).unwrap()
}

/// The compressed-pubkey hex for [`test_sk`] — use as `from_pubkey_hex`.
fn test_pubkey_hex() -> String {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &test_sk());
    hex::encode(pk.serialize())
}

/// Sign every per-input sighash of `u` with [`test_sk`] — real, low-S sigs.
fn sign_all(u: &Unsigned) -> Vec<Secp256k1Signature> {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = test_sk();
    u.sign_requests
        .iter()
        .map(|sr| {
            let d = match sr {
                SignRequest::Digest(d) => *d,
                other => panic!("expected Digest, got {other:?}"),
            };
            let msg = bitcoin::secp256k1::Message::from_digest(d);
            let c = secp.sign_ecdsa(&msg, &sk).serialize_compact();
            let mut r = [0u8; 32];
            r.copy_from_slice(&c[0..32]);
            let mut s = [0u8; 32];
            s.copy_from_slice(&c[32..64]);
            Secp256k1Signature { r, s, recovery_id: 0 }
        })
        .collect()
}

#[test]
fn btc_single_input_roundtrips() {
    let intent = BtcIntent { from_pubkey_hex: test_pubkey_hex(), ..fixture_intent() };
    let u = BtcAdapter::build_unsigned(&intent).unwrap();
    assert_eq!(u.sign_requests.len(), 1);
    let raw: RawTx = BtcAdapter::assemble_signed(&u, &sign_all(&u)).unwrap();

    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw.0).unwrap();
    assert_eq!(tx.input.len(), 1, "one input survives");
    // Witness is [der_sig||sighash_type, compressed_pubkey].
    let w = &tx.input[0].witness;
    assert_eq!(w.len(), 2, "P2WPKH witness = [sig, pubkey]");
    // Outputs: recipient + change (100_000 > 50_000 + small fee).
    assert_eq!(tx.output.len(), 2, "recipient + change");
}

#[test]
fn btc_multi_input_roundtrips() {
    // Two UTXOs of 40_000 each (80_000 total); send 50_000 → both inputs needed.
    let intent = BtcIntent {
        from_pubkey_hex: test_pubkey_hex(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 40_000), utxo(0x02, 40_000)],
    };
    let u = BtcAdapter::build_unsigned(&intent).unwrap();
    assert_eq!(u.sign_requests.len(), 2, "two inputs → two sighashes");
    // The two sighashes differ (different prevout outpoint + value position).
    if let (SignRequest::Digest(a), SignRequest::Digest(b)) =
        (&u.sign_requests[0], &u.sign_requests[1])
    {
        assert_ne!(a, b, "per-input sighashes are distinct");
    } else {
        panic!("expected two Digest sign_requests");
    }

    let sigs = sign_all(&u);
    let raw = BtcAdapter::assemble_signed(&u, &sigs).unwrap();

    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw.0).unwrap();
    assert_eq!(tx.input.len(), 2, "two inputs survive");
    for (i, txin) in tx.input.iter().enumerate() {
        assert_eq!(txin.witness.len(), 2, "input {i} witness = [sig, pubkey]");
    }
}

#[test]
fn btc_coinselect_picks_enough_and_computes_change() {
    // Send 10_000 from a 100_000 UTXO → 1 input, non-dust change → 2 outputs.
    let intent = BtcIntent {
        from_pubkey_hex: test_pubkey_hex(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 10_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 100_000)],
    };
    let u = BtcAdapter::build_unsigned(&intent).unwrap();
    let raw = BtcAdapter::assemble_signed(&u, &sign_all(&u)).unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw.0).unwrap();
    assert_eq!(tx.output.len(), 2, "recipient + non-dust change");
    // Recipient output value is exactly the requested amount.
    assert_eq!(tx.output[0].value.to_sat(), 10_000);
    // Change output is non-dust.
    assert!(tx.output[1].value.to_sat() >= 294, "non-dust change");
}

#[test]
fn btc_dust_change_folded_into_fee_no_change_output() {
    // amount + fee leaves only dust as residue → no change output (1 output).
    // 1 input, 1 output vsize = 11 + 68 + 31 = 110; fee@1 = 110.
    // total = 10_000 + 110 + 293 (dust-1) = 10_403.
    let intent = BtcIntent {
        from_pubkey_hex: test_pubkey_hex(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 10_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 10_403)],
    };
    let u = BtcAdapter::build_unsigned(&intent).unwrap();
    let raw = BtcAdapter::assemble_signed(&u, &sign_all(&u)).unwrap();
    let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw.0).unwrap();
    assert_eq!(tx.output.len(), 1, "dust change folded into fee → no change output");
    assert_eq!(tx.output[0].value.to_sat(), 10_000, "recipient only");
}

// --- Adversarial ---

#[test]
fn btc_insufficient_funds_errs() {
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 5_000)],
    };
    assert!(BtcAdapter::build_unsigned(&intent).is_err());
}

#[test]
fn btc_empty_utxos_errs() {
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: ADDR_MAINNET.into(),
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![],
    };
    assert!(BtcAdapter::build_unsigned(&intent).is_err());
}

#[test]
fn btc_wrong_sig_count_errs() {
    // 1 input → assembling with 0 or 2 sigs must fail closed.
    let u = BtcAdapter::build_unsigned(&fixture_intent()).unwrap();
    assert_eq!(u.sign_requests.len(), 1);
    assert!(BtcAdapter::assemble_signed(&u, &[]).is_err(), "N-1 sigs");
    assert!(
        BtcAdapter::assemble_signed(&u, &[valid_dummy_sig(), valid_dummy_sig()]).is_err(),
        "N+1 sigs"
    );
}

#[test]
fn btc_wrong_network_to_address_errs() {
    // Mainnet intent, but a testnet (tb1q…) destination → reject.
    let testnet_addr =
        BtcAdapter::address_from_pubkey(&pubkey_bytes(), BtcNetwork::Testnet).unwrap();
    let intent = BtcIntent {
        from_pubkey_hex: PUBKEY_HEX.into(),
        network: BtcNetwork::Mainnet,
        to_address: testnet_addr,
        amount_sat: 50_000,
        fee_rate_sat_vb: 1,
        utxos: vec![utxo(0x01, 100_000)],
    };
    assert!(BtcAdapter::build_unsigned(&intent).is_err(), "wrong-network to_address");
}

#[test]
fn btc_garbage_to_address_errs() {
    let mut intent = fixture_intent();
    intent.to_address = "not-an-address".into();
    assert!(BtcAdapter::build_unsigned(&intent).is_err());
}

#[test]
fn btc_zero_and_dust_amount_rejected() {
    // #11: a zero / sub-dust recipient amount is rejected at build time, BEFORE
    // the key is touched — it would only ever produce an unbroadcastable
    // (non-standard dust) tx while consuming a daily-spend slot.
    let zero = BtcIntent { amount_sat: 0, ..fixture_intent() };
    assert!(BtcAdapter::build_unsigned(&zero).is_err(), "zero amount rejected");
    let dust = BtcIntent { amount_sat: 293, ..fixture_intent() };
    assert!(BtcAdapter::build_unsigned(&dust).is_err(), "sub-dust amount rejected");
    // At the dust threshold (294) it builds.
    let ok = BtcIntent { amount_sat: 294, ..fixture_intent() };
    assert!(BtcAdapter::build_unsigned(&ok).is_ok(), "at-dust-threshold amount builds");
}

// ---------------------------------------------------------------------------
// Known answers from the BIPs
// ---------------------------------------------------------------------------

/// BIP-173, "Examples": public key `0279BE66…1798` gives these P2WPKH
/// addresses.
#[test]
fn btc_p2wpkh_addresses_match_bip173() {
    let pk = hex::decode("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798").unwrap();
    assert_eq!(BtcAdapter::address_from_pubkey(&pk, BtcNetwork::Mainnet).unwrap(), "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    assert_eq!(BtcAdapter::address_from_pubkey(&pk, BtcNetwork::Testnet).unwrap(), "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
}

/// BIP-143, "Native P2WPKH": the second input spends a P2WPKH output of 6 BTC.
/// Our sighash is the BIP's, the BIP's signature passes our self-verify, and
/// splicing it (with the BIP's P2PK scriptSig on input 0) gives the BIP's
/// serialized signed transaction.
#[test]
fn btc_p2wpkh_sighash_and_signed_tx_match_bip143() {
    use bitcoin::consensus::{deserialize, serialize};
    let unsigned_hex = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
    let signed_hex = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";
    let input0_script_sig = "4830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01";
    let pubkey_hex = "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357";
    let der_sig = "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee";

    let mut tx: bitcoin::Transaction = deserialize(&hex::decode(unsigned_hex).unwrap()).unwrap();
    let cpk = bitcoin::CompressedPublicKey::from_slice(&hex::decode(pubkey_hex).unwrap()).unwrap();
    let digest = wallet_base_core::btc::p2wpkh_sighash(&tx, 1, &cpk, 600_000_000).unwrap();
    assert_eq!(hex::encode(digest), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");

    let compact = bitcoin::secp256k1::ecdsa::Signature::from_der(&hex::decode(der_sig).unwrap()).unwrap().serialize_compact();
    let sig = Secp256k1Signature { r: compact[..32].try_into().unwrap(), s: compact[32..].try_into().unwrap(), recovery_id: 0 };
    tx.input[0].script_sig = bitcoin::ScriptBuf::from_bytes(hex::decode(input0_script_sig).unwrap());
    wallet_base_core::btc::splice_p2wpkh_signature(&mut tx, 1, &sig, &cpk.0, &digest).unwrap();
    assert_eq!(hex::encode(serialize(&tx)), signed_hex);
}

/// BIP-350, "Test vectors": every valid mainnet/testnet address is a legal
/// recipient on its own network and parses to the BIP's scriptPubKey; every
/// invalid one is refused on either network.
#[test]
fn btc_recipient_addresses_match_bip350() {
    use wallet_base_core::btc::recipient_script_pubkey;
    let valid = [
        ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
        ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
        ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
        ("BC1SW50QGDZ25J", "6002751e"),
        ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"),
        ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
        ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
        ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    ];
    for (addr, spk) in valid {
        let net = if addr.to_ascii_lowercase().starts_with("bc1") { BtcNetwork::Mainnet } else { BtcNetwork::Testnet };
        let got = recipient_script_pubkey(addr, net).unwrap_or_else(|e| panic!("{addr}: {e:?}"));
        assert_eq!(hex::encode(got.as_bytes()), spk, "{addr}");
    }
    let invalid = [
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
        "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
        "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
        "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
        "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
        "bc1pw5dgrnzv",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        "bc1gmk9yu",
    ];
    for addr in invalid {
        for net in [BtcNetwork::Mainnet, BtcNetwork::Testnet] {
            assert!(recipient_script_pubkey(addr, net).is_err(), "{addr} must be refused on {net:?}");
        }
    }
}

/// BIP-341 `wallet-test-vectors.json` (bitcoin/bips, `bip-0341/`, vendored
/// verbatim as `tests/vectors/bip341-wallet-test-vectors.json`), at the
/// dependency: the adapter builds P2WPKH only, so these pin the `bitcoin`
/// crate's taproot key-path sighash and P2TR addresses ahead of a bump.
fn bip341() -> serde_json::Value {
    serde_json::from_str(include_str!("vectors/bip341-wallet-test-vectors.json")).unwrap()
}

#[test]
fn btc_taproot_key_path_sighashes_match_bip341() {
    use bitcoin::sighash::{Prevouts, SighashCache, TapSighashType};
    use bitcoin::hashes::Hash as _;
    let v = bip341();
    let mut checked = 0;
    for case in v["keyPathSpending"].as_array().unwrap() {
        let tx: bitcoin::Transaction =
            bitcoin::consensus::deserialize(&hex::decode(case["given"]["rawUnsignedTx"].as_str().unwrap()).unwrap()).unwrap();
        let prevouts: Vec<bitcoin::TxOut> = case["given"]["utxosSpent"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(u["amountSats"].as_u64().unwrap()),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(hex::decode(u["scriptPubKey"].as_str().unwrap()).unwrap()),
            })
            .collect();
        for input in case["inputSpending"].as_array().unwrap() {
            let index = input["given"]["txinIndex"].as_u64().unwrap() as usize;
            let hash_type = TapSighashType::from_consensus_u8(input["given"]["hashType"].as_u64().unwrap() as u8).unwrap();
            let got = SighashCache::new(&tx).taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), hash_type).unwrap();
            assert_eq!(hex::encode(got.to_byte_array()), input["intermediary"]["sigHash"].as_str().unwrap(), "input {index}");
            checked += 1;
        }
    }
    assert_eq!(checked, 7, "every key-path input in the file");
}

#[test]
fn btc_p2tr_addresses_match_bip341() {
    use bitcoin::secp256k1::{Secp256k1, XOnlyPublicKey};
    use bitcoin::hashes::Hash as _;
    use bitcoin::taproot::TapNodeHash;
    let secp = Secp256k1::verification_only();
    let v = bip341();
    let cases = v["scriptPubKey"].as_array().unwrap();
    for case in cases {
        let internal = XOnlyPublicKey::from_slice(&hex::decode(case["given"]["internalPubkey"].as_str().unwrap()).unwrap()).unwrap();
        let merkle_root = case["intermediary"]["merkleRoot"]
            .as_str()
            .map(|h| TapNodeHash::from_slice(&hex::decode(h).unwrap()).unwrap());
        let addr = bitcoin::Address::p2tr(&secp, internal, merkle_root, bitcoin::KnownHrp::Mainnet);
        assert_eq!(addr.to_string(), case["expected"]["bip350Address"].as_str().unwrap());
        assert_eq!(hex::encode(addr.script_pubkey().as_bytes()), case["expected"]["scriptPubKey"].as_str().unwrap());
    }
    assert_eq!(cases.len(), 7);
}
