//! Pure, host-testable core for the wallet-base catalog service.
//!
//! No I/O, no `boogy-sdk` dependency: chain-agnostic transaction types plus
//! per-chain adapters that build/encode transactions in EXTERNAL-SIGNER mode —
//! the private key lives in credops and never enters this crate or the wasm.
//!
//! # External-signer flow
//!
//! ```ignore
//! use wallet_base_core::evm::EvmAdapter;
//! use wallet_base_core::types::*;
//!
//! let adapter = EvmAdapter;
//! let unsigned = ChainAdapter::build_unsigned(&adapter, &intent, &state)?;
//! // The private key lives in credops, never here:
//! //   let sig = signing_sign_digest(label, digest_from(&unsigned), Secp256k1);
//! let raw = ChainAdapter::assemble_signed(&adapter, &unsigned, &[sig])?;
//! // broadcast raw.to_hex() via outbound_http
//! ```
pub mod types;
pub mod evm;
pub mod cosmos;
pub mod solana;
pub mod btc;
pub mod subject;
pub mod guardrails;
pub mod nonce;

pub use types::secp_sig_from_compact;
