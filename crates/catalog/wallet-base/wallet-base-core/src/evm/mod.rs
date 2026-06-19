pub mod address;
pub mod tx;
pub mod rpc;

use crate::types::*;

/// EVM chain adapter (Ethereum + EVM-compatible L2s).
pub struct EvmAdapter;

impl ChainAdapter for EvmAdapter {
    fn derive_address(&self, pubkey_sec1: &[u8]) -> Result<String, AdapterError> {
        address::address_from_pubkey(pubkey_sec1)
    }
    fn build_unsigned(&self, intent: &EvmIntent, state: &ChainState) -> Result<Unsigned, AdapterError> {
        tx::build_unsigned(intent, state)
    }
    fn assemble_signed(&self, unsigned: &Unsigned, sigs: &[Secp256k1Signature]) -> Result<RawTx, AdapterError> {
        tx::assemble_signed(unsigned, sigs)
    }
    fn parse_fees(&self, resp: &RpcResponse) -> Result<FeeEstimate, AdapterError> { rpc::parse_fees(resp) }
    fn parse_simulation(&self, resp: &RpcResponse) -> Result<Simulation, AdapterError> { rpc::parse_simulation(resp) }
}
