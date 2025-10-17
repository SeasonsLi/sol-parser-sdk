//! Nonce Account 解析
//!
//! 提供 Nonce Account 的解析功能

use crate::core::events::{EventMetadata, NonceAccountEvent};
use crate::DexEvent;
use solana_account_decoder::parse_nonce::parse_nonce;

use super::token::AccountData;

/// Parse nonce account from account data
///
/// # Arguments
/// * `account` - Account data from gRPC
/// * `metadata` - Event metadata (slot, signature, etc.)
///
/// # Returns
/// Returns `Some(DexEvent::NonceAccount)` if parsing succeeds, `None` otherwise
pub fn parse_nonce_account(account: &AccountData, metadata: EventMetadata) -> Option<DexEvent> {
    if let Ok(info) = parse_nonce(&account.data) {
        match info {
            solana_account_decoder::parse_nonce::UiNonceState::Initialized(details) => {
                let event = NonceAccountEvent {
                    metadata,
                    pubkey: account.pubkey,
                    executable: account.executable,
                    lamports: account.lamports,
                    owner: account.owner,
                    rent_epoch: account.rent_epoch,
                    nonce: details.blockhash,
                    authority: details.authority,
                };
                return Some(DexEvent::NonceAccount(event));
            }
            solana_account_decoder::parse_nonce::UiNonceState::Uninitialized => {}
        }
    }
    None
}

/// Helper function to detect if account is a nonce account
///
/// Nonce accounts have a discriminator of [1, 0, 0, 0, 1, 0, 0, 0]
pub fn is_nonce_account(data: &[u8]) -> bool {
    data.len() >= 8 && &data[0..8] == &[1, 0, 0, 0, 1, 0, 0, 0]
}
