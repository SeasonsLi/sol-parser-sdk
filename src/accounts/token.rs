//! SPL Token 和 Token-2022 账户解析
//!
//! 提供 Token Account 和 Mint 账户的解析功能

use crate::core::events::{EventMetadata, TokenAccountEvent, TokenInfoEvent};
use crate::DexEvent;
use solana_sdk::pubkey::Pubkey;

#[derive(Clone, Debug)]
pub struct AccountData {
    pub pubkey: Pubkey,
    pub executable: bool,
    pub lamports: u64,
    pub owner: Pubkey,
    pub rent_epoch: u64,
    pub data: Vec<u8>,
}

pub fn parse_token_account(account: &AccountData, metadata: EventMetadata) -> Option<DexEvent> {
    if account.data.len() <= 100 {
        if let Some(event) = parse_mint_fast(account, metadata.clone()) {
            return Some(event);
        }
    }
    parse_token_fast(account, metadata)
}

fn parse_mint_fast(account: &AccountData, metadata: EventMetadata) -> Option<DexEvent> {
    const MINT_SIZE: usize = 82;
    const SUPPLY_OFFSET: usize = 36;
    const DECIMALS_OFFSET: usize = 44;
    if account.data.len() < MINT_SIZE {
        return None;
    }
    let supply_bytes: [u8; 8] = account.data[SUPPLY_OFFSET..SUPPLY_OFFSET + 8].try_into().ok()?;
    let supply = u64::from_le_bytes(supply_bytes);
    let decimals = account.data[DECIMALS_OFFSET];
    let event = TokenInfoEvent {
        metadata,
        pubkey: account.pubkey,
        executable: account.executable,
        lamports: account.lamports,
        owner: account.owner,
        rent_epoch: account.rent_epoch,
        supply: supply,
        decimals: decimals,
    };
    Some(DexEvent::TokenInfo(event))
}
fn parse_token_fast(account: &AccountData, metadata: EventMetadata) -> Option<DexEvent> {
    const AMOUNT_OFFSET: usize = 64;
    if account.data.len() < AMOUNT_OFFSET + 8 {
        return None;
    }
    let amount_bytes: [u8; 8] = account.data[AMOUNT_OFFSET..AMOUNT_OFFSET + 8].try_into().ok()?;
    let amount = u64::from_le_bytes(amount_bytes);

    let event = TokenAccountEvent {
        metadata,
        pubkey: account.pubkey,
        executable: account.executable,
        lamports: account.lamports,
        owner: account.owner,
        rent_epoch: account.rent_epoch,
        amount: Some(amount),
        token_owner: account.owner,
    };

    Some(DexEvent::TokenAccount(event))
}
