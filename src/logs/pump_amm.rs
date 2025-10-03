//! PumpSwap 日志解析器
//!
//! 使用 match discriminator 模式解析 PumpSwap 事件

use super::utils::*;
use crate::core::events::*;
use solana_sdk::{pubkey::Pubkey, signature::Signature};

/// PumpSwap discriminator 常量
pub mod discriminators {
    pub const BUY: [u8; 8] = [103, 244, 82, 31, 44, 245, 119, 119];
    pub const SELL: [u8; 8] = [62, 47, 55, 10, 165, 3, 220, 42];
    pub const CREATE_POOL: [u8; 8] = [177, 49, 12, 210, 160, 118, 167, 116];
    pub const ADD_LIQUIDITY: [u8; 8] = [120, 248, 61, 83, 31, 142, 107, 144];
    pub const REMOVE_LIQUIDITY: [u8; 8] = [22, 9, 133, 26, 160, 44, 71, 192];
}

/// PumpSwap 程序 ID
pub const PROGRAM_ID: &str = "6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P";

/// 检查日志是否来自 Pump AMM 程序
pub fn is_pump_amm_log(log: &str) -> bool {
    log.contains(&format!("Program {} invoke", PROGRAM_ID))
        || log.contains(&format!("Program {} success", PROGRAM_ID))
        || log.contains("pumpswap")
        || log.contains("PumpSwap")
}

/// 主要的 PumpSwap 日志解析函数
pub fn parse_log(
    log: &str,
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    parse_structured_log(log, signature, slot, tx_index, block_time_us, grpc_recv_us)
}

/// 结构化日志解析（基于 Program data）
fn parse_structured_log(
    log: &str,
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    let program_data = extract_program_data(log)?;
    if program_data.len() < 8 {
        return None;
    }

    let discriminator: [u8; 8] = program_data[0..8].try_into().ok()?;
    let data = &program_data[8..];

    match discriminator {
        discriminators::BUY => {
            parse_buy_event(data, signature, slot, tx_index, block_time_us, grpc_recv_us)
        }
        discriminators::SELL => {
            parse_sell_event(data, signature, slot, tx_index, block_time_us, grpc_recv_us)
        }
        discriminators::CREATE_POOL => {
            parse_create_pool_event(data, signature, slot, tx_index, block_time_us, grpc_recv_us)
        }
        discriminators::ADD_LIQUIDITY => {
            parse_add_liquidity_event(data, signature, slot, tx_index, block_time_us, grpc_recv_us)
        }
        discriminators::REMOVE_LIQUIDITY => parse_remove_liquidity_event(
            data,
            signature,
            slot,
            tx_index,
            block_time_us,
            grpc_recv_us,
        ),
        _ => None,
    }
}

/// 解析买入事件
fn parse_buy_event(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    let mut offset = 0;

    let timestamp = read_i64_le(data, offset)?;
    offset += 8;

    let base_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let max_quote_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let user_base_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let user_quote_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let pool_base_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let pool_quote_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let quote_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let lp_fee_basis_points = read_u64_le(data, offset)?;
    offset += 8;

    let lp_fee = read_u64_le(data, offset)?;
    offset += 8;

    let protocol_fee_basis_points = read_u64_le(data, offset)?;
    offset += 8;

    let protocol_fee = read_u64_le(data, offset)?;
    offset += 8;

    let quote_amount_in_with_lp_fee = read_u64_le(data, offset)?;
    offset += 8;

    let user_quote_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let pool = read_pubkey(data, offset)?;
    offset += 32;

    let user = read_pubkey(data, offset)?;
    offset += 32;

    let user_base_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let user_quote_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let protocol_fee_recipient = read_pubkey(data, offset)?;
    offset += 32;

    let protocol_fee_recipient_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let coin_creator = read_pubkey(data, offset)?;
    offset += 32;

    let coin_creator_fee_basis_points = read_u64_le(data, offset)?;
    offset += 8;

    let coin_creator_fee = read_u64_le(data, offset)?;
    offset += 8;

    let track_volume = read_bool(data, offset)?;
    offset += 1;

    let total_unclaimed_tokens = read_u64_le(data, offset)?;
    offset += 8;

    let total_claimed_tokens = read_u64_le(data, offset)?;
    offset += 8;

    let current_sol_volume = read_u64_le(data, offset)?;
    offset += 8;

    let last_update_timestamp = read_i64_le(data, offset)?;

    let metadata = create_metadata_simple(
        signature,
        slot,
        tx_index,
        block_time_us,
        Pubkey::default(),
        grpc_recv_us,
    );

    Some(DexEvent::PumpSwapBuy(PumpSwapBuyEvent {
        metadata,
        timestamp,
        base_amount_out,
        max_quote_amount_in,
        user_base_token_reserves,
        user_quote_token_reserves,
        pool_base_token_reserves,
        pool_quote_token_reserves,
        quote_amount_in,
        lp_fee_basis_points,
        lp_fee,
        protocol_fee_basis_points,
        protocol_fee,
        quote_amount_in_with_lp_fee,
        user_quote_amount_in,
        pool,
        user,
        user_base_token_account,
        user_quote_token_account,
        protocol_fee_recipient,
        protocol_fee_recipient_token_account,
        coin_creator,
        coin_creator_fee_basis_points,
        coin_creator_fee,
        track_volume,
        total_unclaimed_tokens,
        total_claimed_tokens,
        current_sol_volume,
        last_update_timestamp,
        ..Default::default()
    }))
}

/// 解析卖出事件
fn parse_sell_event(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    let mut offset = 0;

    let timestamp = read_i64_le(data, offset)?;
    offset += 8;

    let base_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let min_quote_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let user_base_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let user_quote_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let pool_base_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let pool_quote_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let quote_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let lp_fee_basis_points = read_u64_le(data, offset)?;
    offset += 8;

    let lp_fee = read_u64_le(data, offset)?;
    offset += 8;

    let protocol_fee_basis_points = read_u64_le(data, offset)?;
    offset += 8;

    let protocol_fee = read_u64_le(data, offset)?;
    offset += 8;

    let quote_amount_out_without_lp_fee = read_u64_le(data, offset)?;
    offset += 8;

    let user_quote_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let pool = read_pubkey(data, offset)?;
    offset += 32;

    let user = read_pubkey(data, offset)?;
    offset += 32;

    let user_base_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let user_quote_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let protocol_fee_recipient = read_pubkey(data, offset)?;
    offset += 32;

    let protocol_fee_recipient_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let coin_creator = read_pubkey(data, offset)?;
    offset += 32;

    let coin_creator_fee_basis_points = read_u64_le(data, offset)?;
    offset += 8;

    let coin_creator_fee = read_u64_le(data, offset)?;

    let metadata = create_metadata_simple(
        signature,
        slot,
        tx_index,
        block_time_us,
        Pubkey::default(),
        grpc_recv_us,
    );

    Some(DexEvent::PumpSwapSell(PumpSwapSellEvent {
        metadata,
        timestamp,
        base_amount_in,
        min_quote_amount_out,
        user_base_token_reserves,
        user_quote_token_reserves,
        pool_base_token_reserves,
        pool_quote_token_reserves,
        quote_amount_out,
        lp_fee_basis_points,
        lp_fee,
        protocol_fee_basis_points,
        protocol_fee,
        quote_amount_out_without_lp_fee,
        user_quote_amount_out,
        pool,
        user,
        user_base_token_account,
        user_quote_token_account,
        protocol_fee_recipient,
        protocol_fee_recipient_token_account,
        coin_creator,
        coin_creator_fee_basis_points,
        coin_creator_fee,
        ..Default::default()
    }))
}

/// 解析池创建事件
fn parse_create_pool_event(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    let mut offset = 0;

    let timestamp = read_i64_le(data, offset)?;
    offset += 8;

    let index = read_u16_le(data, offset)?;
    offset += 2;

    let creator = read_pubkey(data, offset)?;
    offset += 32;

    let base_mint = read_pubkey(data, offset)?;
    offset += 32;

    let quote_mint = read_pubkey(data, offset)?;
    offset += 32;

    let base_mint_decimals = read_u8(data, offset)?;
    offset += 1;

    let quote_mint_decimals = read_u8(data, offset)?;
    offset += 1;

    let base_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let quote_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let pool_base_amount = read_u64_le(data, offset)?;
    offset += 8;

    let pool_quote_amount = read_u64_le(data, offset)?;
    offset += 8;

    let minimum_liquidity = read_u64_le(data, offset)?;
    offset += 8;

    let initial_liquidity = read_u64_le(data, offset)?;
    offset += 8;

    let lp_token_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let pool_bump = read_u8(data, offset)?;
    offset += 1;

    let pool = read_pubkey(data, offset)?;
    offset += 32;

    let lp_mint = read_pubkey(data, offset)?;
    offset += 32;

    let user_base_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let user_quote_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let coin_creator = read_pubkey(data, offset)?;

    let metadata = create_metadata_simple(
        signature,
        slot,
        tx_index,
        block_time_us,
        Pubkey::default(),
        grpc_recv_us,
    );

    Some(DexEvent::PumpSwapCreatePool(PumpSwapCreatePoolEvent {
        metadata,
        timestamp,
        index,
        creator,
        base_mint,
        quote_mint,
        base_mint_decimals,
        quote_mint_decimals,
        base_amount_in,
        quote_amount_in,
        pool_base_amount,
        pool_quote_amount,
        minimum_liquidity,
        initial_liquidity,
        lp_token_amount_out,
        pool_bump,
        pool,
        lp_mint,
        user_base_token_account,
        user_quote_token_account,
        coin_creator,
    }))
}

fn parse_add_liquidity_event(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    let mut offset = 0;

    let timestamp = read_i64_le(data, offset)?;
    offset += 8;

    let lp_token_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let max_base_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let max_quote_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let user_base_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let user_quote_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let pool_base_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let pool_quote_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let base_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let quote_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let lp_mint_supply = read_u64_le(data, offset)?;
    offset += 8;

    let pool = read_pubkey(data, offset)?;
    offset += 32;

    let user = read_pubkey(data, offset)?;
    offset += 32;

    let user_base_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let user_quote_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let user_pool_token_account = read_pubkey(data, offset)?;

    let metadata = create_metadata_simple(
        signature,
        slot,
        tx_index,
        block_time_us,
        Pubkey::default(),
        grpc_recv_us,
    );

    Some(DexEvent::PumpSwapLiquidityAdded(PumpSwapLiquidityAdded {
        metadata,
        timestamp,
        lp_token_amount_out,
        max_base_amount_in,
        max_quote_amount_in,
        user_base_token_reserves,
        user_quote_token_reserves,
        pool_base_token_reserves,
        pool_quote_token_reserves,
        base_amount_in,
        quote_amount_in,
        lp_mint_supply,
        pool,
        user,
        user_base_token_account,
        user_quote_token_account,
        user_pool_token_account,
    }))
}

fn parse_remove_liquidity_event(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    let mut offset = 0;

    let timestamp = read_i64_le(data, offset)?;
    offset += 8;

    let lp_token_amount_in = read_u64_le(data, offset)?;
    offset += 8;

    let min_base_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let min_quote_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let user_base_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let user_quote_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let pool_base_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let pool_quote_token_reserves = read_u64_le(data, offset)?;
    offset += 8;

    let base_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let quote_amount_out = read_u64_le(data, offset)?;
    offset += 8;

    let lp_mint_supply = read_u64_le(data, offset)?;
    offset += 8;

    let pool = read_pubkey(data, offset)?;
    offset += 32;

    let user = read_pubkey(data, offset)?;
    offset += 32;

    let user_base_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let user_quote_token_account = read_pubkey(data, offset)?;
    offset += 32;

    let user_pool_token_account = read_pubkey(data, offset)?;

    let metadata = create_metadata_simple(
        signature,
        slot,
        tx_index,
        block_time_us,
        Pubkey::default(),
        grpc_recv_us,
    );

    Some(DexEvent::PumpSwapLiquidityRemoved(PumpSwapLiquidityRemoved {
        metadata,
        timestamp,
        lp_token_amount_in,
        min_base_amount_out,
        min_quote_amount_out,
        user_base_token_reserves,
        user_quote_token_reserves,
        pool_base_token_reserves,
        pool_quote_token_reserves,
        base_amount_out,
        quote_amount_out,
        lp_mint_supply,
        pool,
        user,
        user_base_token_account,
        user_quote_token_account,
        user_pool_token_account,
    }))
}

/// 文本回退解析
fn parse_text_log(
    log: &str,
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    use super::utils::text_parser::*;

    if log.contains("buy") || log.contains("Buy") {
        return parse_buy_from_text(log, signature, slot, tx_index, block_time_us, grpc_recv_us);
    }

    if log.contains("sell") || log.contains("Sell") {
        return parse_sell_from_text(log, signature, slot, tx_index, block_time_us, grpc_recv_us);
    }

    if log.contains("create") && log.contains("pool") {
        return parse_create_pool_from_text(
            log,
            signature,
            slot,
            tx_index,
            block_time_us,
            grpc_recv_us,
        );
    }

    None
}

/// 从文本解析买入事件
fn parse_buy_from_text(
    log: &str,
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    None
    // use super::utils::text_parser::*;

    // let metadata = create_metadata_simple(signature, slot, tx_index, block_time_us, Pubkey::default(), grpc_recv_us);

    // Some(DexEvent::PumpSwapBuy(PumpSwapBuyEvent {
    //     metadata,
    //     pool_id: Pubkey::default(),
    //     user: Pubkey::default(),
    //     token_mint: Pubkey::default(),
    //     sol_amount: extract_number_from_text(log, "sol").unwrap_or(1_000_000_000),
    //     token_amount: extract_number_from_text(log, "token").unwrap_or(950_000_000),
    //     price: 0,
    //     slippage: 0,
    // }))
}

/// 从文本解析卖出事件
fn parse_sell_from_text(
    log: &str,
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    None
    // use super::utils::text_parser::*;

    // let metadata = create_metadata_simple(
    //     signature,
    //     slot,
    //     tx_index,
    //     block_time_us,
    //     Pubkey::default(),
    //     grpc_recv_us,
    // );

    // Some(DexEvent::PumpSwapSell(PumpSwapSellEvent {
    //     metadata,
    //     pool_id: Pubkey::default(),
    //     user: Pubkey::default(),
    //     token_mint: Pubkey::default(),
    //     token_amount: extract_number_from_text(log, "token").unwrap_or(1_000_000_000),
    //     sol_amount: extract_number_from_text(log, "sol").unwrap_or(900_000_000),
    //     price: 0,
    //     slippage: 0,
    // }))
}

/// 从文本解析池创建事件
fn parse_create_pool_from_text(
    log: &str,
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    None
    // use super::utils::text_parser::*;

    // let metadata = create_metadata_simple(
    //     signature,
    //     slot,
    //     tx_index,
    //     block_time_us,
    //     Pubkey::default(),
    //     grpc_recv_us,
    // );

    // Some(DexEvent::PumpSwapCreatePool(PumpSwapCreatePoolEvent {
    //     metadata,
    //     pool_id: Pubkey::default(),
    //     creator: Pubkey::default(),
    //     token_mint: Pubkey::default(),
    //     initial_sol_amount: extract_number_from_text(log, "sol_reserve").unwrap_or(1_000_000_000),
    //     initial_token_amount: extract_number_from_text(log, "token_reserve")
    //         .unwrap_or(100_000_000_000),
    //     fee_rate: 0,
    // }))
}
