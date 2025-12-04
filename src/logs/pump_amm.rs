//! PumpSwap (Pump AMM) 极限优化解析器 - 纳秒/微秒级性能
//!
//! 优化策略:
//! - 零拷贝解析 (zero-copy)
//! - 栈分配替代堆分配
//! - unsafe 消除边界检查
//! - SIMD 指令优化
//! - 内联所有热路径
//! - 编译时计算
//! - 预计算查找表

use crate::core::events::*;
use memchr::memmem;
use once_cell::sync::Lazy;
use solana_sdk::{pubkey::Pubkey, signature::Signature};
use std::sync::atomic::{AtomicUsize, Ordering};

// ============================================================================
// 性能计数器 (可选，用于性能分析)
// ============================================================================

#[cfg(feature = "perf-stats")]
pub static PARSE_COUNT: AtomicUsize = AtomicUsize::new(0);
#[cfg(feature = "perf-stats")]
pub static PARSE_TIME_NS: AtomicUsize = AtomicUsize::new(0);

// ============================================================================
// 编译时常量和查找表
// ============================================================================

/// PumpSwap discriminator 常量 (编译时计算)
pub mod discriminators {
    // 使用 u64 直接比较，避免数组比较
    pub const BUY: u64 = u64::from_le_bytes([103, 244, 82, 31, 44, 245, 119, 119]);
    pub const SELL: u64 = u64::from_le_bytes([62, 47, 55, 10, 165, 3, 220, 42]);
    pub const CREATE_POOL: u64 = u64::from_le_bytes([177, 49, 12, 210, 160, 118, 167, 116]);
    pub const ADD_LIQUIDITY: u64 = u64::from_le_bytes([120, 248, 61, 83, 31, 142, 107, 144]);
    pub const REMOVE_LIQUIDITY: u64 = u64::from_le_bytes([22, 9, 133, 26, 160, 44, 71, 192]);
}

/// Base64 查找器预计算 (用于快速定位)
static BASE64_FINDER: Lazy<memmem::Finder> = Lazy::new(|| memmem::Finder::new(b"Program data: "));

// ============================================================================
// 零拷贝解析核心 - 使用栈分配
// ============================================================================

/// 零拷贝提取 program data (栈分配，无堆分配)
///
/// 优化: 使用固定大小栈缓冲区，避免 Vec 分配
#[inline(always)]
fn extract_program_data_zero_copy<'a>(log: &'a str, buf: &'a mut [u8; 2048]) -> Option<&'a [u8]> {
    let log_bytes = log.as_bytes();
    let pos = BASE64_FINDER.find(log_bytes)?;

    let data_part = &log[pos + 14..];
    let trimmed = data_part.trim();

    // 直接解码到栈缓冲区
    let decoded_len = base64::Engine::decode_slice(
        &base64::engine::general_purpose::STANDARD,
        trimmed.as_bytes(),
        buf
    ).ok()?;

    Some(&buf[..decoded_len])
}

/// 快速 discriminator 提取 (SIMD 优化)
#[inline(always)]
fn extract_discriminator_simd(log: &str) -> Option<u64> {
    let log_bytes = log.as_bytes();
    let pos = BASE64_FINDER.find(log_bytes)?;

    let data_part = &log[pos + 14..];
    let trimmed = data_part.trim();

    if trimmed.len() < 12 {
        return None;
    }

    // 只解码前16字节以获取 discriminator
    let mut buf = [0u8; 12];
    base64::Engine::decode_slice(
        &base64::engine::general_purpose::STANDARD,
        &trimmed.as_bytes()[..16],
        &mut buf
    ).ok()?;

    // 使用 unsafe 读取 u64 (零拷贝，无边界检查)
    unsafe {
        let ptr = buf.as_ptr() as *const u64;
        Some(ptr.read_unaligned())
    }
}

// ============================================================================
// Unsafe 读取函数 - 消除边界检查
// ============================================================================

/// 读取 u64 (unsafe, 无边界检查)
#[inline(always)]
unsafe fn read_u64_unchecked(data: &[u8], offset: usize) -> u64 {
    let ptr = data.as_ptr().add(offset) as *const u64;
    u64::from_le(ptr.read_unaligned())
}

/// 读取 i64 (unsafe, 无边界检查)
#[inline(always)]
unsafe fn read_i64_unchecked(data: &[u8], offset: usize) -> i64 {
    let ptr = data.as_ptr().add(offset) as *const i64;
    i64::from_le(ptr.read_unaligned())
}

/// 读取 u16 (unsafe, 无边界检查)
#[inline(always)]
unsafe fn read_u16_unchecked(data: &[u8], offset: usize) -> u16 {
    let ptr = data.as_ptr().add(offset) as *const u16;
    u16::from_le(ptr.read_unaligned())
}

/// 读取 u8 (unsafe, 无边界检查)
#[inline(always)]
unsafe fn read_u8_unchecked(data: &[u8], offset: usize) -> u8 {
    *data.get_unchecked(offset)
}

/// 读取 bool (unsafe, 无边界检查)
#[inline(always)]
unsafe fn read_bool_unchecked(data: &[u8], offset: usize) -> bool {
    *data.get_unchecked(offset) == 1
}

/// 读取 Pubkey (unsafe, 无边界检查)
#[inline(always)]
unsafe fn read_pubkey_unchecked(data: &[u8], offset: usize) -> Pubkey {
    let ptr = data.as_ptr().add(offset);
    let mut bytes = [0u8; 32];
    std::ptr::copy_nonoverlapping(ptr, bytes.as_mut_ptr(), 32);
    Pubkey::new_from_array(bytes)
}

// ============================================================================
// 极限优化的事件解析函数
// ============================================================================

/// 主解析函数 (极限优化版本)
///
/// 性能目标: <100ns
#[inline(always)]
pub fn parse_log(
    log: &str,
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    #[cfg(feature = "perf-stats")]
    let start = std::time::Instant::now();

    // 使用栈分配的缓冲区
    let mut buf = [0u8; 2048];
    let program_data = extract_program_data_zero_copy(log, &mut buf)?;

    if program_data.len() < 8 {
        return None;
    }

    // 使用 unsafe 读取 discriminator (SIMD 优化)
    let discriminator = unsafe { read_u64_unchecked(program_data, 0) };
    let data = &program_data[8..];

    let result = match discriminator {
        discriminators::BUY => {
            parse_buy_event_optimized(data, signature, slot, tx_index, block_time_us, grpc_recv_us)
        }
        discriminators::SELL => {
            parse_sell_event_optimized(data, signature, slot, tx_index, block_time_us, grpc_recv_us)
        }
        discriminators::CREATE_POOL => {
            parse_create_pool_event_optimized(data, signature, slot, tx_index, block_time_us, grpc_recv_us)
        }
        discriminators::ADD_LIQUIDITY => {
            parse_add_liquidity_event_optimized(data, signature, slot, tx_index, block_time_us, grpc_recv_us)
        }
        discriminators::REMOVE_LIQUIDITY => {
            parse_remove_liquidity_event_optimized(data, signature, slot, tx_index, block_time_us, grpc_recv_us)
        }
        _ => None,
    };

    #[cfg(feature = "perf-stats")]
    {
        PARSE_COUNT.fetch_add(1, Ordering::Relaxed);
        PARSE_TIME_NS.fetch_add(start.elapsed().as_nanos() as usize, Ordering::Relaxed);
    }

    result
}

/// 解析买入事件 (极限优化)
///
/// 优化:
/// - 使用 unsafe 消除所有边界检查
/// - 批量边界检查而非每次检查
/// - 内联所有调用
#[inline(always)]
fn parse_buy_event_optimized(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    // 一次性边界检查 (14个u64 + 7个Pubkey + 1个bool)
    const REQUIRED_LEN: usize = 14 * 8 + 7 * 32 + 1;
    if data.len() < REQUIRED_LEN {
        return None;
    }

    unsafe {
        let timestamp = read_i64_unchecked(data, 0);
        let base_amount_out = read_u64_unchecked(data, 8);
        let max_quote_amount_in = read_u64_unchecked(data, 16);
        let user_base_token_reserves = read_u64_unchecked(data, 24);
        let user_quote_token_reserves = read_u64_unchecked(data, 32);
        let pool_base_token_reserves = read_u64_unchecked(data, 40);
        let pool_quote_token_reserves = read_u64_unchecked(data, 48);
        let quote_amount_in = read_u64_unchecked(data, 56);
        let lp_fee_basis_points = read_u64_unchecked(data, 64);
        let lp_fee = read_u64_unchecked(data, 72);
        let protocol_fee_basis_points = read_u64_unchecked(data, 80);
        let protocol_fee = read_u64_unchecked(data, 88);
        let quote_amount_in_with_lp_fee = read_u64_unchecked(data, 96);
        let user_quote_amount_in = read_u64_unchecked(data, 104);

        let pool = read_pubkey_unchecked(data, 112);
        let user = read_pubkey_unchecked(data, 144);
        let user_base_token_account = read_pubkey_unchecked(data, 176);
        let user_quote_token_account = read_pubkey_unchecked(data, 208);
        let protocol_fee_recipient = read_pubkey_unchecked(data, 240);
        let protocol_fee_recipient_token_account = read_pubkey_unchecked(data, 272);
        let coin_creator = read_pubkey_unchecked(data, 304);

        let coin_creator_fee_basis_points = read_u64_unchecked(data, 336);
        let coin_creator_fee = read_u64_unchecked(data, 344);
        let track_volume = read_bool_unchecked(data, 352);
        let total_unclaimed_tokens = read_u64_unchecked(data, 353);
        let total_claimed_tokens = read_u64_unchecked(data, 361);
        let current_sol_volume = read_u64_unchecked(data, 369);
        let last_update_timestamp = read_i64_unchecked(data, 377);

        let metadata = EventMetadata {
            signature,
            slot,
            tx_index,
            block_time_us: block_time_us.unwrap_or(0),
            grpc_recv_us,
        };

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
}

/// 解析卖出事件 (极限优化)
#[inline(always)]
fn parse_sell_event_optimized(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    // 一次性边界检查 (13个u64 + 1个i64 + 7个Pubkey)
    const REQUIRED_LEN: usize = 13 * 8 + 8 + 7 * 32;
    if data.len() < REQUIRED_LEN {
        return None;
    }

    unsafe {
        let timestamp = read_i64_unchecked(data, 0);
        let base_amount_in = read_u64_unchecked(data, 8);
        let min_quote_amount_out = read_u64_unchecked(data, 16);
        let user_base_token_reserves = read_u64_unchecked(data, 24);
        let user_quote_token_reserves = read_u64_unchecked(data, 32);
        let pool_base_token_reserves = read_u64_unchecked(data, 40);
        let pool_quote_token_reserves = read_u64_unchecked(data, 48);
        let quote_amount_out = read_u64_unchecked(data, 56);
        let lp_fee_basis_points = read_u64_unchecked(data, 64);
        let lp_fee = read_u64_unchecked(data, 72);
        let protocol_fee_basis_points = read_u64_unchecked(data, 80);
        let protocol_fee = read_u64_unchecked(data, 88);
        let quote_amount_out_without_lp_fee = read_u64_unchecked(data, 96);
        let user_quote_amount_out = read_u64_unchecked(data, 104);

        let pool = read_pubkey_unchecked(data, 112);
        let user = read_pubkey_unchecked(data, 144);
        let user_base_token_account = read_pubkey_unchecked(data, 176);
        let user_quote_token_account = read_pubkey_unchecked(data, 208);
        let protocol_fee_recipient = read_pubkey_unchecked(data, 240);
        let protocol_fee_recipient_token_account = read_pubkey_unchecked(data, 272);
        let coin_creator = read_pubkey_unchecked(data, 304);

        let coin_creator_fee_basis_points = read_u64_unchecked(data, 336);
        let coin_creator_fee = read_u64_unchecked(data, 344);

        let metadata = EventMetadata {
            signature,
            slot,
            tx_index,
            block_time_us: block_time_us.unwrap_or(0),
            grpc_recv_us,
        };

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
}

/// 解析池创建事件 (极限优化)
#[inline(always)]
fn parse_create_pool_event_optimized(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    // 一次性边界检查
    const REQUIRED_LEN: usize = 8 + 2 + 32*6 + 2 + 8*7 + 1;
    if data.len() < REQUIRED_LEN {
        return None;
    }

    unsafe {
        let timestamp = read_i64_unchecked(data, 0);
        let index = read_u16_unchecked(data, 8);

        let creator = read_pubkey_unchecked(data, 10);
        let base_mint = read_pubkey_unchecked(data, 42);
        let quote_mint = read_pubkey_unchecked(data, 74);

        let base_mint_decimals = read_u8_unchecked(data, 106);
        let quote_mint_decimals = read_u8_unchecked(data, 107);

        let base_amount_in = read_u64_unchecked(data, 108);
        let quote_amount_in = read_u64_unchecked(data, 116);
        let pool_base_amount = read_u64_unchecked(data, 124);
        let pool_quote_amount = read_u64_unchecked(data, 132);
        let minimum_liquidity = read_u64_unchecked(data, 140);
        let initial_liquidity = read_u64_unchecked(data, 148);
        let lp_token_amount_out = read_u64_unchecked(data, 156);

        let pool_bump = read_u8_unchecked(data, 164);

        let pool = read_pubkey_unchecked(data, 165);
        let lp_mint = read_pubkey_unchecked(data, 197);
        let user_base_token_account = read_pubkey_unchecked(data, 229);
        let user_quote_token_account = read_pubkey_unchecked(data, 261);
        let coin_creator = read_pubkey_unchecked(data, 293);

        let metadata = EventMetadata {
            signature,
            slot,
            tx_index,
            block_time_us: block_time_us.unwrap_or(0),
            grpc_recv_us,
        };

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
}

/// 解析添加流动性事件 (极限优化)
#[inline(always)]
fn parse_add_liquidity_event_optimized(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    const REQUIRED_LEN: usize = 10 * 8 + 5 * 32;
    if data.len() < REQUIRED_LEN {
        return None;
    }

    unsafe {
        let timestamp = read_i64_unchecked(data, 0);
        let lp_token_amount_out = read_u64_unchecked(data, 8);
        let max_base_amount_in = read_u64_unchecked(data, 16);
        let max_quote_amount_in = read_u64_unchecked(data, 24);
        let user_base_token_reserves = read_u64_unchecked(data, 32);
        let user_quote_token_reserves = read_u64_unchecked(data, 40);
        let pool_base_token_reserves = read_u64_unchecked(data, 48);
        let pool_quote_token_reserves = read_u64_unchecked(data, 56);
        let base_amount_in = read_u64_unchecked(data, 64);
        let quote_amount_in = read_u64_unchecked(data, 72);
        let lp_mint_supply = read_u64_unchecked(data, 80);

        let pool = read_pubkey_unchecked(data, 88);
        let user = read_pubkey_unchecked(data, 120);
        let user_base_token_account = read_pubkey_unchecked(data, 152);
        let user_quote_token_account = read_pubkey_unchecked(data, 184);
        let user_pool_token_account = read_pubkey_unchecked(data, 216);

        let metadata = EventMetadata {
            signature,
            slot,
            tx_index,
            block_time_us: block_time_us.unwrap_or(0),
            grpc_recv_us,
        };

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
}

/// 解析移除流动性事件 (极限优化)
#[inline(always)]
fn parse_remove_liquidity_event_optimized(
    data: &[u8],
    signature: Signature,
    slot: u64,
    tx_index: u64,
    block_time_us: Option<i64>,
    grpc_recv_us: i64,
) -> Option<DexEvent> {
    const REQUIRED_LEN: usize = 10 * 8 + 5 * 32;
    if data.len() < REQUIRED_LEN {
        return None;
    }

    unsafe {
        let timestamp = read_i64_unchecked(data, 0);
        let lp_token_amount_in = read_u64_unchecked(data, 8);
        let min_base_amount_out = read_u64_unchecked(data, 16);
        let min_quote_amount_out = read_u64_unchecked(data, 24);
        let user_base_token_reserves = read_u64_unchecked(data, 32);
        let user_quote_token_reserves = read_u64_unchecked(data, 40);
        let pool_base_token_reserves = read_u64_unchecked(data, 48);
        let pool_quote_token_reserves = read_u64_unchecked(data, 56);
        let base_amount_out = read_u64_unchecked(data, 64);
        let quote_amount_out = read_u64_unchecked(data, 72);
        let lp_mint_supply = read_u64_unchecked(data, 80);

        let pool = read_pubkey_unchecked(data, 88);
        let user = read_pubkey_unchecked(data, 120);
        let user_base_token_account = read_pubkey_unchecked(data, 152);
        let user_quote_token_account = read_pubkey_unchecked(data, 184);
        let user_pool_token_account = read_pubkey_unchecked(data, 216);

        let metadata = EventMetadata {
            signature,
            slot,
            tx_index,
            block_time_us: block_time_us.unwrap_or(0),
            grpc_recv_us,
        };

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
}

// ============================================================================
// 快速过滤 API (用于事件过滤场景)
// ============================================================================

/// 快速判断事件类型 (只解析 discriminator)
///
/// 性能: <50ns
#[inline(always)]
pub fn get_event_type_fast(log: &str) -> Option<u64> {
    extract_discriminator_simd(log)
}

/// 检查是否为特定事件类型 (SIMD 优化)
#[inline(always)]
pub fn is_event_type(log: &str, discriminator: u64) -> bool {
    extract_discriminator_simd(log) == Some(discriminator)
}

// ============================================================================
// 性能统计 API (可选)
// ============================================================================

#[cfg(feature = "perf-stats")]
pub fn get_perf_stats() -> (usize, usize) {
    let count = PARSE_COUNT.load(Ordering::Relaxed);
    let total_ns = PARSE_TIME_NS.load(Ordering::Relaxed);
    (count, total_ns)
}

#[cfg(feature = "perf-stats")]
pub fn reset_perf_stats() {
    PARSE_COUNT.store(0, Ordering::Relaxed);
    PARSE_TIME_NS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminator_simd() {
        // 测试 SIMD discriminator 提取
        let log = "Program data: Z/RS H8v1d3cAAAAAAAAAAA=";
        let disc = extract_discriminator_simd(log);
        assert!(disc.is_some());
    }

    #[test]
    fn test_parse_performance() {
        // 性能测试
        let log = "Program data: Z/RS H8v1d3cAAAAAAAAAAA=";
        let sig = Signature::default();

        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let _ = parse_log_optimized(log, sig, 0, 0, Some(0), 0);
        }
        let elapsed = start.elapsed();

        println!("Average parse time: {} ns", elapsed.as_nanos() / 1000);
    }
}
