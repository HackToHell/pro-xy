#![no_std]
#![no_main]

use aya_bpf::{bindings::xdp_action, macros::xdp, programs::XdpContext};
use aya_bpf::{macros::socket_filter, programs::SkBuffContext};
use aya_log_ebpf::info;

mod bindings;

use bindings::{ethhdr, iphdr, udphdr};
use core::mem;

const IPPROTO_UDP: u8 = 0x0011;
const ETH_P_IP: u16 = 0x0800;

const ETH_HLEN: usize = core::mem::size_of::<ethhdr>();
const IP_HLEN: usize = core::mem::size_of::<iphdr>();
const UDP_HLEN: usize = core::mem::size_of::<udphdr>();

const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
const IP_HDR_LEN: usize = mem::size_of::<iphdr>();

#[xdp]
pub fn pro_xy_xdp(ctx: XdpContext) -> u32 {
    match try_pro_xy(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

fn try_pro_xy(ctx: XdpContext) -> Result<u32, u32> {
    info!(&ctx, "received a packet");
    let eth = ptr_at::<ethhdr>(&ctx, 0).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { u16::from_be((*eth).h_proto) } != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip = ptr_at::<iphdr>(&ctx, ETH_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    if unsafe { (*ip).protocol } != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }
    info!(&ctx, "received a UDP packet");
    let udp = ptr_at_mut::<udphdr>(&ctx, ETH_HDR_LEN + IP_HDR_LEN).ok_or(xdp_action::XDP_PASS)?;
    let destination_port = unsafe { u16::from_be((*udp).dest) };
    if destination_port == 53 {
        // DNS standard port
        info!(&ctx, "received a DNS packet");
    }

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Option<*const T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return None;
    }

    Some((start + offset) as *const T)
}

#[inline(always)]
fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Option<*mut T> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Some(ptr as *mut T)
}

#[socket_filter]
pub fn pro_xy_filter(_ctx: SkBuffContext) -> i64 {
    let eth: ethhdr = unsafe {
        _ctx.load(0).unwrap()
    };
    if unsafe { u16::from_be((eth).h_proto) } != ETH_P_IP {
        return 0;
    }
    let ip: iphdr = unsafe {
        _ctx.load(IP_HDR_LEN).unwrap()
    };
    if unsafe { u8::from_be((ip).protocol) } != IPPROTO_UDP {
        return 0;
    }
    let udp: udphdr = unsafe {
        _ctx.load(ETH_HDR_LEN + IP_HDR_LEN).unwrap()
    };
    if unsafe { u16::from_be((udp).source) } == 53 || unsafe { u16::from_be((udp).dest) } == 53 {
        return 1;
    }
    return 0;
}
