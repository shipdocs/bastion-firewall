#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{kprobe, map},
    programs::KProbe,
    maps::HashMap,
};
use aya_log_ebpf::{info, warn};

// Key structure for our socket map
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SocketKey {
    pub src_port: u16,
    pub dst_ip: u32,  // IPv4 only for now
    pub dst_port: u16,
}

// Value structure for our socket map
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SocketInfo {
    pub pid: u32,
    pub timestamp: u64,  // For TTL/expiry
}

// Map to store socket information
#[map(name = "SOCKET_MAP")]
static mut SOCKET_MAP: HashMap<SocketKey, SocketInfo> = HashMap::with_max_entries(10240, 0);

// Helper to convert IPv4 address from struct sockaddr_in
#[inline]
fn ipv4_from_sockaddr(addr: *const core::ffi::c_void) -> u32 {
    // sockaddr_in structure:
    // struct sockaddr_in {
    //     sa_family_t    sin_family;   // AF_INET
    //     in_port_t      sin_port;     // Port number
    //     struct in_addr sin_addr;     // IPv4 address
    // };
    unsafe {
        let addr = addr as *const u8;
        // Skip sin_family (2 bytes) and sin_port (2 bytes)
        let ip_ptr = addr.add(4) as *const u32;
        *ip_ptr
    }
}

// Helper to extract port from struct sockaddr_in
#[inline]
fn port_from_sockaddr(addr: *const core::ffi::c_void) -> u16 {
    unsafe {
        let addr = addr as *const u8;
        // Skip sin_family (2 bytes)
        let port_ptr = addr.add(2) as *const u16;
        u16::from_be(*port_ptr)  // Network byte order to host
    }
}

#[kprobe(name = "tcp_v4_connect")]
fn tcp_v4_connect(ctx: KProbe) -> u32 {
    match try_tcp_v4_connect(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_tcp_v4_connect(ctx: KProbe) -> Result<(), i32> {
    // tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
    // Arguments: RDI = sock, RSI = uaddr, RDX = addr_len
    
    let pid = match aya_bpf::helpers::bpf_get_current_pid_tgid() as u32 {
        pid => pid,
    };
    
    // Get the userspace address from RSI (second argument)
    let uaddr = unsafe {
        let regs = ctx.regs();
        if regs.is_null() {
            return Err(1);
        }
        (*regs).rsi
    };
    
    // Read the sockaddr structure from userspace
    let mut sockaddr = [0u8; 16];  // sizeof(struct sockaddr_in)
    if unsafe { aya_bpf::helpers::bpf_probe_read_user(&mut sockaddr, uaddr) } != 0 {
        return Err(2);
    }
    
    // Extract destination IP and port
    let dst_ip = ipv4_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    let dst_port = port_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    
    // For TCP connect, we don't know the source port yet (it's assigned later)
    // We'll use a special value (0) and update it when we see the actual packet
    let key = SocketKey {
        src_port: 0,  // Will be updated when we see the actual packet
        dst_ip,
        dst_port,
    };
    
    let info = SocketInfo {
        pid,
        timestamp: unsafe { aya_bpf::helpers::bpf_ktime_get_ns() },
    };
    
    unsafe {
        if let Err(_) = SOCKET_MAP.insert(&ctx, &key, &info, 0) {
            warn!(&ctx, "Failed to insert TCP connection info");
        }
    }
    
    info!(&ctx, "TCP connect: PID {} -> {}:{}", pid, dst_ip, dst_port);
    
    Ok(())
}

#[kprobe(name = "udp_sendmsg")]
fn udp_sendmsg(ctx: KProbe) -> u32 {
    match try_udp_sendmsg(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

fn try_udp_sendmsg(ctx: KProbe) -> Result<(), i32> {
    // udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
    // Arguments: RDI = sock, RSI = msg, RDX = len
    
    let pid = match aya_bpf::helpers::bpf_get_current_pid_tgid() as u32 {
        pid => pid,
    };
    
    // Get the msghdr from RSI (second argument)
    let msg = unsafe {
        let regs = ctx.regs();
        if regs.is_null() {
            return Err(1);
        }
        (*regs).rsi
    };
    
    // msg->msg_name contains the destination address
    let mut msg_name_ptr = [0u8; 8];  // Pointer size
    if unsafe { aya_bpf::helpers::bpf_probe_read(&mut msg_name_ptr, msg as *const u8) } != 0 {
        return Err(2);
    }
    
    let msg_name = u64::from_le_bytes(msg_name_ptr);
    if msg_name == 0 {
        // No destination address (connected UDP socket)
        return Ok(());
    }
    
    // Read the sockaddr structure
    let mut sockaddr = [0u8; 16];
    if unsafe { aya_bpf::helpers::bpf_probe_read_user(&mut sockaddr, msg_name) } != 0 {
        return Err(3);
    }
    
    // Extract destination IP and port
    let dst_ip = ipv4_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    let dst_port = port_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    
    // For UDP, we also don't know the source port yet
    let key = SocketKey {
        src_port: 0,  // Will be updated when we see the actual packet
        dst_ip,
        dst_port,
    };
    
    let info = SocketInfo {
        pid,
        timestamp: unsafe { aya_bpf::helpers::bpf_ktime_get_ns() },
    };
    
    unsafe {
        if let Err(_) = SOCKET_MAP.insert(&ctx, &key, &info, 0) {
            warn!(&ctx, "Failed to insert UDP connection info");
        }
    }
    
    info!(&ctx, "UDP sendmsg: PID {} -> {}:{}", pid, dst_ip, dst_port);
    
    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}