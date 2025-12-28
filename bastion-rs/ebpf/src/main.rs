#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{kprobe, map},
    programs::ProbeContext as KProbe,
    maps::HashMap,
};
use aya_log_ebpf::{info, warn};

// Key structure for our socket map
// FIX #1, #2: Added pid disambiguator to prevent key collision between processes
// FIX #2: Field order matches user-space (src_port, dst_ip, dst_port, pid)
#[derive(Clone, Copy)]
#[repr(C)]
pub struct SocketKey {
    pub src_port: u16,
    pub dst_ip: u32,  // IPv4 in network byte order
    pub dst_port: u16,
    pub pid: u32,     // Disambiguator to prevent collisions between processes
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
// FIX #3: Returns IPv4 in network byte order (already in correct format in sockaddr)
/// Extracts the IPv4 address from a pointer to a `sockaddr_in`.
///
/// Interprets `addr` as a pointer to a C `sockaddr_in` and reads the 32-bit
/// IPv4 address field. The returned value is in network byte order (big-endian).
///
/// # Examples
///
/// ```
/// use core::ffi::c_void;
/// // Construct a sockaddr_in-like buffer: [family(2), port(2), ip(4), ...]
/// let buf: [u8; 8] = [0, 2, 0x1F, 0x90, 192, 168, 1, 10]; // family=AF_INET, port=8080, ip=192.168.1.10
/// let ip_be = unsafe { ipv4_from_sockaddr(buf.as_ptr() as *const c_void) };
/// // ip_be is 0xC0A8010A (192.168.1.10) in network byte order
/// assert_eq!(ip_be.to_be(), 0xC0A8_010A);
/// ```
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
        *ip_ptr  // Already in network byte order
    }
}

// Helper to extract port from struct sockaddr_in
/// Extracts the 16-bit port number from a pointer to a `sockaddr_in`.
///
/// Interprets `addr` as a pointer to a `sockaddr_in`-style buffer and returns the port
/// converted from network byte order to host byte order.
///
/// # Safety
///
/// The caller must ensure `addr` is a valid pointer to at least a `sockaddr_in`-sized
/// region (commonly 16 bytes) and properly aligned for reading a `u16`.
///
/// # Examples
///
/// ```
/// let mut buf = [0u8; 16];
/// // place port 8080 (0x1F90) into bytes 2..4 (network byte order)
/// buf[2] = 0x1F;
/// buf[3] = 0x90;
/// let port = port_from_sockaddr(buf.as_ptr() as *const core::ffi::c_void);
/// assert_eq!(port, 8080);
/// ```
#[inline]
fn port_from_sockaddr(addr: *const core::ffi::c_void) -> u16 {
    unsafe {
        let addr = addr as *const u8;
        // Skip sin_family (2 bytes)
        let port_ptr = addr.add(2) as *const u16;
        u16::from_be(*port_ptr)  // Network byte order to host
    }
}

/// Kprobe entry for the kernel's `tcp_v4_connect`; records outbound TCP destinations.
///
/// # Examples
///
/// ```
/// // The probe entry always returns 0 when invoked.
/// let rc = tcp_v4_connect(unsafe { core::mem::zeroed() });
/// assert_eq!(rc, 0);
/// ```
#[kprobe]
fn tcp_v4_connect(ctx: KProbe) -> u32 {
    match try_tcp_v4_connect(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// Records an outbound TCP IPv4 connect attempt in the global SOCKET_MAP keyed by destination and PID.
///
/// Reads a user-space `sockaddr` from the second argument of `tcp_v4_connect`, extracts the
/// destination IPv4 address and port, and inserts a `SocketInfo` (with PID and timestamp) into
/// `SOCKET_MAP`. The `SocketKey`'s `src_port` is set to 0 because the source port is not known
/// at connect time.
///
/// # Examples
///
/// ```no_run
/// // Invoked from a kprobe handler with a valid `KProbe` context.
/// try_tcp_v4_connect(ctx).ok();
/// ```
///
/// Returns `Ok(())` on success; returns `Err(code)` if reading registers or user memory fails or
/// if map operations encounter an error.
fn try_tcp_v4_connect(ctx: KProbe) -> Result<(), i32> {
    // tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
    // Arguments: RDI = sock, RSI = uaddr, RDX = addr_len
    
    // FIX #4: Extract PID correctly from bpf_get_current_pid_tgid()
    // Returns u64 where lower 32 bits = PID, upper 32 bits = TGID
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    
    // Get the userspace address from RSI (second argument)
    let uaddr = unsafe {
        let regs = ctx.regs;
        if regs.is_null() {
            return Err(1);
        }
        (*regs).rsi
    };
    
    // Read the sockaddr structure (try kernel space first, then user space)
    let sockaddr: [u8; 16] = unsafe {
        // Try kernel space read first (for some kernel versions)
        match aya_ebpf::helpers::bpf_probe_read(uaddr as *const [u8; 16]) {
            Ok(val) => val,
            Err(_) => {
                // Fall back to user space read
                match aya_ebpf::helpers::bpf_probe_read_user(uaddr as *const [u8; 16]) {
                    Ok(val) => val,
                    Err(_) => return Err(2),
                }
            }
        }
    };
    
    // Extract destination IP and port
    let dst_ip = ipv4_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    let dst_port = port_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    
    // For TCP connect, we don't know the source port yet (it's assigned later)
    // FIX #1: Include pid in key to prevent collisions between processes
    let key = SocketKey {
        src_port: 0,  // Will be updated when we see the actual packet
        dst_ip,
        dst_port,
        pid,
    };
    
    let info = SocketInfo {
        pid,
        timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
    };
    
    unsafe {
        if let Err(_) = SOCKET_MAP.insert(&key, &info, 0) {
            warn!(&ctx, "Failed to insert TCP connection info");
        }
    }
    
    info!(&ctx, "TCP connect: PID {} -> {}:{}", pid, dst_ip, dst_port);
    
    Ok(())
}

/// Kprobe handler attached to the kernel's `udp_sendmsg` entry that records UDP peer destinations into the global socket map.
///
/// The handler always returns `0` to indicate the probe completed (no directional error signalling).
///
/// # Examples
///
/// ```
/// // Constructing a real `KProbe` is platform-specific; in tests or simulation you can pass a zeroed context.
/// let ctx: KProbe = unsafe { core::mem::zeroed() };
/// let res = udp_sendmsg(ctx);
/// assert_eq!(res, 0);
/// ```
#[kprobe]
fn udp_sendmsg(ctx: KProbe) -> u32 {
    match try_udp_sendmsg(ctx) {
        Ok(_) => 0,
        Err(_) => 0,
    }
}

/// Parse a user-space msghdr from a UDP sendmsg probe and record the destination in SOCKET_MAP.
///
/// Reads the msghdr pointer from the probe context, obtains the msg_name (destination sockaddr)
/// from user space, extracts the IPv4 destination address and port, and inserts a SocketKey/SocketInfo
/// entry (with `src_port = 0`) keyed by destination and calling PID so consumers can later correlate
/// packets with the originating process.
///
/// On success returns `Ok(())`. Returns `Err(code)` for recoverable probe/read failures:
/// - `Err(1)` if the probe register context is null,
/// - `Err(2)` if reading the msghdr's msg_name pointer fails,
/// - `Err(3)` if reading the sockaddr from user space fails.
///
/// # Examples
///
/// ```rust,no_run
/// // In eBPF context the KProbe is provided by the framework; this example shows intended usage.
/// # use aya_bpf::macros::kprobe;
/// # use aya_bpf::programs::KProbe;
/// // fn example(ctx: KProbe) { let _ = try_udp_sendmsg(ctx); }
/// ```
fn try_udp_sendmsg(ctx: KProbe) -> Result<(), i32> {
    // udp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
    // Arguments: RDI = sock, RSI = msg, RDX = len
    
    // FIX #5: Extract PID correctly from bpf_get_current_pid_tgid()
    // Returns u64 where lower 32 bits = PID, upper 32 bits = TGID
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() & 0xFFFFFFFF) as u32;
    
    // Get the msghdr from RSI (second argument)
    let msg = unsafe {
        let regs = ctx.regs;
        if regs.is_null() {
            return Err(1);
        }
        (*regs).rsi
    };
    
    // msg->msg_name contains the destination address
    let msg_name_ptr: [u8; 8] = unsafe {
        match aya_ebpf::helpers::bpf_probe_read(msg as *const [u8; 8]) {
            Ok(val) => val,
            Err(_) => return Err(2),
        }
    };
    
    let msg_name = u64::from_le_bytes(msg_name_ptr);
    if msg_name == 0 {
        // No destination address (connected UDP socket)
        return Ok(());
    }
    
    // Read the sockaddr structure
    let sockaddr: [u8; 16] = unsafe {
        match aya_ebpf::helpers::bpf_probe_read_user(msg_name as *const [u8; 16]) {
            Ok(val) => val,
            Err(_) => return Err(3),
        }
    };
    
    // Extract destination IP and port
    let dst_ip = ipv4_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    let dst_port = port_from_sockaddr(sockaddr.as_ptr() as *const core::ffi::c_void);
    
    // For UDP, we also don't know the source port yet
    // FIX #1: Include pid in key to prevent collisions between processes
    let key = SocketKey {
        src_port: 0,  // Will be updated when we see the actual packet
        dst_ip,
        dst_port,
        pid,
    };
    
    let info = SocketInfo {
        pid,
        timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
    };
    
    unsafe {
        if let Err(_) = SOCKET_MAP.insert(&key, &info, 0) {
            warn!(&ctx, "Failed to insert UDP connection info");
        }
    }
    
    info!(&ctx, "UDP sendmsg: PID {} -> {}:{}", pid, dst_ip, dst_port);
    
    Ok(())
}

/// Halts execution on panic by entering an infinite loop.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}