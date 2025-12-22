"""
eBPF Traffic Identifier Module
"""
import socket
import struct
import logging
import os

logger = logging.getLogger(__name__)

# BPF Program
BPF_TEXT = """
// Fix for recent kernels (6.9+) where bpf.h uses struct bpf_wq but it is not defined in included headers
struct bpf_wq {
    int dummy;
};

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>

struct ipv4_key_t {
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8  proto;
};

struct process_info_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};

// Hash map to store connection info: Key -> Process Info
BPF_HASH(conn_map, struct ipv4_key_t, struct process_info_t, 10240);

// Helper to store event
static void store_event(struct sock *sk, u32 pid, u8 proto) {
    struct ipv4_key_t key = {};
    struct process_info_t info = {};
    
    // Read socket details
    u16 dport = sk->__sk_common.skc_dport;
    u16 sport = sk->__sk_common.skc_num;
    
    key.saddr = sk->__sk_common.skc_rcv_saddr;
    key.daddr = sk->__sk_common.skc_daddr;
    key.sport = sport;
    key.dport = ntohs(dport); 
    key.proto = proto;
    
    // Get process info
    info.pid = pid;
    bpf_get_current_comm(&info.comm, sizeof(info.comm));
    
    conn_map.update(&key, &info);
}

// ENTRY hook to save socket pointer
struct cur_sock_t {
    struct sock *sk;
};
BPF_HASH(connect_socks, u32, struct sock *);

int trace_tcp_connect_entry(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    connect_socks.update(&pid, &sk);
    return 0;
}

int trace_tcp_connect_return(struct pt_regs *ctx) {
    int ret = PT_REGS_RC(ctx);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    
    struct sock **skpp = connect_socks.lookup(&pid);
    if (skpp == 0) return 0; // Missed entry
    
    struct sock *sk = *skpp;
    connect_socks.delete(&pid);
    
    if (ret != 0) return 0; // Failed connect
    
    store_event(sk, pid, IPPROTO_TCP);
    return 0;
}

// UDP Sendmsg
int trace_udp_sendmsg(struct pt_regs *ctx, struct sock *sk) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    store_event(sk, pid, IPPROTO_UDP);
    return 0;
}
"""

class EBPFIdentifier:
    """Uses eBPF to identify applications creating network connections"""
    
    def __init__(self):
        self.available = False
        self.b = None
        
        # Check root
        if os.geteuid() != 0:
            logger.warning("eBPF requires root privileges")
            return

        try:
            from bcc import BPF
            self.b = BPF(text=BPF_TEXT)
            
            # Attach probes
            self.b.attach_kprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect_entry")
            self.b.attach_kretprobe(event="tcp_v4_connect", fn_name="trace_tcp_connect_return")
            self.b.attach_kprobe(event="udp_sendmsg", fn_name="trace_udp_sendmsg")
            
            self.available = True
            logger.info("eBPF Traffic Identifier initialized successfully")
        except ImportError:
            logger.warning("BCC library not installed. eBPF identification unavailable.")
        except Exception as e:
            logger.error(f"Failed to initialize eBPF: {e}")

    def lookup(self, src_ip, dest_ip, src_port, dest_port, protocol):
        """
        Lookup process info from eBPF map.
        Returns: {'pid': int, 'comm': str} or None
        """
        if not self.available:
            return None

        try:
            conn_map = self.b["conn_map"]
            
            # Prepare key
            # Note: We iterate because constructing the ctypes key matches strict types
            # and sometimes endianness or IP format matches are tricky in python-bcc interchange.
            # Optimization: In high performance, we should construct the key struct directly.
            # But for stability now, iteration is okay (map size 10k max).
            # ACTUALLY, iteration is too slow for per-packet logic.
            # We MUST construct the key.
            
            # Key definition (must match C struct)
            # struct ipv4_key_t { u32 saddr; u32 daddr; u16 sport; u16 dport; u8 proto; };
            # BPF hash keys are binary data.
            
            saddr_int = struct.unpack("I", socket.inet_aton(src_ip))[0]
            daddr_int = struct.unpack("I", socket.inet_aton(dest_ip))[0]
            proto_int = 6 if protocol == 'tcp' else 17
            
            # Use ctypes to create key
            import ctypes
            class IPv4Key(ctypes.Structure):
                _fields_ = [
                    ("saddr", ctypes.c_uint32),
                    ("daddr", ctypes.c_uint32),
                    ("sport", ctypes.c_uint16),
                    ("dport", ctypes.c_uint16),
                    ("proto", ctypes.c_uint8)
                ]
            
            key = IPv4Key(saddr_int, daddr_int, src_port, dest_port, proto_int)
            
            # Lookup
            if key in conn_map:
                val = conn_map[key]
                return {
                    'pid': val.pid,
                    'comm': val.comm.decode('utf-8', 'ignore')
                }
                
        except Exception as e:
            # logger.debug(f"eBPF lookup error: {e}")
            pass
            
        return None
