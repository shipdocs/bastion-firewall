#!/usr/bin/env python3
"""Netfilter packet interception and application identification."""

import os
import sys
import logging
import socket
import struct
import subprocess
from pathlib import Path
from typing import Optional, Dict, Tuple
import psutil
import time

logger = logging.getLogger(__name__)

try:
    from netfilterqueue import NetfilterQueue
    from scapy.all import IP, TCP, UDP
    NETFILTER_AVAILABLE = True
except ImportError:
    NETFILTER_AVAILABLE = False
    logger.warning("NetfilterQueue or scapy not available - running in limited mode")


class PacketInfo:
    def __init__(self, src_ip: str, src_port: int, dest_ip: str, dest_port: int,
                 protocol: str, pid: Optional[int] = None):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.protocol = protocol
        self.pid = pid
        self.app_name = None
        self.app_path = None
    
    def __str__(self):
        return (f"PacketInfo({self.app_name or 'unknown'} [{self.pid}] -> "
                f"{self.dest_ip}:{self.dest_port} (src:{self.src_port}) via {self.protocol})")


class ConnectionCache:
    """Cache identified connections. Key: (src_port, protocol)"""

    def __init__(self, ttl=60):
        self.cache = {}
        self.ttl = ttl
        
    def get(self, src_port, protocol):
        now = time.time()

        # Lazy cleanup
        keys_to_delete = [k for k, v in self.cache.items() if now - v['time'] > self.ttl]
        for k in keys_to_delete:
            del self.cache[k]

        key = (src_port, protocol)
        if key not in self.cache:
            return None

        entry = self.cache[key]

        # Validate PID still exists and exe path matches (port reuse check)
        try:
            process = psutil.Process(entry['pid'])
            if process.exe() != entry['path']:
                del self.cache[key]
                return None
            return entry
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            del self.cache[key]
            return None
        
    def set(self, src_port, protocol, pid, name, path):
        key = (src_port, protocol)
        self.cache[key] = {
            'pid': pid,
            'name': name,
            'path': path,
            'time': time.time()
        }



class ApplicationIdentifier:
    """Identifies which application is making a connection"""
    
    @staticmethod
    def find_process_by_socket(src_ip: str, src_port: int, dest_ip: str, 
                               dest_port: int, protocol: str) -> Optional[Dict]:
        """
        Find the process that owns a socket by matching connection info.
        
        This reads /proc/net/tcp or /proc/net/udp to find the socket,
        then matches it to a process.
        """
        try:
            # Get all network connections
            kind = 'tcp' if protocol.lower() == 'tcp' else 'udp'
            connections = psutil.net_connections(kind=kind)
            
            for conn in connections:
                # Match source and destination
                if (conn.laddr and conn.raddr and
                    conn.laddr.ip == src_ip and 
                    conn.laddr.port == src_port and
                    conn.raddr.ip == dest_ip and 
                    conn.raddr.port == dest_port):
                    
                    if conn.pid:
                        try:
                            process = psutil.Process(conn.pid)
                            return {
                                'pid': conn.pid,
                                'name': process.name(),
                                'exe_path': process.exe(),
                                'cmdline': ' '.join(process.cmdline())
                            }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
            
            # Fallback for connectionless protocols (UDP) or initial packets
            # where strict connection info isn't available in process table.
            # Many UDP apps bind to 0.0.0.0:port and send to various destinations
            # without establishing a connected socket (so raddr is empty).
            for conn in connections:
                if conn.pid and conn.laddr and conn.laddr.port == src_port:
                    # Check IP match (exact or wildcard)
                    # We accept if local socket is bound to the specific source IP
                    # OR if it's bound to all interfaces (0.0.0.0 / ::)
                    is_ip_match = (conn.laddr.ip == src_ip or 
                                 conn.laddr.ip == '0.0.0.0' or 
                                 conn.laddr.ip == '::')
                    
                    if is_ip_match:
                        try:
                            # Verify valid process
                            process = psutil.Process(conn.pid)
                            path = process.exe()
                            
                            # Only return if we can actually get the path
                            if path:
                                logger.debug(f"Found loose match for {src_ip}:{src_port} -> pid {conn.pid} ({process.name()})")
                                return {
                                    'pid': conn.pid,
                                    'name': process.name(),
                                    'exe_path': path,
                                    'cmdline': ' '.join(process.cmdline())
                                }
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass

            return None
            
        except Exception as e:
            logger.error(f"Error identifying application: {e}")
            return None
    
    @staticmethod
    def get_process_info(pid: int) -> Optional[Dict]:
        """Get process information by PID"""
        try:
            process = psutil.Process(pid)
            return {
                'pid': pid,
                'name': process.name(),
                'exe_path': process.exe(),
                'cmdline': ' '.join(process.cmdline())
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None


class PacketProcessor:
    """Processes packets from netfilter queue"""
    
    def __init__(self, decision_callback):
        """
        Initialize packet processor.
        
        Args:
            decision_callback: Function that takes PacketInfo and returns True (allow) or False (deny)
        """
        self.decision_callback = decision_callback
        self.identifier = ApplicationIdentifier()
        # Initialize eBPF identifier (will fallback gracefully if unavailable)
        # Initialize eBPF identifier (will fallback gracefully if unavailable)
        try:
            from .ebpf import EBPFIdentifier
            self.ebpf = EBPFIdentifier()
            if self.ebpf.available:
                logger.info("High-performance eBPF traffic identification enabled")
            else:
                logger.warning("eBPF identification unavailable (using legacy /proc scanning)")
        except Exception as e:
            logger.warning(f"Failed to load eBPF module: {e}")
            self.ebpf = None
        
        self.cache = ConnectionCache(ttl=120) # 2 minute cache
        self.nfqueue = None
        
        if not NETFILTER_AVAILABLE:
            raise RuntimeError("NetfilterQueue not available - cannot process packets")
    
    def process_packet(self, nfpacket):
        """
        Process a single packet from the netfilter queue.
        
        This is called for each packet that matches our iptables rule.
        """
        try:
            # Parse the packet
            packet = IP(nfpacket.get_payload())
            
            # Extract connection info
            protocol = None
            src_port = None
            dest_port = None
            
            if packet.haslayer(TCP):
                protocol = 'tcp'
                src_port = packet[TCP].sport
                dest_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                protocol = 'udp'
                src_port = packet[UDP].sport
                dest_port = packet[UDP].dport
            else:
                # Not TCP or UDP, accept by default
                nfpacket.accept()
                return

            # Create packet info
            pkt_info = PacketInfo(
                src_ip=packet.src,
                src_port=src_port,
                dest_ip=packet.dst,
                dest_port=dest_port,
                protocol=protocol
            )

            # 1. Check Cache First
            if src_port and protocol:
                cached_app = self.cache.get(src_port, protocol)
                if cached_app:
                    pkt_info.pid = cached_app['pid']
                    pkt_info.app_name = cached_app['name']
                    pkt_info.app_path = cached_app['path']
                    pkt_info.app_path = cached_app['path']
                    logger.debug(f"Cache hit for {src_port}/{protocol}: {pkt_info.app_name}")

            # 2. Try eBPF (High Performance, solves race condition)
            if not pkt_info.app_path and self.ebpf and self.ebpf.available:
                ebpf_info = self.ebpf.lookup(
                    packet.src, packet.dst, src_port, dest_port, protocol
                )
                if ebpf_info:
                    pkt_info.pid = ebpf_info['pid']
                    pkt_info.app_name = ebpf_info['comm']
                    # eBPF gives us comm (process name) but not full path.
                    # We can use PID to get path quickly without scanning all connections.
                    proc_info = self.identifier.get_process_info(pkt_info.pid)
                    if proc_info:
                        pkt_info.app_path = proc_info['exe_path']
                        # Update name to full name if possible
                        if proc_info.get('name'):
                            pkt_info.app_name = proc_info['name']
                    
                    logger.debug(f"eBPF hit: {pkt_info.app_name} (PID {pkt_info.pid})")
                    
                    # Update cache
                    if src_port and protocol:
                        self.cache.set(src_port, protocol, 
                                     pkt_info.pid, pkt_info.app_name, pkt_info.app_path)

            # 3. If not in cache and BPF missed, try legacy /proc scan
            if not pkt_info.app_path:
                # We use a retry mechanism to handle race conditions where the
                # socket is created but not yet visible in /proc (common for new TCP)
                app_info = None
                for attempt in range(10):
                    # Try strict match first
                    app_info = self.identifier.find_process_by_socket(
                        packet.src, src_port, packet.dst, dest_port, protocol
                    )
                    
                    if app_info:
                        break
                        
                    # If not found and it's TCP, wait a bit and retry
                    # This helps with "SYN_SENT" sockets that might lag in psutil
                    if protocol == 'tcp' and attempt < 9:
                        import time
                        time.sleep(0.05)  # Wait 50ms (total wait up to 500ms)
                
                if app_info:
                    pkt_info.pid = app_info['pid']
                    pkt_info.app_name = app_info['name']
                    pkt_info.app_path = app_info['exe_path']
                    
                    # Save to cache
                    if src_port and protocol:
                        self.cache.set(src_port, protocol, 
                                     app_info['pid'], app_info['name'], app_info['exe_path'])
                else:
                    logger.warning(f"Could not identify application for packet: {pkt_info}")

            # Get decision from callback
            allow = self.decision_callback(pkt_info)

            if allow:
                logger.debug(f"Accepting packet: {pkt_info}")
                nfpacket.accept()
            else:
                logger.debug(f"Dropping packet: {pkt_info}")
                nfpacket.drop()

        except Exception as e:
            logger.error(f"Error processing packet: {e}", exc_info=True)
            # On error, accept the packet to avoid breaking connectivity
            nfpacket.accept()

    def start(self, queue_num=1):
        """Start processing packets from netfilter queue"""
        if not NETFILTER_AVAILABLE:
            raise RuntimeError("NetfilterQueue not available")

        self.nfqueue = NetfilterQueue()
        self.nfqueue.bind(queue_num, self.process_packet)

        logger.info(f"Packet processor started on queue {queue_num}")

        try:
            self.nfqueue.run()
        except KeyboardInterrupt:
            logger.info("Packet processor interrupted")
        finally:
            self.stop()

    def stop(self):
        """Stop processing packets"""
        if self.nfqueue:
            self.nfqueue.unbind()
            logger.info("Packet processor stopped")


class IPTablesManager:
    """Manages iptables rules for packet queuing"""

    @staticmethod
    def setup_nfqueue(queue_num=1):
        """
        Set up iptables rules to queue outbound packets.
        Ensures a clean slate before adding rules to prevent duplicates.
        """

        # 0. Clean up existing rules first (Idempotency)
        # This prevents duplicate rules from accumulating (Fixes 16x duplicates issue)
        IPTablesManager.cleanup_nfqueue(queue_num)

        # Rule to queue new outbound connections
        rule = [
            'iptables', '-I', 'OUTPUT', '1',
            '-m', 'state', '--state', 'NEW',
            '-j', 'NFQUEUE', '--queue-num', str(queue_num)
        ]

        try:
            # 1. Insert NFQUEUE rule (will optionally be pushed down by bypass rules)
            result = subprocess.run(rule, capture_output=True, text=True, check=True)
            logger.info(f"Added iptables NFQUEUE rule: {' '.join(rule)}")

            # 2. Optimization: Bypass NFQUEUE for root and systemd services
            # "If root is compromised, we are compromised" -> minimal risk, high performance gain
            bypass_rules = [
                # Allow root (UID 0) - manages system updates, cron, etc.
                ['iptables', '-I', 'OUTPUT', '1', 
                 '-m', 'owner', '--uid-owner', '0', 
                 '-m', 'comment', '--comment', 'BASTION_BYPASS',
                 '-j', 'ACCEPT'],
                
                # Allow systemd-network (GID) - handles DHCP, etc.
                ['iptables', '-I', 'OUTPUT', '1', 
                 '-m', 'owner', '--gid-owner', 'systemd-network',
                 '-m', 'comment', '--comment', 'BASTION_BYPASS',
                 '-j', 'ACCEPT']
            ]

            for bypass in bypass_rules:
                try:
                    subprocess.run(bypass, capture_output=True, text=True, check=True)
                    logger.info(f"Added bypass rule: {' '.join(bypass)}")
                except subprocess.CalledProcessError as e:
                    # Non-fatal: some distros might lack systemd-network group
                    logger.debug(f"Could not add bypass rule (safe to ignore): {e}")

            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add iptables rule: {e.stderr}")
            return False

    @staticmethod
    def remove_nfqueue(queue_num=1):
        """Remove iptables NFQUEUE and bypass rules"""
        # Alias to cleanup_nfqueue for consistent behavior
        return IPTablesManager.cleanup_nfqueue(queue_num)

    @staticmethod
    def cleanup_nfqueue(queue_num=1):
        """
        Aggressively remove ALL NFQUEUE and BASTION_BYPASS rules.
        Ensures a completely clean state to prevent "connected but no internet".
        """

        logger.info("Cleaning up iptables NFQUEUE and BYPASS rules...")
        removed_count = 0

        # 1. Remove NFQUEUE rules (loop until none left)
        nfqueue_spec = [
            '-m', 'state', '--state', 'NEW',
            '-j', 'NFQUEUE', '--queue-num', str(queue_num)
        ]

        # Loop to remove duplicates (limit 50 to avoid infinite loop)
        for _ in range(50):
            try:
                cmd = ['iptables', '-D', 'OUTPUT'] + nfqueue_spec
                subprocess.run(cmd, capture_output=True, check=True)
                removed_count += 1
            except subprocess.CalledProcessError:
                # Failure means no more matching rules
                break

        # 2. Remove BASTION_BYPASS rules
        # We loop this to handle multiple rules and shifting indices
        for _ in range(20):
            try:
                # Query all OUTPUT rules
                result = subprocess.run(
                    ['iptables', '-S', 'OUTPUT'], 
                    capture_output=True, text=True, check=True
                )
                
                # Find any rule with our signature
                bypass_rules = [line for line in result.stdout.split('\n') 
                              if 'BASTION_BYPASS' in line]
                
                if not bypass_rules:
                    break
                
                deleted_in_pass = 0
                for line in bypass_rules:
                    # Line format: -A OUTPUT ...
                    parts = line.split()
                    if len(parts) > 2 and parts[0] == '-A':
                        # Convert -A (append) to -D (delete)
                        # parts[1] is the chain name (should be OUTPUT)
                        # We explicitly use OUTPUT to be safe, or use parts[1]
                        
                        # Fix: Ensure we include the chain name in the delete command
                        # parts looks like: ['-A', 'OUTPUT', '-m', ...]
                        # We want: iptables -D OUTPUT -m ...
                        del_cmd = ['iptables', '-D', parts[1]] + parts[2:]
                        
                        try:
                            subprocess.run(del_cmd, capture_output=True, check=True)
                            logger.info(f"Removed bypass rule: {' '.join(del_cmd)}")
                            removed_count += 1
                            deleted_in_pass += 1
                        except subprocess.CalledProcessError as e:
                            logger.debug(f"Failed to remove rule: {e}")
                            pass
                
                if deleted_in_pass == 0:
                    break
                    
            except subprocess.CalledProcessError:
                break

        if removed_count > 0:
            logger.info(f"Cleanup finished. Removed {removed_count} rules")
        else:
            logger.debug("No rules needed verification/cleanup")

        return removed_count

    @staticmethod
    def check_iptables_available():
        """Check if iptables is available"""

        try:
            result = subprocess.run(['which', 'iptables'],
                                  capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False

