#!/usr/bin/env python3
"""
Firewall Core - Netfilter packet interception and processing

This module handles the low-level packet interception using NetfilterQueue
and identifies which application is making each connection.
"""

import os
import sys
import logging
import socket
import struct
from pathlib import Path
from typing import Optional, Dict, Tuple
import psutil

logger = logging.getLogger(__name__)

try:
    from netfilterqueue import NetfilterQueue
    from scapy.all import IP, TCP, UDP
    NETFILTER_AVAILABLE = True
except ImportError:
    NETFILTER_AVAILABLE = False
    logger.warning("NetfilterQueue or scapy not available - running in limited mode")


class PacketInfo:
    """Information about a network packet"""
    
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
    """
    Cache identified connections to handle retransmissions and consistent identification.
    
    Stores: (src_port, protocol) -> (pid, app_name, app_path, timestamp)
    
    Since we intercept NEW packets, we might see retransmissions of the SYN,
    or we might look up a connection once and want to remember it for a short time.
    Local source ports are unique per protocol.
    """
    def __init__(self, ttl=60):
        self.cache = {}
        self.ttl = ttl
        
    def get(self, src_port, protocol):
        import time
        now = time.time()
        
        # Cleanup old entries while we are here (lazy cleanup)
        # In a high-volume system, we'd use a separate cleanup thread, 
        # but for a personal firewall this is fine.
        keys_to_delete = [k for k, v in self.cache.items() if now - v['time'] > self.ttl]
        for k in keys_to_delete:
            del self.cache[k]
            
        key = (src_port, protocol)
        if key in self.cache:
            entry = self.cache[key]
            # Verify PID still exists? Optional, but safer to assume 
            # port reuse is slower than our TTL for *different* apps.
            return entry
        return None
        
    def set(self, src_port, protocol, pid, name, path):
        import time
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
                    logger.debug(f"Cache hit for {src_port}/{protocol}: {pkt_info.app_name}")

            # 2. If not in cache, try to identify
            if not pkt_info.app_path:
                # We use a retry mechanism to handle race conditions where the
                # socket is created but not yet visible in /proc (common for new TCP)
                app_info = None
                for attempt in range(5):
                    # Try strict match first
                    app_info = self.identifier.find_process_by_socket(
                        packet.src, src_port, packet.dst, dest_port, protocol
                    )
                    
                    if app_info:
                        break
                        
                    # If not found and it's TCP, wait a bit and retry
                    # This helps with "SYN_SENT" sockets that might lag in psutil
                    if protocol == 'tcp' and attempt < 4:
                        import time
                        time.sleep(0.05)  # Wait 50ms (total wait up to 200ms)
                
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

        This adds an iptables rule to send new outbound connections to NFQUEUE.
        """
        import subprocess

        # Rule to queue new outbound connections
        rule = [
            'iptables', '-I', 'OUTPUT', '1',
            '-m', 'state', '--state', 'NEW',
            '-j', 'NFQUEUE', '--queue-num', str(queue_num)
        ]

        try:
            result = subprocess.run(rule, capture_output=True, text=True, check=True)
            logger.info(f"Added iptables NFQUEUE rule: {' '.join(rule)}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to add iptables rule: {e.stderr}")
            return False

    @staticmethod
    def remove_nfqueue(queue_num=1):
        """Remove iptables NFQUEUE rules"""
        import subprocess

        rule = [
            'iptables', '-D', 'OUTPUT',
            '-m', 'state', '--state', 'NEW',
            '-j', 'NFQUEUE', '--queue-num', str(queue_num)
        ]

        try:
            subprocess.run(rule, capture_output=True, text=True, check=True)
            logger.info("Removed iptables NFQUEUE rule")
            return True
        except subprocess.CalledProcessError:
            # Rule might not exist, that's okay
            return False

    @staticmethod
    def cleanup_nfqueue(queue_num=1):
        """
        Aggressively remove ALL NFQUEUE rules to ensure clean shutdown.
        This prevents the "WiFi connected but no internet" issue.
        """
        import subprocess

        logger.info("Cleaning up iptables NFQUEUE rules...")
        removed_count = 0

        # Try to remove the specific rule multiple times (in case of duplicates)
        for _ in range(10):
            if IPTablesManager.remove_nfqueue(queue_num):
                removed_count += 1
            else:
                break

        # Double-check: list all OUTPUT rules and remove any NFQUEUE rules
        try:
            result = subprocess.run(
                ['iptables', '-S', 'OUTPUT'],
                capture_output=True, text=True, check=True
            )

            for line in result.stdout.split('\n'):
                if 'NFQUEUE' in line and '--queue-num' in line:
                    # Extract the rule and remove it
                    # Line format: -A OUTPUT -m state --state NEW -j NFQUEUE --queue-num 1
                    parts = line.split()
                    if len(parts) > 2 and parts[0] == '-A':
                        # Convert -A to -D for deletion
                        delete_cmd = ['iptables', '-D'] + parts[2:]
                        try:
                            subprocess.run(delete_cmd, capture_output=True, check=True)
                            removed_count += 1
                            logger.info(f"Removed NFQUEUE rule: {' '.join(delete_cmd)}")
                        except subprocess.CalledProcessError:
                            pass
        except subprocess.CalledProcessError as e:
            logger.warning(f"Could not list iptables rules: {e}")

        if removed_count > 0:
            logger.info(f"Removed {removed_count} NFQUEUE rule(s)")
        else:
            logger.info("No NFQUEUE rules to remove")

        return removed_count

    @staticmethod
    def check_iptables_available():
        """Check if iptables is available"""
        import subprocess

        try:
            result = subprocess.run(['which', 'iptables'],
                                  capture_output=True, text=True)
            return result.returncode == 0
        except Exception:
            return False

