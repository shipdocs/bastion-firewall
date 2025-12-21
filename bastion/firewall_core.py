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
                f"{self.dest_ip}:{self.dest_port} via {self.protocol})")


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

            # Try to identify the application
            app_info = self.identifier.find_process_by_socket(
                packet.src, src_port, packet.dst, dest_port, protocol
            )

            if app_info:
                pkt_info.pid = app_info['pid']
                pkt_info.app_name = app_info['name']
                pkt_info.app_path = app_info['exe_path']
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

