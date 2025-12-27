#!/usr/bin/env python3
"""
Live Network Anomaly Detection using UNSW-NB15 Trained Model
============================================================

Captures live network packets, extracts UNSW-NB15 compatible features,
and detects anomalies using the trained Gradient Boosting model.

Requirements:
- Scapy for packet capture
- Root/sudo permissions for packet capture
- Trained model: trained_models/unsw_attack_detector.joblib

Usage:
    sudo python3 live_anomaly_detection.py
    sudo python3 live_anomaly_detection.py --interface eth0
    sudo python3 live_anomaly_detection.py --threshold 0.8
"""
import argparse
import csv
import json
import os
import sys
import time
import warnings
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import joblib
import numpy as np
import pandas as pd

warnings.filterwarnings('ignore')

# Try to import scapy
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    print("ERROR: Scapy not installed. Install with: pip install scapy")
    SCAPY_AVAILABLE = False
    sys.exit(1)


class FlowTracker:
    """
    Tracks network flows and extracts UNSW-NB15 compatible features.
    """
    
    def __init__(self, flow_timeout: int = 120):
        self.flows = defaultdict(lambda: {
            'packets': [],
            'start_time': None,
            'last_time': None,
            'fwd_packets': [],
            'bwd_packets': [],
            'flags': defaultdict(int),
        })
        self.flow_timeout = flow_timeout
        
    def get_flow_key(self, packet) -> Optional[str]:
        """Generate unique bidirectional flow key."""
        if not packet.haslayer(IP):
            return None
        
        ip = packet[IP]
        proto = ip.proto
        
        # Get ports if TCP/UDP
        if packet.haslayer(TCP):
            sport, dport = packet[TCP].sport, packet[TCP].dport
            proto_name = 'tcp'
        elif packet.haslayer(UDP):
            sport, dport = packet[UDP].sport, packet[UDP].dport
            proto_name = 'udp'
        else:
            sport, dport = 0, 0
            proto_name = str(proto)
        
        # Create bidirectional flow key (normalize direction)
        if (ip.src, sport) < (ip.dst, dport):
            return f"{ip.src}:{sport}-{ip.dst}:{dport}-{proto_name}"
        else:
            return f"{ip.dst}:{dport}-{ip.src}:{sport}-{proto_name}"
    
    def clean_old_flows(self):
        """Remove expired flows."""
        current_time = time.time()
        expired = []
        
        for flow_key, flow_data in self.flows.items():
            if flow_data['last_time'] and (current_time - flow_data['last_time']) > self.flow_timeout:
                expired.append(flow_key)
        
        for key in expired:
            del self.flows[key]
    
    def update_flow(self, packet, flow_key: str):
        """Update flow statistics with new packet."""
        if not packet.haslayer(IP):
            return
        
        flow = self.flows[flow_key]
        current_time = time.time()
        
        # Initialize flow
        if flow['start_time'] is None:
            flow['start_time'] = current_time
        
        flow['last_time'] = current_time
        
        # Packet info
        pkt_size = len(packet)
        pkt_info = {
            'time': current_time,
            'size': pkt_size,
            'src': packet[IP].src,
            'dst': packet[IP].dst,
        }
        
        # Direction detection (simplified)
        first_src = flow['packets'][0]['src'] if flow['packets'] else packet[IP].src
        if packet[IP].src == first_src:
            flow['fwd_packets'].append(pkt_info)
        else:
            flow['bwd_packets'].append(pkt_info)
        
        flow['packets'].append(pkt_info)
        
        # TCP flags
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            if tcp.flags.F: flow['flags']['FIN'] += 1
            if tcp.flags.S: flow['flags']['SYN'] += 1
            if tcp.flags.R: flow['flags']['RST'] += 1
            if tcp.flags.P: flow['flags']['PSH'] += 1
            if tcp.flags.A: flow['flags']['ACK'] += 1
            if tcp.flags.U: flow['flags']['URG'] += 1
    
    def extract_features(self, flow_key: str) -> Dict:
        """
        Extract UNSW-NB15 compatible features from flow.
        
        UNSW-NB15 has 42 features (excluding id, label, attack_cat):
        - Duration, protocol, state info
        - Packet counts and bytes (forward/backward)
        - Statistical features (mean, std, min, max)
        - Inter-arrival times
        - TCP window and flags
        - Service-specific features
        """
        flow = self.flows[flow_key]
        
        if not flow['packets']:
            return self._get_default_features()
        
        # Basic flow info
        duration = flow['last_time'] - flow['start_time'] if flow['start_time'] else 0.0
        
        fwd_pkts = flow['fwd_packets']
        bwd_pkts = flow['bwd_packets']
        
        total_fwd = len(fwd_pkts)
        total_bwd = len(bwd_pkts)
        
        fwd_bytes = sum(p['size'] for p in fwd_pkts)
        bwd_bytes = sum(p['size'] for p in bwd_pkts)
        
        # Calculate rates
        rate = (total_fwd + total_bwd) / duration if duration > 0 else 0
        
        # Packet sizes
        fwd_sizes = [p['size'] for p in fwd_pkts] if fwd_pkts else [0]
        bwd_sizes = [p['size'] for p in bwd_pkts] if bwd_pkts else [0]
        
        # Inter-arrival times
        all_times = [p['time'] for p in flow['packets']]
        iats = [all_times[i+1] - all_times[i] for i in range(len(all_times)-1)] if len(all_times) > 1 else [0]
        
        fwd_times = [p['time'] for p in fwd_pkts]
        fwd_iats = [fwd_times[i+1] - fwd_times[i] for i in range(len(fwd_times)-1)] if len(fwd_times) > 1 else [0]
        
        bwd_times = [p['time'] for p in bwd_pkts]
        bwd_iats = [bwd_times[i+1] - bwd_times[i] for i in range(len(bwd_times)-1)] if len(bwd_times) > 1 else [0]
        
        # Protocol
        parts = flow_key.split('-')
        proto = parts[-1] if len(parts) > 2 else 'unknown'
        
        # State (simplified)
        state = 'FIN' if flow['flags']['FIN'] > 0 else 'CON'
        
        # Build feature dictionary matching UNSW-NB15 schema
        features = {
            # Basic flow features
            'dur': duration,
            'proto': proto,
            'service': '-',  # Would need deep packet inspection
            'state': state,
            'spkts': total_fwd,
            'dpkts': total_bwd,
            'sbytes': fwd_bytes,
            'dbytes': bwd_bytes,
            'rate': rate,
            
            # TTL (would need packet capture)
            'sttl': 64,  # Default assumption
            'dttl': 64,
            
            # Load
            'sload': (fwd_bytes * 8) / duration if duration > 0 else 0,  # bits per second
            'dload': (bwd_bytes * 8) / duration if duration > 0 else 0,
            
            # Loss (simplified - would need sequence analysis)
            'sloss': 0,
            'dloss': 0,
            
            # Inter-packet times (microseconds)
            'sinpkt': np.mean(fwd_iats) * 1e6 if fwd_iats and fwd_iats[0] > 0 else 0,
            'dinpkt': np.mean(bwd_iats) * 1e6 if bwd_iats and bwd_iats[0] > 0 else 0,
            
            # Jitter (std of inter-arrival times)
            'sjit': np.std(fwd_iats) * 1e6 if len(fwd_iats) > 1 else 0,
            'djit': np.std(bwd_iats) * 1e6 if len(bwd_iats) > 1 else 0,
            
            # Window sizes (would need from packets)
            'swin': 8192,  # Default
            'dwin': 8192,
            'stcpb': 0,
            'dtcpb': 0,
            
            # TCP specific
            'tcprtt': 0,  # Would need SYN/ACK timing
            'synack': 0,
            'ackdat': 0,
            
            # Mean packet sizes
            'smean': np.mean(fwd_sizes) if fwd_sizes else 0,
            'dmean': np.mean(bwd_sizes) if bwd_sizes else 0,
            
            # Transaction depth (simplified)
            'trans_depth': len(flow['packets']),
            'response_body_len': bwd_bytes,
            
            # Connection state features (simplified)
            'ct_srv_src': 1,  # Would need cross-flow analysis
            'ct_state_ttl': 1,
            'ct_dst_ltm': 1,
            'ct_src_dport_ltm': 1,
            'ct_dst_sport_ltm': 1,
            'ct_dst_src_ltm': 1,
            
            # FTP features
            'is_ftp_login': 0,
            'ct_ftp_cmd': 0,
            
            # HTTP features
            'ct_flw_http_mthd': 0,
            'ct_src_ltm': 1,
            'ct_srv_dst': 1,
            
            # Same IP/Port
            'is_sm_ips_ports': 0,
        }
        
        return features
    
    def _get_default_features(self) -> Dict:
        """Return default feature values."""
        return {
            'dur': 0, 'proto': 'tcp', 'service': '-', 'state': 'CON',
            'spkts': 0, 'dpkts': 0, 'sbytes': 0, 'dbytes': 0, 'rate': 0,
            'sttl': 64, 'dttl': 64, 'sload': 0, 'dload': 0,
            'sloss': 0, 'dloss': 0, 'sinpkt': 0, 'dinpkt': 0,
            'sjit': 0, 'djit': 0, 'swin': 0, 'dwin': 0,
            'stcpb': 0, 'dtcpb': 0, 'tcprtt': 0, 'synack': 0, 'ackdat': 0,
            'smean': 0, 'dmean': 0, 'trans_depth': 0, 'response_body_len': 0,
            'ct_srv_src': 0, 'ct_state_ttl': 0, 'ct_dst_ltm': 0,
            'ct_src_dport_ltm': 0, 'ct_dst_sport_ltm': 0, 'ct_dst_src_ltm': 0,
            'is_ftp_login': 0, 'ct_ftp_cmd': 0, 'ct_flw_http_mthd': 0,
            'ct_src_ltm': 0, 'ct_srv_dst': 0, 'is_sm_ips_ports': 0,
        }


class LiveAnomalyDetector:
    """
    Real-time network anomaly detection system.
    """
    
    def __init__(self, model_path: str, threshold: float = 0.5, log_dir: str = "logs"):
        self.model = self.load_model(model_path)
        self.threshold = threshold
        self.flow_tracker = FlowTracker()
        self.log_dir = Path(log_dir)
        
        # Create log directory
        self.log_dir.mkdir(exist_ok=True)
        
        # Initialize log files with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.anomaly_log_csv = self.log_dir / f"anomalies_{timestamp}.csv"
        self.anomaly_log_json = self.log_dir / f"anomalies_{timestamp}.json"
        self.flow_log_csv = self.log_dir / f"flows_{timestamp}.csv"
        self.session_log = self.log_dir / f"session_{timestamp}.json"
        
        # Initialize CSV files with headers
        self._init_log_files()
        
        # Statistics
        self.stats = {
            'packets_captured': 0,
            'flows_analyzed': 0,
            'anomalies_detected': 0,
            'start_time': time.time(),
        }
        
        print(f"📁 Logs will be saved to: {self.log_dir.absolute()}/")
        print(f"   - Anomalies: {self.anomaly_log_csv.name}")
        print(f"   - Flows: {self.flow_log_csv.name}")
        print(f"   - Session: {self.session_log.name}\n")
    
    def _init_log_files(self):
        """Initialize CSV log files with headers."""
        # Anomaly log CSV headers
        anomaly_headers = [
            'timestamp', 'flow_key', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'confidence', 'duration', 'packets_fwd', 'packets_bwd',
            'bytes_fwd', 'bytes_bwd', 'rate', 'prediction'
        ]
        
        with open(self.anomaly_log_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=anomaly_headers)
            writer.writeheader()
        
        # Flow log CSV headers
        flow_headers = [
            'timestamp', 'flow_key', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'protocol', 'duration', 'packets_fwd', 'packets_bwd',
            'bytes_fwd', 'bytes_bwd', 'rate'
        ]
        
        with open(self.flow_log_csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=flow_headers)
            writer.writeheader()
        
        # Initialize JSON log files
        with open(self.anomaly_log_json, 'w') as f:
            json.dump([], f)
    
    def load_model(self, model_path: str):
        """Load trained model."""
        print(f"Loading model from: {model_path}")
        
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Model not found: {model_path}")
        
        model = joblib.load(model_path)
        print("✓ Model loaded successfully\n")
        return model
    
    def packet_handler(self, packet):
        """Handle each captured packet."""
        self.stats['packets_captured'] += 1
        
        # Get flow key
        flow_key = self.flow_tracker.get_flow_key(packet)
        if flow_key is None:
            return
        
        # Update flow
        self.flow_tracker.update_flow(packet, flow_key)
        
        # Analyze flow every N packets (to avoid too frequent predictions)
        flow = self.flow_tracker.flows[flow_key]
        if len(flow['packets']) % 10 == 0 and len(flow['packets']) >= 10:
            self.analyze_flow(flow_key, packet)
        
        # Periodic cleanup
        if self.stats['packets_captured'] % 100 == 0:
            self.flow_tracker.clean_old_flows()
            self.print_stats()
    
    def analyze_flow(self, flow_key: str, packet):
        """Extract features and predict anomaly."""
        try:
            # Extract features
            features = self.flow_tracker.extract_features(flow_key)
            features_df = pd.DataFrame([features])
            
            # Predict
            prediction = self.model.predict(features_df)[0]
            probability = self.model.predict_proba(features_df)[0][1]  # Probability of attack
            
            self.stats['flows_analyzed'] += 1
            
            # Log all flows
            self.log_flow(flow_key, packet, features)
            
            # Check if anomaly
            if prediction == 1 and probability >= self.threshold:
                self.stats['anomalies_detected'] += 1
                self.print_alert(flow_key, packet, probability, features)
                self.log_anomaly(flow_key, packet, probability, features, prediction)
        
        except Exception as e:
            print(f"[ERROR] Analysis failed: {e}")
            import traceback
            traceback.print_exc()
    
    def print_alert(self, flow_key: str, packet, probability: float, features: Dict):
        """Print anomaly alert."""
        print("\n" + "="*80)
        print("🚨 ANOMALY DETECTED!")
        print("="*80)
        print(f"Time:        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Flow:        {flow_key}")
        
        if packet.haslayer(IP):
            ip = packet[IP]
            print(f"Source:      {ip.src}")
            print(f"Destination: {ip.dst}")
            print(f"Protocol:    {features['proto']}")
        
        print(f"Confidence:  {probability:.2%}")
        print(f"Duration:    {features['dur']:.2f}s")
        print(f"Packets:     {features['spkts']} fwd, {features['dpkts']} bwd")
        print(f"Bytes:       {features['sbytes']} fwd, {features['dbytes']} bwd")
        print(f"Rate:        {features['rate']:.2f} pkt/s")
        print("="*80 + "\n")
    
    def log_anomaly(self, flow_key: str, packet, probability: float, features: Dict, prediction: int):
        """Log detected anomaly to CSV and JSON."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Parse flow_key
        parts = flow_key.split('-')
        src_ip, src_port = parts[0].rsplit(':', 1)
        dst_ip, dst_port = parts[1].rsplit(':', 1)
        protocol = parts[2]
        
        # Create log entry
        log_entry = {
            'timestamp': timestamp,
            'flow_key': flow_key,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'confidence': float(probability),
            'duration': float(features['dur']),
            'packets_fwd': int(features['spkts']),
            'packets_bwd': int(features['dpkts']),
            'bytes_fwd': int(features['sbytes']),
            'bytes_bwd': int(features['dbytes']),
            'rate': float(features['rate']),
            'prediction': int(prediction)
        }
        
        # Write to CSV
        with open(self.anomaly_log_csv, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=log_entry.keys())
            writer.writerow(log_entry)
        
        # Append to JSON
        try:
            with open(self.anomaly_log_json, 'r') as f:
                anomalies = json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            anomalies = []
        
        # Add detailed features to JSON
        json_entry = log_entry.copy()
        json_entry['all_features'] = {k: float(v) if isinstance(v, (int, float, np.number)) else str(v) 
                                      for k, v in features.items()}
        anomalies.append(json_entry)
        
        with open(self.anomaly_log_json, 'w') as f:
            json.dump(anomalies, f, indent=2)
    
    def log_flow(self, flow_key: str, packet, features: Dict):
        """Log all analyzed flows to CSV."""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Parse flow_key
        parts = flow_key.split('-')
        src_ip, src_port = parts[0].rsplit(':', 1)
        dst_ip, dst_port = parts[1].rsplit(':', 1)
        protocol = parts[2]
        
        # Create log entry
        log_entry = {
            'timestamp': timestamp,
            'flow_key': flow_key,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'duration': float(features['dur']),
            'packets_fwd': int(features['spkts']),
            'packets_bwd': int(features['dpkts']),
            'bytes_fwd': int(features['sbytes']),
            'bytes_bwd': int(features['dbytes']),
            'rate': float(features['rate'])
        }
        
        # Write to CSV
        with open(self.flow_log_csv, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=log_entry.keys())
            writer.writerow(log_entry)
    
    def print_stats(self):
        """Print periodic statistics."""
        runtime = time.time() - self.stats['start_time']
        pps = self.stats['packets_captured'] / runtime if runtime > 0 else 0
        
        print(f"\r📊 Stats: {self.stats['packets_captured']} pkts | "
              f"{self.stats['flows_analyzed']} flows | "
              f"{self.stats['anomalies_detected']} anomalies | "
              f"{pps:.1f} pps", end='', flush=True)
    
    def start_capture(self, interface: Optional[str] = None, filter_str: str = "ip"):
        """Start packet capture."""
        print("="*80)
        print("🔍 LIVE NETWORK ANOMALY DETECTION")
        print("="*80)
        print(f"Interface:  {interface or 'default'}")
        print(f"Filter:     {filter_str}")
        print(f"Threshold:  {self.threshold:.2f}")
        print(f"Model:      Gradient Boosting (87.31% accuracy)")
        print("\nPress Ctrl+C to stop...")
        print("="*80 + "\n")
        
        try:
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self.packet_handler,
                store=0
            )
        except KeyboardInterrupt:
            print("\n\n🛑 Stopping capture...")
            self.save_session_summary()
            self.print_final_stats()
        except PermissionError:
            print("\n❌ ERROR: Permission denied")
            print("Please run with sudo: sudo python3 live_anomaly_detection.py")
        except Exception as e:
            print(f"\n❌ ERROR: {e}")
    
    def save_session_summary(self):
        """Save session summary to JSON file."""
        runtime = time.time() - self.stats['start_time']
        pps = self.stats['packets_captured'] / runtime if runtime > 0 else 0
        anomaly_rate = (self.stats['anomalies_detected'] / self.stats['flows_analyzed'] * 100) if self.stats['flows_analyzed'] > 0 else 0
        
        summary = {
            'session_info': {
                'start_time': datetime.fromtimestamp(self.stats['start_time']).strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'duration_seconds': float(runtime),
                'threshold': float(self.threshold)
            },
            'statistics': {
                'packets_captured': int(self.stats['packets_captured']),
                'flows_analyzed': int(self.stats['flows_analyzed']),
                'anomalies_detected': int(self.stats['anomalies_detected']),
                'capture_rate_pps': float(pps),
                'anomaly_rate_percent': float(anomaly_rate)
            },
            'log_files': {
                'anomalies_csv': str(self.anomaly_log_csv),
                'anomalies_json': str(self.anomaly_log_json),
                'flows_csv': str(self.flow_log_csv)
            }
        }
        
        with open(self.session_log, 'w') as f:
            json.dump(summary, f, indent=2)
        
        print(f"💾 Session summary saved to: {self.session_log}")
    
    def print_final_stats(self):
        """Print final statistics."""
        runtime = time.time() - self.stats['start_time']
        
        print("\n" + "="*80)
        print("📊 FINAL STATISTICS")
        print("="*80)
        print(f"Runtime:             {runtime:.1f} seconds")
        print(f"Packets Captured:    {self.stats['packets_captured']:,}")
        print(f"Flows Analyzed:      {self.stats['flows_analyzed']:,}")
        print(f"Anomalies Detected:  {self.stats['anomalies_detected']:,}")
        
        if self.stats['packets_captured'] > 0:
            pps = self.stats['packets_captured'] / runtime
            anomaly_rate = (self.stats['anomalies_detected'] / self.stats['flows_analyzed'] * 100) if self.stats['flows_analyzed'] > 0 else 0
            
            print(f"Capture Rate:        {pps:.1f} packets/second")
            print(f"Anomaly Rate:        {anomaly_rate:.2f}%")
        
        print(f"\n📁 Log files saved in: {self.log_dir.absolute()}/")
        print(f"   - {self.anomaly_log_csv.name}")
        print(f"   - {self.anomaly_log_json.name}")
        print(f"   - {self.flow_log_csv.name}")
        print(f"   - {self.session_log.name}")
        print("="*80)


def main():
    parser = argparse.ArgumentParser(
        description='Live network anomaly detection using UNSW-NB15 trained model'
    )
    parser.add_argument(
        '--model',
        default='trained_models/unsw_attack_detector.joblib',
        help='Path to trained model'
    )
    parser.add_argument(
        '--interface',
        '-i',
        default=None,
        help='Network interface to capture on (default: all interfaces)'
    )
    parser.add_argument(
        '--filter',
        '-f',
        default='ip',
        help='BPF filter for packet capture (default: ip)'
    )
    parser.add_argument(
        '--threshold',
        '-t',
        type=float,
        default=0.7,
        help='Detection threshold (0.0-1.0, default: 0.7)'
    )
    parser.add_argument(
        '--log-dir',
        '-l',
        default=None,
        help='Directory to save log files (default: logs in script directory)'
    )
    args = parser.parse_args()
    
    # If log_dir not specified, use 'logs' directory relative to script location
    if args.log_dir is None:
        script_dir = Path(__file__).parent.absolute()
        args.log_dir = str(script_dir / 'logs')
    
    # Check for root permissions
    if os.geteuid() != 0:
        print("⚠️  WARNING: Not running as root.")
        print("Packet capture requires root permissions.")
        print("Please run: sudo python3 live_anomaly_detection.py")
        print()
    
    try:
        detector = LiveAnomalyDetector(args.model, args.threshold, args.log_dir)
        detector.start_capture(args.interface, args.filter)
    except Exception as e:
        print(f"\n❌ FATAL ERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    if not SCAPY_AVAILABLE:
        print("Please install scapy: pip install scapy")
        sys.exit(1)
    
    main()
