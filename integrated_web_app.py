#!/usr/bin/env python3
"""
Integrated Network Anomaly Detection Web Application
====================================================

This application integrates the live anomaly detection with a web interface.
It manages the live detection process and displays real-time results.

Requirements:
- Root/sudo permissions (for packet capture)
- FastAPI, uvicorn
- All dependencies from live_anomaly_detection.py

Usage:
    sudo python3 integrated_web_app.py --interface enp1s0 --threshold 0.7
    Then open http://localhost:8000 in your browser
"""
import argparse
import asyncio
import json
import os
import subprocess
import sys
import signal
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional
from collections import deque
from contextlib import asynccontextmanager
from queue import Queue

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import logging

# Check if running as root
if os.geteuid() != 0:
    print("=" * 80)
    print("⚠️  ERROR: This application requires root/sudo privileges")
    print("=" * 80)
    print("Packet capture requires administrative permissions.")
    print("\nPlease run with sudo:")
    print(f"    sudo python3 {sys.argv[0]} --interface <interface> --threshold <threshold>")
    print("\nExample:")
    print(f"    sudo python3 {sys.argv[0]} --interface eth0 --threshold 0.7")
    print("=" * 80)
    sys.exit(1)

# Lifespan context manager for startup/shutdown events
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    asyncio.create_task(monitor_logs())
    asyncio.create_task(process_message_queue())
    yield
    # Shutdown
    stop_detection()

# Initialize FastAPI app with lifespan
app = FastAPI(
    title="Network Anomaly Detection System",
    description="Real-time network intrusion detection and monitoring",
    version="2.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
detection_process = None
anomaly_buffer = deque(maxlen=1000)  # Store last 1000 anomalies in memory
flow_buffer = deque(maxlen=1000)  # Store last 1000 flows in memory
message_queue = Queue()  # Thread-safe queue for messages from parser thread
stats = {
    "total_anomalies": 0,
    "total_flows": 0,
    "packets_captured": 0,
    "detection_active": False,
    "start_time": None,
    "interface": None,
    "threshold": None,
}

# Setup directories
SCRIPT_DIR = Path(__file__).parent
LOGS_DIR = SCRIPT_DIR / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Configure Splunk-compatible logging
splunk_logger = logging.getLogger('splunk_forwarder')
splunk_logger.setLevel(logging.INFO)
splunk_handler = logging.FileHandler(LOGS_DIR / 'splunk_anomalies.log')
splunk_formatter = logging.Formatter('%(message)s')  # JSON format, no extra formatting
splunk_handler.setFormatter(splunk_formatter)
splunk_logger.addHandler(splunk_handler)

def log_to_splunk(anomaly_data):
    """Log anomaly in Splunk-compatible JSON format."""
    splunk_event = {
        "timestamp": anomaly_data.get("timestamp", datetime.now().isoformat()),
        "event_type": "network_anomaly",
        "severity": "high" if anomaly_data.get("confidence", 0) >= 90 else ("medium" if anomaly_data.get("confidence", 0) >= 75 else "low"),
        "source_ip": anomaly_data.get("source", "N/A"),
        "destination_ip": anomaly_data.get("destination", "N/A"),
        "protocol": anomaly_data.get("protocol", "N/A"),
        "flow_id": anomaly_data.get("flow", "N/A"),
        "confidence_score": anomaly_data.get("confidence", 0),
        "duration_seconds": anomaly_data.get("duration", 0),
        "packet_count": anomaly_data.get("packets_info", "N/A"),
        "byte_count": anomaly_data.get("bytes_info", "N/A"),
        "packet_rate": anomaly_data.get("rate", 0),
        "detection_time": anomaly_data.get("time", "N/A"),
        "anomaly_id": anomaly_data.get("id", 0),
        "interface": stats.get("interface", "N/A"),
        "threshold": stats.get("threshold", 0)
    }
    splunk_logger.info(json.dumps(splunk_event))

# Configuration
LOGS_DIR = Path("logs")
MODELS_DIR = Path("trained_models")
SCRIPT_DIR = Path(__file__).parent.absolute()

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Broadcast message to all connected clients."""
        for connection in self.active_connections[:]:  # Copy list to avoid modification during iteration
            try:
                await connection.send_json(message)
            except Exception as e:
                self.active_connections.remove(connection)

manager = ConnectionManager()


# Helper functions
def get_latest_files(directory: Path, pattern: str) -> List[Path]:
    """Get latest files matching pattern sorted by modification time."""
    files = list(directory.glob(pattern))
    return sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)


def parse_detection_output():
    """Parse live detection output and broadcast updates (runs in thread)."""
    global detection_process, stats
    
    if detection_process is None:
        return
    
    current_anomaly = {}
    
    try:
        while detection_process and detection_process.poll() is None:
            line = detection_process.stdout.readline()
            if not line:
                time.sleep(0.1)
                continue
            
            line = line.decode('utf-8', errors='ignore').strip()
            
            # Parse anomaly detection
            if "🚨 ANOMALY DETECTED!" in line:
                if current_anomaly:
                    # Save previous anomaly
                    anomaly_buffer.append(current_anomaly)
                    stats["total_anomalies"] += 1
                    # Log to Splunk
                    log_to_splunk(current_anomaly)
                    
                    # Put message in queue for async processing
                    message_queue.put({
                        "type": "anomaly",
                        "data": current_anomaly
                    })
                current_anomaly = {
                    "timestamp": datetime.now().isoformat(),
                    "id": stats["total_anomalies"] + 1
                }
            
            # Parse anomaly fields
            elif "Time:" in line and current_anomaly:
                current_anomaly["time"] = line.split("Time:")[1].strip()
            elif "Flow:" in line and current_anomaly:
                current_anomaly["flow"] = line.split("Flow:")[1].strip()
            elif "Source:" in line and current_anomaly:
                current_anomaly["source"] = line.split("Source:")[1].strip()
            elif "Destination:" in line and current_anomaly:
                current_anomaly["destination"] = line.split("Destination:")[1].strip()
            elif "Protocol:" in line and current_anomaly:
                current_anomaly["protocol"] = line.split("Protocol:")[1].strip()
            elif "Confidence:" in line and current_anomaly:
                conf_str = line.split("Confidence:")[1].strip().replace("%", "")
                current_anomaly["confidence"] = float(conf_str)
            elif "Duration:" in line and current_anomaly:
                dur_str = line.split("Duration:")[1].strip().replace("s", "")
                current_anomaly["duration"] = float(dur_str)
            elif "Packets:" in line and current_anomaly:
                parts = line.split("Packets:")[1].strip()
                current_anomaly["packets_info"] = parts
            elif "Bytes:" in line and current_anomaly:
                parts = line.split("Bytes:")[1].strip()
                current_anomaly["bytes_info"] = parts
            elif "Rate:" in line and current_anomaly:
                rate_str = line.split("Rate:")[1].strip().replace("pkt/s", "").strip()
                current_anomaly["rate"] = float(rate_str)
            
            # Parse stats
            elif "Stats:" in line:
                try:
                    # Remove emoji and split by |
                    clean_line = line.replace("📊", "").strip()
                    parts = clean_line.split("|")
                    for part in parts:
                        part = part.strip()
                        if "pkts" in part:
                            num = ''.join(filter(str.isdigit, part.split()[0]))
                            if num:
                                stats["packets_captured"] = int(num)
                        elif "flows" in part:
                            num = ''.join(filter(str.isdigit, part.split()[0]))
                            if num:
                                stats["total_flows"] = int(num)
                        elif "anomalies" in part:
                            # Update from detection output if needed
                            pass
                    
                    # Put message in queue for async processing
                    message_queue.put({
                        "type": "stats",
                        "data": stats.copy()
                    })
                except Exception as e:
                    print(f"Error parsing stats line: {e}")
            
            time.sleep(0.01)  # Small delay to prevent CPU spinning
            
    except Exception as e:
        print(f"Error parsing detection output: {e}")


def start_detection(interface: str, threshold: float):
    """Start the live anomaly detection process."""
    global detection_process, stats
    
    stats["detection_active"] = True
    stats["start_time"] = datetime.now().isoformat()
    stats["interface"] = interface
    stats["threshold"] = threshold
    
    # Use the same Python interpreter that's running this script
    python_executable = sys.executable
    
    cmd = [
        python_executable,
        str(SCRIPT_DIR / "live_anomaly_detection.py"),
        "--interface", interface,
        "--threshold", str(threshold),
        "--log-dir", str(LOGS_DIR)
    ]
    
    print(f"Starting detection with command: {' '.join(cmd)}")
    print(f"Using Python: {python_executable}")
    print(f"Log directory: {LOGS_DIR}")
    
    detection_process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=0  # Unbuffered for real-time output
    )
    
    # Start output parser in background thread
    parser_thread = threading.Thread(target=parse_detection_output, daemon=True)
    parser_thread.start()


def stop_detection():
    """Stop the live anomaly detection process."""
    global detection_process, stats
    
    if detection_process:
        detection_process.send_signal(signal.SIGINT)
        detection_process.wait(timeout=5)
        detection_process = None
    
    stats["detection_active"] = False


# API Routes

@app.get("/", response_class=HTMLResponse)
async def read_root():
    """Serve the main HTML page."""
    html_content = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Network Anomaly Detection System</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
        <style>
            * {
                box-sizing: border-box;
            }
            body {
                background: #f8f9fa;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                margin: 0;
                padding: 0;
            }
            .header-section {
                background: linear-gradient(135deg, #0C4B33 0%, #1a7a52 100%);
                color: white;
                padding: 20px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            .header-section h1 {
                font-size: clamp(1.5rem, 4vw, 2rem);
                margin: 0;
            }
            .header-section p {
                font-size: clamp(0.875rem, 2vw, 1rem);
            }
            
            /* Responsive Statistics Cards */
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 15px;
                padding: 20px;
                max-width: 1400px;
                margin: 0 auto;
            }
            .stat-card {
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                text-align: center;
                transition: transform 0.3s;
            }
            .stat-card:hover {
                transform: translateY(-5px);
            }
            .stat-card h3 {
                font-size: clamp(1.5rem, 3vw, 2.5rem);
                font-weight: bold;
                margin: 10px 0;
                color: #0C4B33;
            }
            .stat-card i {
                color: #0C4B33;
                font-size: clamp(1.5rem, 3vw, 2rem);
            }
            .stat-card p {
                margin: 0;
                font-size: clamp(0.75rem, 1.5vw, 0.9rem);
                color: #6c757d;
            }
            
            /* Alert Items - Stack Vertically */
            .alert-item {
                background: white;
                border-radius: 8px;
                border-left: 4px solid #dc3545;
                padding: 15px;
                margin-bottom: 10px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                cursor: pointer;
                transition: all 0.3s ease;
                animation: slideIn 0.5s ease-out;
            }
            .alert-item:hover {
                box-shadow: 0 4px 15px rgba(0,0,0,0.2);
                transform: translateX(5px);
            }
            @keyframes slideIn {
                from {
                    opacity: 0;
                    transform: translateY(-20px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            .alert-high { border-left-color: #dc3545; }
            .alert-medium { border-left-color: #ffc107; }
            .alert-low { border-left-color: #28a745; }
            
            .scrollable-alerts {
                max-height: 600px;
                overflow-y: auto;
                padding: 15px;
            }
            
            /* Responsive containers */
            .content-container {
                max-width: 1400px;
                margin: 0 auto;
                padding: 0 15px;
            }
            
            .status-indicator {
                display: inline-block;
                width: 12px;
                height: 12px;
                border-radius: 50%;
                margin-right: 8px;
                animation: pulse 2s infinite;
            }
            .status-active { background-color: #28a745; }
            @keyframes pulse {
                0%, 100% { opacity: 1; }
                50% { opacity: 0.5; }
            }
            .card {
                border: none;
                border-radius: 10px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                margin: 15px 0;
            }
            .card-header {
                background: linear-gradient(135deg, #0C4B33 0%, #1a7a52 100%);
                color: white;
                border-radius: 10px 10px 0 0 !important;
                padding: 15px 20px;
            }
            .badge-confidence {
                font-size: 0.9rem;
                padding: 5px 10px;
            }
            
            /* Modal Styles */
            .modal-backdrop {
                display: none;
                position: fixed;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                background: rgba(0,0,0,0.5);
                z-index: 1000;
                align-items: center;
                justify-content: center;
            }
            .modal-backdrop.show {
                display: flex;
            }
            .modal-content-custom {
                background: white;
                border-radius: 10px;
                padding: 25px;
                max-width: 800px;
                width: 90%;
                max-height: 90vh;
                overflow-y: auto;
                box-shadow: 0 10px 40px rgba(0,0,0,0.3);
                animation: modalSlideIn 0.3s ease-out;
            }
            @keyframes modalSlideIn {
                from {
                    opacity: 0;
                    transform: translateY(-50px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            .modal-close {
                float: right;
                font-size: 28px;
                font-weight: bold;
                color: #999;
                cursor: pointer;
                line-height: 20px;
            }
            .modal-close:hover {
                color: #000;
            }
            
            /* Responsive Typography */
            @media (max-width: 768px) {
                .header-section {
                    text-align: center;
                }
                .stats-grid {
                    grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
                    gap: 10px;
                    padding: 10px;
                }
                .alert-item {
                    padding: 10px;
                }
                .scrollable-alerts {
                    max-height: 400px;
                }
            }
        </style>
    </head>
    <body>
        <div class="header-section">
            <div class="container-fluid">
                <div class="row align-items-center">
                    <div class="col-md-8 col-12 mb-2 mb-md-0">
                        <h1><i class="fas fa-shield-alt"></i> Network Anomaly Detection System</h1>
                        <p class="mb-0">Real-time Network Intrusion Detection and Monitoring</p>
                    </div>
                    <div class="col-md-4 col-12 text-md-end text-center">
                        <div>
                            <span class="status-indicator status-active"></span>
                            <strong>Status: </strong><span id="system-status">Active</span>
                        </div>
                        <div class="mt-2">
                            <small>Interface: <span id="interface">--</span></small><br>
                            <small>Threshold: <span id="threshold">--</span></small>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Statistics Cards with Responsive Grid -->
        <div class="stats-grid">
            <div class="stat-card">
                <i class="fas fa-exclamation-triangle fa-2x"></i>
                <h3 id="total-anomalies">0</h3>
                <p class="text-muted">Total Anomalies</p>
            </div>
            <div class="stat-card">
                <i class="fas fa-network-wired fa-2x"></i>
                <h3 id="total-flows">0</h3>
                <p class="text-muted">Network Flows</p>
            </div>
            <div class="stat-card">
                <i class="fas fa-ethernet fa-2x"></i>
                <h3 id="packets-captured">0</h3>
                <p class="text-muted">Packets Captured</p>
            </div>
            <div class="stat-card">
                <i class="fas fa-clock fa-2x"></i>
                <h3 id="uptime">00:00:00</h3>
                <p class="text-muted">Uptime</p>
            </div>
        </div>

        <!-- Recent Alerts -->
        <div class="content-container">
            <div class="card">
                <div class="card-header">
                    <h5 class="mb-0"><i class="fas fa-bell"></i> Real-time Anomaly Alerts</h5>
                </div>
                <div class="card-body">
                    <div class="scrollable-alerts" id="alerts-container">
                        <div class="text-center text-muted">
                            <i class="fas fa-hourglass-half"></i> Waiting for anomalies...
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Modal for Alert Details -->
        <div class="modal-backdrop" id="alertModal">
            <div class="modal-content-custom">
                <span class="modal-close" onclick="closeModal()">&times;</span>
                <div id="modal-body"></div>
            </div>
        </div>

        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            let ws = null;
            let startTime = null;

            function connectWebSocket() {
                const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
                ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
                
                ws.onopen = () => {
                    console.log('WebSocket connected');
                    loadStats();
                };
                
                ws.onmessage = (event) => {
                    const data = JSON.parse(event.data);
                    
                    if (data.type === 'anomaly') {
                        addAnomaly(data.data);
                    } else if (data.type === 'stats') {
                        updateStats(data.data);
                    }
                };
                
                ws.onclose = () => {
                    console.log('WebSocket disconnected. Reconnecting...');
                    setTimeout(connectWebSocket, 3000);
                };
            }

            function addAnomaly(anomaly) {
                const container = document.getElementById('alerts-container');
                
                // Clear waiting message only once
                const waitingMsg = container.querySelector('.text-muted');
                if (waitingMsg && waitingMsg.parentElement === container) {
                    container.innerHTML = '';
                }
                
                const confidence = anomaly.confidence || 0;
                let severityClass = 'alert-low';
                let severityBadge = 'success';
                
                if (confidence >= 90) {
                    severityClass = 'alert-high';
                    severityBadge = 'danger';
                } else if (confidence >= 75) {
                    severityClass = 'alert-medium';
                    severityBadge = 'warning';
                }
                
                // Create unique ID with timestamp and random component to avoid collisions
                const alertId = 'alert-' + Date.now() + '-' + Math.random().toString(36).substr(2, 9);
                
                // Store anomaly data FIRST before creating HTML (deep copy to avoid reference issues)
                if (!window.anomalyData) window.anomalyData = {};
                window.anomalyData[alertId] = JSON.parse(JSON.stringify(anomaly));
                
                // Create alert element using DOM (more reliable than innerHTML)
                const alertDiv = document.createElement('div');
                alertDiv.className = `alert-item ${severityClass}`;
                alertDiv.id = alertId;
                alertDiv.style.marginBottom = '10px';  // Ensure spacing between alerts
                alertDiv.onclick = function() { showAlertDetails(alertId); };
                
                // Build inner HTML with proper escaping
                alertDiv.innerHTML = `
                    <div class="d-flex justify-content-between align-items-start">
                        <div class="flex-grow-1">
                            <h6 class="mb-2">
                                <i class="fas fa-exclamation-circle"></i>
                                <strong>${escapeHtml(anomaly.flow || 'Unknown Flow')}</strong>
                                <span class="badge bg-${severityBadge} badge-confidence ms-2">${confidence.toFixed(2)}%</span>
                            </h6>
                            <div class="small">
                                <i class="fas fa-arrow-right"></i> <strong>Source:</strong> ${escapeHtml(anomaly.source || 'N/A')} → 
                                <strong>Destination:</strong> ${escapeHtml(anomaly.destination || 'N/A')}
                            </div>
                            <div class="small mt-1">
                                <span class="me-3"><i class="fas fa-network-wired"></i> ${escapeHtml(anomaly.protocol || 'N/A')}</span>
                                <span class="me-3"><i class="fas fa-boxes"></i> ${escapeHtml(anomaly.packets_info || 'N/A')}</span>
                                <span class="me-3"><i class="fas fa-database"></i> ${escapeHtml(anomaly.bytes_info || 'N/A')}</span>
                                <span><i class="fas fa-tachometer-alt"></i> ${(anomaly.rate || 0).toFixed(2)} pkt/s</span>
                            </div>
                        </div>
                        <div class="text-end ms-3">
                            <small class="text-muted">${escapeHtml(anomaly.time || new Date().toLocaleTimeString())}</small>
                        </div>
                    </div>
                `;
                
                // Append to container (adds at bottom)
                container.appendChild(alertDiv);
                
                // Scroll to bottom smoothly to show new alert
                setTimeout(() => {
                    container.scrollTop = container.scrollHeight;
                }, 100);
                
                // Keep only last 100 alerts visible
                while (container.children.length > 100) {
                    const firstChild = container.firstChild;
                    if (firstChild && window.anomalyData) {
                        delete window.anomalyData[firstChild.id];
                    }
                    container.removeChild(firstChild);
                }
                
                // Update anomaly counter
                const total = parseInt(document.getElementById('total-anomalies').textContent) + 1;
                document.getElementById('total-anomalies').textContent = total;
            }
            
            function escapeHtml(text) {
                if (text === null || text === undefined) return 'N/A';
                const div = document.createElement('div');
                div.textContent = String(text);
                return div.innerHTML;
            }
                
                // Update anomaly counter
                const total = parseInt(document.getElementById('total-anomalies').textContent) + 1;
                document.getElementById('total-anomalies').textContent = total;
            }

            function showAlertDetails(alertId) {
                const anomaly = window.anomalyData[alertId];
                
                if (!anomaly) {
                    console.error('Anomaly data not found for ID:', alertId);
                    console.log('Available alert IDs:', Object.keys(window.anomalyData || {}));
                    document.getElementById('modal-body').innerHTML = '<div class="alert alert-danger"><strong>Error:</strong> Alert data not available</div>';
                    document.getElementById('alertModal').classList.add('show');
                    return;
                }
                
                console.log('Displaying anomaly details:', anomaly);
                
                const confidence = parseFloat(anomaly.confidence) || 0;
                let severityLabel = 'Low';
                let severityColor = '#28a745';
                
                if (confidence >= 90) {
                    severityLabel = 'High';
                    severityColor = '#dc3545';
                } else if (confidence >= 75) {
                    severityLabel = 'Medium';
                    severityColor = '#ffc107';
                }
                
                const modalContent = `
                    <h3><i class="fas fa-exclamation-triangle" style="color: ${severityColor}"></i> Anomaly Details</h3>
                    <hr>
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <strong>Severity:</strong>
                            <span class="badge" style="background-color: ${severityColor}">${severityLabel} - ${confidence.toFixed(2)}%</span>
                        </div>
                        <div class="col-md-6">
                            <strong>Time:</strong> ${escapeHtml(anomaly.time) || 'N/A'}
                        </div>
                    </div>
                    
                    <h5><i class="fas fa-network-wired"></i> Network Information</h5>
                    <table class="table table-bordered">
                        <tr><th>Flow ID</th><td>${escapeHtml(anomaly.flow) || 'N/A'}</td></tr>
                        <tr><th>Source IP</th><td>${escapeHtml(anomaly.source) || 'N/A'}</td></tr>
                        <tr><th>Destination IP</th><td>${escapeHtml(anomaly.destination) || 'N/A'}</td></tr>
                        <tr><th>Protocol</th><td>${escapeHtml(anomaly.protocol) || 'N/A'}</td></tr>
                        <tr><th>Duration</th><td>${escapeHtml(anomaly.duration) || 'N/A'}s</td></tr>
                    </table>
                    
                    <h5><i class="fas fa-chart-bar"></i> Traffic Statistics</h5>
                    <table class="table table-bordered">
                        <tr><th>Packets</th><td>${escapeHtml(anomaly.packets_info) || 'N/A'}</td></tr>
                        <tr><th>Bytes</th><td>${escapeHtml(anomaly.bytes_info) || 'N/A'}</td></tr>
                        <tr><th>Rate</th><td>${(parseFloat(anomaly.rate) || 0).toFixed(2)} packets/second</td></tr>
                    </table>
                    
                    <h5><i class="fas fa-info-circle"></i> Additional Information</h5>
                    <table class="table table-bordered">
                        <tr><th>Timestamp</th><td>${escapeHtml(anomaly.timestamp) || 'N/A'}</td></tr>
                        <tr><th>Alert ID</th><td>${escapeHtml(anomaly.id) || 'N/A'}</td></tr>
                    </table>
                    
                    <div class="alert alert-info mt-3">
                        <strong><i class="fas fa-lightbulb"></i> Recommendation:</strong>
                        ${confidence >= 90 ? 'High confidence anomaly detected. Immediate investigation recommended.' :
                          confidence >= 75 ? 'Moderate confidence anomaly. Review and monitor this flow.' :
                          'Low confidence anomaly. May be a false positive, but worth monitoring.'}
                    </div>
                `;
                
                document.getElementById('modal-body').innerHTML = modalContent;
                document.getElementById('alertModal').classList.add('show');
            }

            function closeModal() {
                document.getElementById('alertModal').classList.remove('show');
            }

            // Close modal on backdrop click
            document.getElementById('alertModal').addEventListener('click', function(e) {
                if (e.target === this) {
                    closeModal();
                }
            });

            // Close modal on Escape key
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape') {
                    closeModal();
                }
            });

            function updateStats(stats) {
                document.getElementById('total-anomalies').textContent = stats.total_anomalies || 0;
                document.getElementById('total-flows').textContent = stats.total_flows || 0;
                document.getElementById('packets-captured').textContent = stats.packets_captured || 0;
                document.getElementById('interface').textContent = stats.interface || '--';
                document.getElementById('threshold').textContent = stats.threshold || '--';
                
                if (stats.start_time && !startTime) {
                    startTime = new Date(stats.start_time);
                }
            }

            function loadStats() {
                fetch('/api/stats')
                    .then(response => response.json())
                    .then(data => updateStats(data))
                    .catch(err => console.error('Error loading stats:', err));
            }

            function updateUptime() {
                if (startTime) {
                    const now = new Date();
                    const diff = Math.floor((now - startTime) / 1000);
                    const hours = Math.floor(diff / 3600);
                    const minutes = Math.floor((diff % 3600) / 60);
                    const seconds = diff % 60;
                    document.getElementById('uptime').textContent = 
                        `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
                }
            }

            document.addEventListener('DOMContentLoaded', () => {
                connectWebSocket();
                loadStats();
                setInterval(updateUptime, 1000);
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)


@app.get("/api/stats")
async def get_stats_api():
    """Get current statistics."""
    return JSONResponse(stats)


@app.get("/api/anomalies")
async def get_anomalies_api(limit: int = 100):
    """Get recent anomalies from buffer."""
    anomalies = list(anomaly_buffer)[-limit:]
    anomalies.reverse()  # Most recent first
    return JSONResponse(anomalies)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


async def process_message_queue():
    """Background task to process messages from parser thread and broadcast to WebSocket clients."""
    while True:
        await asyncio.sleep(0.1)  # Check queue frequently
        
        try:
            # Process all available messages
            while not message_queue.empty():
                message = message_queue.get_nowait()
                await manager.broadcast(message)
        except Exception as e:
            print(f"Error processing message queue: {e}")


async def monitor_logs():
    """Background task to monitor log files and broadcast updates."""
    last_check = datetime.now()
    
    while True:
        await asyncio.sleep(5)  # Check every 5 seconds
        
        try:
            # Check if there are new anomaly files
            anomaly_files = get_latest_files(LOGS_DIR, "anomalies_*.json")
            if anomaly_files:
                latest_file = anomaly_files[0]
                file_mtime = datetime.fromtimestamp(latest_file.stat().st_mtime)
                
                if file_mtime > last_check:
                    # New data detected, broadcast update
                    await manager.broadcast({"type": "update", "timestamp": datetime.now().isoformat()})
                    last_check = datetime.now()
        except Exception as e:
            print(f"Error in monitor_logs: {e}")
            print(f"Error in monitor_logs: {e}")


def main():
    parser = argparse.ArgumentParser(
        description='Integrated Network Anomaly Detection Web Application'
    )
    parser.add_argument(
        '--interface',
        '-i',
        required=True,
        help='Network interface to capture on (e.g., eth0, enp1s0)'
    )
    parser.add_argument(
        '--threshold',
        '-t',
        type=float,
        default=0.7,
        help='Detection threshold (0.0-1.0, default: 0.7)'
    )
    parser.add_argument(
        '--port',
        '-p',
        type=int,
        default=8000,
        help='Web server port (default: 8000)'
    )
    args = parser.parse_args()
    
    # Create directories
    LOGS_DIR.mkdir(exist_ok=True)
    
    print("=" * 80)
    print("INTEGRATED NETWORK ANOMALY DETECTION SYSTEM")
    print("=" * 80)
    print(f"Interface:       {args.interface}")
    print(f"Threshold:       {args.threshold}")
    print(f"Web Interface:   http://localhost:{args.port}")
    print(f"Logs Directory:  {LOGS_DIR.absolute()}")
    print("=" * 80)
    print("\nStarting detection and web server...")
    print("Open http://localhost:{} in your browser\n".format(args.port))
    print("Press Ctrl+C to stop")
    print("=" * 80)
    
    # Start detection
    start_detection(args.interface, args.threshold)
    
    # Small delay to let detection process start
    time.sleep(1)
    
    # Start web server
    try:
        uvicorn.run(app, host="0.0.0.0", port=args.port, log_level="warning")
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        stop_detection()
        print("Stopped.")


if __name__ == "__main__":
    main()
