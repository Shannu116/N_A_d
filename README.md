# Network Anomaly Detection System

A real-time network anomaly detection system using Machine Learning to identify suspicious network traffic patterns. This project uses the UNSW-NB15 dataset and implements a Gradient Boosting Classifier for high-accuracy threat detection.

## 🎯 Features

- **Real-time Packet Capture**: Live network traffic monitoring using Scapy
- **Machine Learning Detection**: Gradient Boosting Classifier with 87.31% accuracy
- **Flow-based Analysis**: Aggregates packets into network flows for better context
- **UNSW-NB15 Feature Extraction**: Extracts 42 standardized network flow features
- **Web-based Dashboard**: Real-time monitoring interface with live statistics
- **Anomaly Alerting**: Real-time alerts with confidence scores and detailed statistics
- **Comprehensive Logging**: CSV and JSON logs for captured packets and detected anomalies
- **High Detection Rate**: 98.33% recall for attack detection

## 📊 Model Performance

| Metric | Value |
|--------|-------|
| **Training Accuracy** | 96.20% |
| **Testing Accuracy** | 87.31% |
| **Precision** | 82.14% |
| **Recall** | 98.33% |
| **F1-Score** | 89.51% |
| **ROC-AUC** | 98.37% |

Trained on **175,341 samples** and tested on **82,332 independent samples** from the UNSW-NB15 dataset.

## 🏗️ Architecture

```
Network Traffic → Packet Capture → Flow Aggregation → Feature Extraction → ML Model → Anomaly Alert
                      (Scapy)       (FlowTracker)      (42 Features)      (GB Clf)    (Logging)
```

---

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- Root/sudo privileges (for packet capture)
- Linux/macOS (Windows requires additional setup)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/Network-Anamoly-Detection.git
cd Network-Anamoly-Detection

# 2. Install dependencies
pip install -r requirements.txt
```

### Running the Application

#### 🌟 Integrated Web Application (Recommended)

**All-in-one solution with real-time web interface:**

```bash
# Quick start with the startup script
sudo ./start_integrated_app.sh enp1s0

# Or use Python directly
sudo python3 integrated_web_app.py --interface enp1s0 --threshold 0.7
```

Then open **http://localhost:8000** in your browser!

**Command Line Arguments:**
- `--interface`, `-i` : Network interface (REQUIRED) - e.g., eth0, enp1s0, wlan0
- `--threshold`, `-t` : Detection threshold 0.0-1.0 (default: 0.7)
- `--port`, `-p` : Web server port (default: 8000)

**Features:**
- ✅ Single command startup
- ✅ Real-time anomaly display
- ✅ Live statistics dashboard
- ✅ WebSocket push notifications
- ✅ No file polling delays

**Finding Your Network Interface:**
```bash
ip -br link show
# Common names: eth0, enp1s0 (Ethernet), wlan0, wlp2s0 (WiFi)
```

---

## 📚 Additional Usage

### Training the Model

```bash
python train_unsw_nb15.py
```

This will:
- Load the UNSW-NB15 training dataset
- Train and evaluate 3 ML models (Random Forest, Gradient Boosting, Extra Trees)
- Select the best model based on F1-score and ROC-AUC
- Save the trained model to `trained_models/`

### Testing the Model

```bash
python test_model.py
```

Evaluates the model on the UNSW-NB15 test dataset and generates performance metrics.

### Standalone Live Detection (CLI Mode)

```bash
# Basic usage
sudo python3 live_anomaly_detection.py --interface enp1s0 --threshold 0.7

# With BPF filter (capture only HTTP traffic)
sudo python3 live_anomaly_detection.py --interface eth0 --filter "tcp port 80"

# High sensitivity (more detections)
sudo python3 live_anomaly_detection.py --interface wlan0 --threshold 0.5
```

**Options:**
- `--model` : Path to trained model (default: `trained_models/unsw_attack_detector.joblib`)
- `--interface`, `-i` : Network interface (e.g., eth0, wlan0)
- `--filter`, `-f` : BPF filter for packet capture (default: `ip`)
- `--threshold`, `-t` : Detection threshold 0.0-1.0 (default: 0.7)
- `--log-dir`, `-l` : Directory for log files (default: `logs`)

### Standalone Web Interface

```bash
# Terminal 1: Start web interface
python3 web_app.py

# Terminal 2: Start live detection
sudo python3 live_anomaly_detection.py --interface enp1s0
```

Then open **http://localhost:8000**

---

## 📁 Project Structure

```
Network-Anamoly-Detection/
├── integrated_web_app.py           # ⭐ All-in-one web application
├── start_integrated_app.sh         # Quick start script
├── live_anomaly_detection.py       # Real-time detection engine
├── web_app.py                      # Standalone web interface
├── train_unsw_nb15.py              # Training script
├── test_model.py                   # Model evaluation script
├── predict_attacks.py              # Batch prediction demo
├── requirements.txt                # Python dependencies
│
├── UNSW_NB15_training-set.csv     # Training dataset (175,341 samples)
├── UNSW_NB15_testing-set.csv      # Testing dataset (82,332 samples)
│
├── trained_models/
│   ├── unsw_attack_detector.joblib # Trained model (4.7 MB)
│   └── unsw_training_report.json   # Training metrics
│
├── test_results/
│   └── test_report.json            # Test performance metrics
│
└── logs/
    ├── anomalies_*.csv             # Detected anomalies
    ├── flows_*.csv                 # Network flows
    └── session_*.json              # Session summaries
```

---

## 🔍 How It Works

### 1. Flow Aggregation
The system groups packets into bidirectional flows using a 5-tuple key:
- Source IP + Port
- Destination IP + Port  
- Protocol

### 2. Feature Extraction
For each flow, 42 UNSW-NB15 features are extracted:

**Basic Features:**
- Duration, protocol, service, state

**Traffic Features:**
- Packet counts (forward/backward)
- Byte counts (forward/backward)
- Packet rate

**Time Features:**
- Inter-arrival times (mean, std, min, max)
- TTL values
- Jitter

**TCP Features:**
- Window sizes
- Sequence numbers
- RTT estimation
- TCP flags

**Content Features:**
- Payload statistics
- Header lengths

### 3. Anomaly Detection
The Gradient Boosting Classifier predicts whether a flow is:
- **Normal (0)**: Legitimate network traffic
- **Anomaly (1)**: Suspicious/malicious traffic

### 4. Alerting & Logging
When an anomaly is detected:
- **Web Dashboard**: Real-time display with severity levels
- **Console Alert**: Terminal notification with flow details
- **CSV Log**: Complete flow features and predictions
- **JSON Log**: Session summary and statistics

---

## 📈 Datasets

### UNSW-NB15 Dataset
- **Source**: University of New South Wales, Australian Centre for Cyber Security
- **Size**: 257,673 records (175,341 training + 82,332 testing)
- **Features**: 42 network flow features
- **Classes**: Normal (0) and Attack (1)
- **Attack Types**: 
  - Fuzzers, Analysis, Backdoors, DoS
  - Exploits, Generic, Reconnaissance
  - Shellcode, Worms

**Dataset is included in this repository** for easy reproduction of results.

---

## 🛠️ Model Training Details

### Algorithm Selection
Three algorithms were evaluated:
1. **Random Forest**: Baseline ensemble method
2. **Gradient Boosting**: Best performer ⭐ (selected)
3. **Extra Trees**: Alternative ensemble approach

### Preprocessing Pipeline
- **Numeric Features (39)**: `SimpleImputer` → `StandardScaler`
- **Categorical Features (3)**: `SimpleImputer` → `OneHotEncoder`
  - Protocol: tcp, udp, icmp, etc.
  - Service: http, dns, smtp, etc.
  - State: CON, FIN, INT, etc.

### Hyperparameters (Gradient Boosting)
```python
GradientBoostingClassifier(
    n_estimators=100,
    max_depth=10,
    learning_rate=0.1,
    random_state=42
)
```

---

## 🎨 Web Interface Features

### Dashboard Components

**Statistics Cards:**
- Total Anomalies Detected
- Network Flows Analyzed
- Packets Captured
- System Uptime

**Real-time Anomaly Feed:**
- Live stream of detected anomalies
- Color-coded by severity:
  - 🔴 **High** (Red) - Confidence ≥ 90%
  - 🟡 **Medium** (Yellow) - Confidence ≥ 75%
  - 🟢 **Low** (Green) - Confidence < 75%
- Detailed packet information
- Source/destination IPs and ports
- Protocol, rate, and byte statistics

**System Status:**
- Active/Inactive indicator
- Current interface being monitored
- Detection threshold
- Live update timestamp

---

## ⚙️ Threshold Guide

| Threshold | Sensitivity | Use Case |
|-----------|-------------|----------|
| 0.5 - 0.6 | Very High | Testing, learning, catching subtle anomalies |
| 0.6 - 0.7 | High | Balanced detection for most scenarios |
| 0.7 - 0.8 | Medium | **Recommended** for production use |
| 0.8 - 0.9 | Low | Conservative, fewer false positives |
| 0.9 - 1.0 | Very Low | Only highest confidence threats |

**Note:** Lower threshold = more detections but more false positives

---

## 🔧 Troubleshooting

### "Requires root/sudo privileges"
```bash
# Always run detection with sudo:
sudo python3 integrated_web_app.py --interface enp1s0
```

### "Interface not found"
```bash
# Check available interfaces:
ip -br link show

# Use correct interface name:
sudo python3 integrated_web_app.py --interface enp1s0
```

### No anomalies detected
**Possible solutions:**
1. Lower the threshold: `--threshold 0.6`
2. Generate network traffic (browse websites, download files)
3. Wait 2-3 minutes for flow patterns to develop
4. Verify interface is active: `sudo tcpdump -i enp1s0 -c 10`

### Web interface not loading
```bash
# Check if server is running:
curl http://localhost:8000/api/stats

# Try different port:
sudo python3 integrated_web_app.py --interface enp1s0 --port 8080

# Check for port conflicts:
sudo lsof -i :8000
```

### Permission denied errors
```bash
# Fix log directory permissions:
sudo chown -R $USER:$USER logs/

# Or run with sudo:
sudo python3 integrated_web_app.py --interface enp1s0
```

---

## 🔒 Security Considerations

- **Root Privileges**: Packet capture requires sudo/root access
- **Privacy**: Be mindful of capturing sensitive traffic
- **Legal**: Only monitor networks you have permission to analyze
- **Performance**: High-traffic networks may require optimization
- **False Positives**: Legitimate encrypted traffic may trigger alerts

---

## 📝 Logging

All logs are saved to the `logs/` directory:

**Anomaly Logs** (`anomalies_YYYYMMDD_HHMMSS.csv`):
- Timestamp, flow details, confidence score
- All 42 extracted features
- Source/destination IPs and ports

**Flow Logs** (`flows_YYYYMMDD_HHMMSS.csv`):
- All captured network flows
- Complete feature set

**Session Logs** (`session_YYYYMMDD_HHMMSS.json`):
- Session start/end time
- Total packets captured
- Flows analyzed
- Anomalies detected
- Detection rate

---

## 🎯 Example Usage Session

```bash
# 1. Start the integrated application
$ sudo ./start_integrated_app.sh enp1s0 0.7

================================================================
INTEGRATED NETWORK ANOMALY DETECTION SYSTEM
================================================================
Interface:       enp1s0
Threshold:       0.7
Web Interface:   http://localhost:8000
================================================================

# 2. Open browser to http://localhost:8000

# 3. Generate network traffic to test
$ ping -c 100 google.com
$ curl -s https://example.com > /dev/null

# 4. Watch anomalies appear in real-time on the dashboard!

# 5. Stop with Ctrl+C when done
# Logs saved to: logs/
```

---

## 🧪 Testing the System

### Generate Test Traffic

```bash
# Basic connectivity test
ping -c 100 google.com

# HTTP traffic
for i in {1..10}; do curl -s https://example.com > /dev/null; done

# Multiple connections
for i in {1..50}; do curl -s https://httpbin.org/get > /dev/null & done

# Port scan simulation (will likely be detected as anomaly)
nmap -sS localhost
```

### Verify Detection

1. Check terminal for anomaly alerts
2. View real-time updates on web dashboard
3. Review logs in `logs/` directory
4. Check API endpoint: `curl http://localhost:8000/api/stats`

---

## 📊 API Endpoints

For custom integrations:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Web dashboard |
| `/api/stats` | GET | Current statistics |
| `/api/anomalies?limit=100` | GET | Recent anomalies |
| `/ws` | WebSocket | Real-time updates |

**Example:**
```bash
# Get current statistics
curl http://localhost:8000/api/stats

# Get last 50 anomalies
curl http://localhost:8000/api/anomalies?limit=50
```

---

## 📁 Log Files

The system generates multiple log files for analysis and integration:

### Standard Logs
- `logs/anomalies_YYYYMMDD_HHMMSS.csv` - CSV format with detected anomalies
- `logs/anomalies_YYYYMMDD_HHMMSS.json` - JSON format with detailed anomaly data
- `logs/flows_YYYYMMDD_HHMMSS.csv` - All captured network flows

### Splunk Integration
- `logs/splunk_anomalies.log` - **Splunk Universal Forwarder compatible JSON logs**

Each anomaly is logged in single-line JSON format for easy ingestion by Splunk:
```json
{"timestamp": "2024-12-27T10:30:45.123456", "event_type": "network_anomaly", "severity": "high", "source_ip": "192.168.1.100", "destination_ip": "10.0.0.50", ...}
```

**See [SPLUNK_LOGGING_GUIDE.md](SPLUNK_LOGGING_GUIDE.md) for complete Splunk integration instructions.**

---

## 🔧 Recent Updates

### Version 2.1.0 (Latest)
- ✅ **Fixed Alert Segregation**: Alerts now display as separate stacked items (no overlap)
- ✅ **Fixed Modal Details**: Alert detail popup now correctly shows all anomaly information
- ✅ **Splunk Logging**: Added Splunk Universal Forwarder compatible JSON logging
- ✅ **Improved Alert Rendering**: Using DOM createElement for reliable alert display
- ✅ **Enhanced Data Handling**: Deep copy of anomaly data prevents reference issues
- ✅ **Better Error Handling**: Modal shows error messages when data is unavailable

### Alert Display Improvements
- Each alert gets unique ID with timestamp + random component
- Proper HTML escaping prevents injection issues
- Auto-scroll to show newest alerts
- Maintains last 100 alerts (older ones auto-removed)
- 10px margin between alerts prevents overlap

### Splunk Integration Features
- JSON log file: `logs/splunk_anomalies.log`
- Fields: timestamp, severity, source_ip, destination_ip, protocol, confidence_score, etc.
- Automatic severity classification: high (≥90%), medium (75-89%), low (<75%)
- Ready for Splunk Universal Forwarder ingestion
- See SPLUNK_LOGGING_GUIDE.md for setup

---

## 🚀 Future Improvements

- [ ] Deep learning models (LSTM, CNN)
- [ ] Multi-class attack classification
- [ ] Docker containerization
- [ ] Support for additional datasets (CIC-IDS, Bot-IoT)
- [ ] Payload inspection and DPI features
- [ ] Integration with SIEM systems
- [ ] Email/SMS alerting
- [ ] Historical analysis and reporting

---

## 🙏 Acknowledgments

- **UNSW-NB15 Dataset**: Australian Centre for Cyber Security (ACCS)
- **Scapy**: Packet manipulation library
- **scikit-learn**: Machine learning framework
- **FastAPI**: Modern web framework for Python

---

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**Ready to start?** Run: `sudo ./start_integrated_app.sh <your-interface>`

Example: `sudo ./start_integrated_app.sh enp1s0`

