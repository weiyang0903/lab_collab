# IoT-Guardian

## 🛡️ Expert System for IoT Network Security

IoT-Guardian is a web-based expert system that uses CLIPS (C Language Integrated Production System) to detect and respond to security threats in IoT networks.

## 📁 Project Structure

```
project/
├── app.py                  # Main Flask application
├── requirements.txt        # Python dependencies
├── README.md              # This file
├── rules/
│   └── iot_security.clp   # CLIPS rules for attack detection
├── templates/
│   ├── dashboard.html     # Main monitoring dashboard
│   ├── hacker.html        # Attack simulator interface
│   ├── defense.html       # Defense & inference view
│   └── report.html        # Diagnostic reports
└── static/
    ├── css/
    │   └── style.css      # Main stylesheet
    └── js/
        └── main.js        # Client-side JavaScript
```

## 🚀 Features

### 1. Dashboard (`/`)
- Real-time network monitoring
- IoT device topology visualization
- Live alerts and statistics
- Network packet simulation

### 2. Attack Simulator (`/hacker`)
- Simulate various IoT attacks:
  - **Sinkhole** - Malicious node attracting traffic
  - **DDoS** - Distributed Denial of Service
  - **Replay** - Packet retransmission attacks
  - **MITM** - Man-in-the-Middle interception
  - **Wormhole** - Malicious tunnel creation
  - **Selective Forwarding** - Packet dropping
  - **Sybil** - Multiple fake identities

### 3. Defense View (`/defense`)
- CLIPS fact base visualization
- Inference chain display
- Real-time defense recommendations
- Inference log monitoring

### 4. Reports (`/report`)
- Attack history and breakdown
- Alert timeline
- Defense actions table
- Diagnostic summary

## 🔧 Installation

### Prerequisites
- Python 3.8 or higher
- CLIPS library (clipspy)

### Setup

1. **Create virtual environment** (optional but recommended):
```bash
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/Mac
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

3. **Run the application**:
```bash
python app.py
```

4. **Open in browser**:
```
http://localhost:5000
```

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Get system status |
| `/api/load_rules` | POST | Load CLIPS rules |
| `/api/reset` | POST | Reset expert system |
| `/inject_attack` | POST | Inject attack fact |
| `/api/facts` | GET | Get all facts |
| `/api/inference_log` | GET | Get inference log |
| `/api/simulate_packets` | POST | Simulate network packets |
| `/api/attack_history` | GET | Get attack history |
| `/api/generate_report` | GET | Generate diagnostic report |

### Inject Attack API

**Request:**
```json
POST /inject_attack
{
    "attack_type": "Sinkhole",
    "source": "malicious-node-001",
    "target": "gateway-001"
}
```

**Response:**
```json
{
    "success": true,
    "attack": {
        "type": "Sinkhole",
        "source": "malicious-node-001",
        "target": "gateway-001",
        "severity": "HIGH",
        "confidence": 85,
        "timestamp": "2024-01-21 10:30:00"
    },
    "rules_fired": 2,
    "alerts": [...],
    "defenses": [...]
}
```

## 🔒 CLIPS Rules

The expert system uses CLIPS rules defined in `rules/iot_security.clp`:

- **Templates**: Define fact structures for packets, devices, attacks, alerts, and defenses
- **Attack Detection Rules**: Detect various IoT attack patterns
- **Defense Rules**: Generate appropriate defense recommendations
- **Escalation Rules**: Escalate alerts when multiple attacks detected

## 🔌 WebSocket Events

Real-time communication via Flask-SocketIO:

- `connect` - Client connection established
- `disconnect` - Client disconnected
- `inference_update` - New inference log entry
- `new_alert` - New security alert generated
- `new_defense` - New defense action recommended

## 🛠️ Technology Stack

- **Backend**: Flask, Flask-SocketIO
- **Expert System**: CLIPS (clipspy)
- **Frontend**: HTML5, CSS3, JavaScript
- **Real-time**: WebSocket (Socket.IO)
- **Icons**: Font Awesome

## 📖 Usage Guide

1. **Start** by visiting the Dashboard to see the current network state
2. **Simulate attacks** using the Attack Simulator page
3. **View inference** results in the Defense View
4. **Generate reports** for documentation and analysis

## 📝 License

This project is for educational purposes.

## 👨‍💻 Author

IoT-Guardian Expert System - Lab Project
