# IoT-Guardian

## Expert System for IoT Network Security

IoT-Guardian is a web-based expert system that uses **CLIPS** (C Language Integrated Production System) to detect and respond to security threats in IoT networks.

---

## Setup

### Prerequisites
- Python 3.8 or higher

### Installation

1. **Create and activate virtual environment**:
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate
   
   # Linux/Mac
   python -m venv venv
   source venv/bin/activate
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**:
   ```bash
   python app.py
   ```
   OR
   ```bash
   start start.bat
   ```
   Or simply double-click `start.bat` (Windows only).

4. **Open in browser**:
   ```
   http://localhost:5000
   ```
    Or use CTRL+CLICK the link provided by the system.
---

## How to Use

### 1. Dashboard (`/`)
The main monitoring page. View real-time network status, IoT device topology, and live security alerts.

### 2. Attack Simulator (`/hacker`)
Simulate different types of IoT attacks to test the expert system:
- **Sinkhole** - Malicious node attracting traffic
- **DDoS** - Distributed Denial of Service
- **Replay** - Packet retransmission attacks
- **MITM** - Man-in-the-Middle interception
- **Wormhole** - Malicious tunnel creation
- **Selective Forwarding** - Packet dropping
- **Sybil** - Multiple fake identities

### 3. Defense View (`/defense`)
View the CLIPS inference engine in action:
- See the fact base (what the system knows)
- Watch the inference chain (how the system reasons)
- Get real-time defense recommendations

### 4. Reports (`/report`)
Generate and view diagnostic reports including attack history, alert timeline, and defense actions.

---

## Quick Start Guide

1. Open the **Dashboard** to see the network overview
2. Go to **Attack Simulator** and inject an attack (e.g., select "Sinkhole" and click inject)
3. Switch to **Defense View** to see how the expert system detects and responds to the attack
4. Check **Reports** for a summary of all detected threats and actions taken

---

## Technology Stack

| Component | Technology |
|-----------|------------|
| Backend | Flask, Flask-SocketIO |
| Expert System | CLIPS (clipspy) |
| Frontend | HTML5, CSS3, JavaScript |
| Real-time | WebSocket (Socket.IO) |