# IoT-Guardian Expert System - Technical Documentation

---

## System Overview

### What is IoT-Guardian?

**IoT-Guardian** is an educational simulation platform and learning environment designed to help users understand, explore, and experiment with IoT network security concepts. Rather than monitoring real-world networks, IoT-Guardian provides a **safe sandbox environment** where users can design their own IoT network topologies, simulate various routing protocol attacks, and observe how an expert system detects and responds to these threats—all without any risk to actual infrastructure.

The platform focuses on the **RPL (Routing Protocol for Low-Power and Lossy Networks)** protocol, which is the standardized routing protocol for resource-constrained IoT devices. By leveraging rule-based artificial intelligence built upon the **CLIPS (C Language Integrated Production System)** inference engine, IoT-Guardian demonstrates how expert systems can perform forward-chaining reasoning on network behaviors to identify potential security threats with high accuracy and explainability.

**In essence, IoT-Guardian is a "flight simulator" for IoT security**—just as pilots train in simulators before flying real aircraft, security professionals and students can use IoT-Guardian to practice attack detection and defense strategies in a controlled, consequence-free environment.

### Who is the Target User?

IoT-Guardian is designed primarily as an **educational and training tool** for several user groups:

**Students and Learners** studying cybersecurity, artificial intelligence, or IoT systems form the primary audience. The platform provides hands-on experience with expert systems, fuzzy logic-based detection, and rule-based reasoning in an interactive environment. Students can visually observe how different attack parameters trigger different detection rules, making abstract security concepts tangible and understandable.

**Educators and Instructors** can utilize IoT-Guardian as a teaching aid in courses covering network security, expert systems, or IoT architecture. The system's transparent inference paths allow instructors to walk through detection logic step-by-step, demonstrating how rules fire and conclusions are reached.

**Security Researchers and Analysts** can use the platform to prototype and validate detection algorithms. Before implementing detection mechanisms in production systems, researchers can test their rule logic in IoT-Guardian's simulation environment to verify correctness and observe behavior across different attack scenarios.

**IoT Developers and System Integrators** who want to understand potential threats to RPL-based networks can use the platform to familiarize themselves with attack vectors and defense strategies, improving their security awareness when designing real systems.

### What Does the System Do?

IoT-Guardian provides a complete **simulation and learning experience** through several integrated features:

**Custom Network Topology Design** allows users to create their own virtual IoT networks. Using the interactive Topology Designer, users can add nodes (gateways, routers, sensors, cameras, actuators), connect them with edges, and save their custom topologies. This visual approach helps users understand network structure and how attacks propagate through connected devices.

**Attack Simulation Laboratory (Hacker Lab)** is the core interactive feature. Users can select from over 10 different attack types derived from academic literature, configure attack parameters (such as DIO message frequency, packet drop rates, or rank values), choose source and target nodes, and "launch" simulated attacks. The system then processes these parameters through the expert system to demonstrate detection outcomes—no real network traffic is generated or harmed.

**Real-time Expert System Inference** demonstrates how rule-based AI works. When an attack is simulated, users can observe which facts are asserted into the CLIPS working memory, which rules fire based on pattern matching, and what conclusions (alerts and defense recommendations) are generated. This transparent process makes the "black box" of AI detection visible and educational.

**Visual Feedback and Status Updates** bring the simulation to life. The network topology view updates in real-time with color-coded node status: red for malicious nodes, orange for quarantined nodes, purple for victim nodes, and green for healthy nodes. This immediate visual feedback reinforces learning by showing the consequences of different attack scenarios.

**Detailed Diagnostic Reports** summarize each simulation session. After launching an attack, users can view comprehensive reports including the attack type, severity assessment, triggered rules, inference paths, and recommended defense actions. These reports serve as learning artifacts that students can study and instructors can evaluate.

**Inference Path Explanation** ensures learning transparency. For every alert generated, the system displays the complete reasoning chain—which conditions were met, which rules fired, and how conclusions were derived. This explainable approach helps users understand not just *what* was detected, but *why* and *how*.

### What is the Purpose?

The fundamental purpose of IoT-Guardian is to **provide a safe, interactive environment for learning about IoT security through hands-on experimentation**.

**Bridging Theory and Practice** is the primary goal. Academic papers describe numerous attack techniques and detection algorithms, but reading about attacks is fundamentally different from experiencing them. IoT-Guardian allows users to actively engage with security concepts—designing networks, configuring attacks, observing detection, and analyzing results—transforming passive learning into active discovery.

**Demystifying Expert Systems** is another key objective. Many students learn about rule-based AI in textbooks but never see a working implementation. IoT-Guardian provides a tangible example of how CLIPS rules, pattern matching, and forward-chaining inference work together in a practical application. Users can modify attack parameters and immediately see how different inputs lead to different rule activations.

**Building Security Intuition** through experimentation helps users develop practical understanding. By trying different attack configurations and observing outcomes, users naturally learn which parameter combinations are dangerous, which behaviors indicate specific attack types, and how defense mechanisms should respond. This experiential learning builds intuition that transfers to real-world security work.

**Supporting Coursework and Research** with a ready-to-use platform saves educators and researchers significant setup time. Rather than building simulation environments from scratch, they can leverage IoT-Guardian's existing infrastructure to focus on teaching concepts or testing hypotheses.

**Enabling Safe Experimentation** without legal or ethical concerns is crucial. Attacking real networks—even for educational purposes—raises serious legal and ethical issues. IoT-Guardian eliminates these concerns by providing a completely virtual environment where users can freely experiment with attack techniques without any real-world consequences.

### What IoT-Guardian is NOT

To clarify the system's scope and prevent misuse:

**IoT-Guardian is NOT a real network monitoring tool.** It does not connect to actual IoT devices, capture real network traffic, or monitor production infrastructure. All network data is simulated within the application.

**IoT-Guardian is NOT a hacking tool.** The "Hacker Lab" simulates attack scenarios for educational purposes only. It cannot and does not generate actual malicious traffic or attack real systems.

**IoT-Guardian is NOT a production security solution.** While the detection rules are derived from peer-reviewed research, the system is designed for learning and demonstration, not for protecting real IoT deployments.

### System Architecture Summary

IoT-Guardian employs a modern web-based architecture optimized for interactive learning:

The **Backend Layer** consists of a Flask application integrated with the CLIPS inference engine. This layer handles attack simulation requests, executes rule-based inference, and manages simulation state. WebSocket connections via Flask-SocketIO enable real-time updates across all interface components.

The **Knowledge Base Layer** contains 1,687 lines of CLIPS rules organized by literature source. Each rule encapsulates detection logic from peer-reviewed research papers, with confidence values calibrated to reported accuracy rates. This rule base serves as both a functional detection engine and an educational reference.

The **Simulation Layer** manages virtual network state, including topology definitions, node status, and attack history. All data exists only in memory and browser storage—no external network connections are made.

The **Presentation Layer** comprises five specialized interfaces designed for different aspects of the learning experience:
- **Dashboard** - Overview of simulation metrics and system status
- **Hacker Lab** - Attack configuration and simulation launcher
- **Topology Designer** - Interactive network topology creation
- **Defense Center** - Real-time alert and inference monitoring  
- **Report Generator** - Comprehensive attack analysis documentation

The **Verification Layer** provides formal methods support through CNF conversion and SAT solving, demonstrating how expert system rules can be mathematically verified for consistency—an advanced topic for users interested in formal verification techniques.

Together, these components create a comprehensive educational platform that transforms abstract IoT security concepts into interactive, observable, and explorable learning experiences.

---

## 1. Programming Languages & Tools

### Core Technologies

| Technology | Version | Purpose |
|------------|---------|---------|
| **Python** | 3.8+ | Backend server, CLIPS integration |
| **CLIPS** | 6.40 (clipspy) | Expert system inference engine |
| **Flask** | 2.0+ | Web framework & REST API |
| **Flask-SocketIO** | 5.0+ | Real-time WebSocket communication |
| **HTML5/CSS3/JavaScript** | - | Frontend UI |
| **vis.js** | 9.1.2 | Network topology visualization |
| **Socket.IO** | 4.0.1 | Client-side real-time updates |
| **PySAT** | 0.1.8 | SAT solver for rule verification |

### Project Structure
```
project/
├── app.py                    # Flask backend + CLIPS integration
├── rules/
│   ├── rpl_rules.clp        # CLIPS expert system rules (1687 lines)
│   ├── rpl_rules.cnf        # CNF format for SAT verification
│   └── sat_verify.py        # SAT solver verification script
├── templates/
│   ├── dashboard.html       # Main monitoring dashboard
│   ├── hacker.html          # Attack simulation lab
│   ├── topology.html        # Network topology designer
│   ├── defense.html         # Defense monitoring center
│   └── report.html          # Security diagnostic report
└── static/
    ├── css/style.css
    └── js/main.js
```

---

## 2. Knowledge Representation

### 2.1 Fact Templates (CLIPS)

The expert system uses structured fact templates to represent IoT network knowledge:

```clips
;;; DIO Message Counter (for FLSec-RPL) [Reference 9]
(deftemplate dio-counter
   "Counts DIO messages from a node"
   (slot node-id (type STRING))
   (slot count (type INTEGER))
   (slot level (type SYMBOL) (allowed-symbols Low Medium High)))

;;; Attack Alert Output
(deftemplate attack-alert
   "Generated Security Alert"
   (slot alert-id (type INTEGER))
   (slot attack-type (type STRING))
   (slot node-id (type STRING))
   (slot severity (type STRING))
   (slot message (type STRING))
   (slot timestamp (type INTEGER)))

;;; Defense Action Recommendation
(deftemplate defense-action
   "Recommended Defense Measure"
   (slot action-id (type INTEGER))
   (slot action-type (type STRING))
   (slot target-node (type STRING))
   (slot priority (type STRING))
   (slot description (type STRING)))
```

### 2.2 Knowledge Base Structure (Tabular)

#### Table 1: Attack Detection Rules by Literature Reference

| Rule ID | Attack Type | Source Reference | Detection Parameters | Confidence |
|---------|-------------|------------------|---------------------|------------|
| R-FLSec-1 | DIO Suppression (Malicious) | [9] FLSec-RPL | DIO=High, DTI=Low, STIA=Low | 97% |
| R-FLSec-2 | DIO Suppression (Quarantine) | [9] FLSec-RPL | DIO=High, DTI=Low, STIA=Medium | 97% |
| R-FLSec-3 | Normal Behavior | [9] FLSec-RPL | DIO=Medium, DTI=Medium, STIA=Medium | 97% |
| R-FLSec-4 | DIO Suppression (Victim) | [9] FLSec-RPL | DIO=Low, DTI=Low, STIA=Low | 97% |
| R-Jam-3 | High Jamming | [15] Jamming Detection | ETX=High, Retrans=High | 76% |
| R-Sink-1 | Sinkhole Attack | [3] PRBA | Rank decrease > threshold | 95% |
| R-SF-1 | Selective Forwarding | [11] Random Forest | Drop rate > 20% | 87% |
| R-DoS-1 | DoS Attack | [11] Random Forest | DPR>0.5, PFR>0.6 | 85% |
| R-VN-1 | Version Number Attack | [2] SRPL-RP | VN forgery detected | 98% |
| R-Sybil-1 | Sybil Attack | [12] FLBT-RPL | Multiple identities | 98% |

#### Table 2: Fuzzy Logic Membership (FLSec-RPL) [Reference 9]

| Parameter | Low | Medium | High |
|-----------|-----|--------|------|
| DIO Counter | 0-30 | 31-70 | 71-100+ |
| DTI (sec) | >1.0 | 0.5-1.0 | <0.5 |
| STIA | >0.7 | 0.3-0.7 | <0.3 |

#### Table 3: Defense Action Mapping

| Attack Classification | Severity | Defense Action | Priority |
|----------------------|----------|----------------|----------|
| MALICIOUS | CRITICAL | BLOCK_PERMANENT | Immediate |
| QUARANTINE | HIGH | ISOLATE | Immediate |
| VICTIM | MEDIUM | MONITOR | Short-term |
| NORMAL | LOW | NONE | N/A |

---

## 3. Reasoning Mechanism

### 3.1 Forward Chaining Inference

The system uses **forward chaining** (data-driven reasoning):

```
Facts (Input) → Pattern Matching → Rule Firing → Conclusions (Output)
```

### 3.2 Conflict Resolution (Salience-Based)

Rules are prioritized using salience values:

```clips
;;; Critical attack detection - highest priority
(defrule R-FLSec-1-Malicious
   (declare (salience 100))  ; Highest priority
   ...)

;;; Normal behavior check - lower priority
(defrule R-FLSec-3-Normal
   (declare (salience 90))   ; Lower priority
   ...)
```

### 3.3 Inference Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                    IoT-Guardian Inference Engine                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │ Network Data │────▶│ Fact Assert  │────▶│ Working      │    │
│  │ (Sensors)    │     │ (CLIPS)      │     │ Memory       │    │
│  └──────────────┘     └──────────────┘     └──────┬───────┘    │
│                                                    │             │
│                                                    ▼             │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │ Defense      │◀────│ Inference    │◀────│ Rule Base    │    │
│  │ Actions      │     │ Engine       │     │ (1687 lines) │    │
│  └──────────────┘     └──────┬───────┘     └──────────────┘    │
│                              │                                   │
│                              ▼                                   │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐    │
│  │ Real-time    │◀────│ Alert        │────▶│ Report       │    │
│  │ Dashboard    │     │ Generation   │     │ Generation   │    │
│  └──────────────┘     └──────────────┘     └──────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Code Snippets

### 4.1 CLIPS Rule Example (FLSec-RPL Malicious Detection)

```clips
;;; R_FLSec_1: High DIO + Low DTI + Low STIA = Malicious [Reference 9]
(defrule R-FLSec-1-Malicious
   "FLSec-RPL: Detect Malicious Node - DIO High, DTI Low, STIA Low"
   (declare (salience 100))
   
   ;; Pattern matching conditions
   (dio-counter (node-id ?nid) (level High))
   (dti-record (node-id ?nid) (level Low))
   (stia-record (node-id ?nid) (level Low))
   
   ;; Counter management
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   
   ;; Avoid duplicate alerts
   (not (attack-alert (attack-type "DIO-Suppression-Malicious") (node-id ?nid)))
   
   =>
   
   ;; Generate attack alert
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "DIO-Suppression-Malicious")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "Node " ?nid " identified as MALICIOUS"))))
   
   ;; Generate defense recommendation
   (assert (defense-action
      (action-type "BLOCK_PERMANENT")
      (target-node ?nid)
      (priority "CRITICAL")
      (description "Permanently isolate malicious node"))))
```

### 4.2 Python CLIPS Integration

```python
# app.py - CLIPS Integration
import clips

# Initialize CLIPS environment
clips_env = clips.Environment()

def inject_attack_fact(attack_type, source, target, **kwargs):
    """Inject attack facts into CLIPS working memory"""
    global clips_env
    
    # Build attack-specific facts based on literature rules
    if attack_type == 'DIO-Suppression':
        dio_level = kwargs.get('dio_level', 'High')
        dti_level = kwargs.get('dti_level', 'Low')
        stia_level = kwargs.get('stia_level', 'Low')
        
        # Assert facts to CLIPS
        clips_env.assert_string(
            f'(dio-counter (node-id "{source}") (count 100) (level {dio_level}))'
        )
        clips_env.assert_string(
            f'(dti-record (node-id "{source}") (interval 0.1) (level {dti_level}))'
        )
        clips_env.assert_string(
            f'(stia-record (node-id "{source}") (value 0.2) (level {stia_level}))'
        )
    
    return True, result

def run_inference():
    """Execute CLIPS inference engine"""
    global clips_env
    rules_fired = clips_env.run()  # Forward chaining execution
    return True, rules_fired
```

### 4.3 Real-time WebSocket Communication

```python
# Flask-SocketIO for real-time updates
from flask_socketio import SocketIO, emit

socketio = SocketIO(app, cors_allowed_origins="*")

# Emit alert to all connected clients
def emit_alert(alert_data):
    socketio.emit('new_alert', alert_data, namespace='/')

# Emit defense action
def emit_defense(defense_data):
    socketio.emit('new_defense', defense_data, namespace='/')

# Emit report update for real-time sync
def emit_report_update(report_data):
    socketio.emit('report_update', report_data, namespace='/')
```

### 4.4 CNF for SAT Verification

```
p cnf 215 47
1 2 3 0
-1 -2 0
-1 -3 0
-2 -3 0
-1 -6 -9 101 0
-101 201 0
```

Encoding: `(DIO_High ∧ DTI_Low ∧ STIA_Low) → MALICIOUS → DEFENSE_BLOCK`

---

## 5. Special Features

### 5.1 Multi-Literature Rule Integration

The system integrates rules from **10 academic papers**:

| Reference | Technique | Attack Type |
|-----------|-----------|-------------|
| [9] FLSec-RPL | Fuzzy Logic | DIO Suppression |
| [15] | Signal Analysis | Jamming |
| [3] PRBA | Passive Rule-Based | Sinkhole |
| [11] RF | Random Forest ML | Multi-Attack |
| [6] XAI | Isolation Forest | Anomaly |
| [14] UVM | Voting Method | Multi-Rule Voting |
| [13] Hybrid IDS | Combined Approach | Hello Flood, Version |
| [2] SRPL-RP | Secure RPL | Rank Attack |
| [10] Distributed | Threshold-Based | Violations |
| [12] FLBT-RPL | Federated Learning | Sybil |

### 5.2 Real-time Topology Visualization

- Interactive drag-and-drop network design
- Live node color changes based on attack severity:
  - 🔴 Red = MALICIOUS (CRITICAL)
  - 🟠 Orange = QUARANTINE (HIGH)
  - 🟣 Purple = VICTIM (MEDIUM)
  - 🟡 Yellow = WARNING (LOW)

### 5.3 Inference Path Explanation

The system provides transparent reasoning:

```
Rule: DIO-Suppression-Malicious-Detection
Trigger: DIO_Counter=High AND DTI=Low AND STIA=Low
Conclusion: Aggressive_Weight = Malicious
Evidence: Excessive DIO messages with short intervals
```

### 5.4 SAT Solver Verification

Rules are formally verified using SAT solving:
- **Consistency Check**: No contradictions in rule base
- **Completeness Check**: All attack scenarios have responses
- **Safety Verification**: Critical attacks always trigger blocking

### 5.5 Dynamic Severity Calculation

Severity is calculated based on actual inference results, not static configuration:

```python
# If no rules fired → LOW severity (normal behavior)
if rules_fired == 0:
    actual_severity = 'LOW'
else:
    # Get highest severity from generated alerts
    actual_severity = max(alert.level for alert in new_alerts)
```

---

## 6. Execution Screenshots

### Screenshot Locations (to capture):

1. **Dashboard** - `http://localhost:5000/` - Main monitoring view
2. **Hacker Lab** - `http://localhost:5000/hacker` - Attack simulation
3. **Topology** - `http://localhost:5000/topology` - Network designer
4. **Defense Center** - `http://localhost:5000/defense` - Real-time alerts
5. **Report** - `http://localhost:5000/report` - Diagnostic report

### Key Visual Elements:

| Page | Feature | Visual |
|------|---------|--------|
| Hacker Lab | Attack Parameters | Dropdown selectors for DIO/DTI/STIA levels |
| Hacker Lab | Console Output | Real-time attack injection feedback |
| Topology | Network Graph | vis.js force-directed layout |
| Topology | Node Colors | Dynamic color based on attack status |
| Defense | Alert Stream | Scrolling alert feed with timestamps |
| Report | Severity Banner | Color-coded severity indicator |
| Report | Inference Path | Visual rule chain explanation |

---

## 7. References

1. [2] SRPL-RP: Secure RPL Routing Protocol (98.48% accuracy)
2. [3] PRBA: Passive Rule-Based Approach (90-100% accuracy)
3. [6] XAI: Explainable AI with Isolation Forest (98-100% accuracy)
4. [9] FLSec-RPL: Fuzzy Logic Security (97-100% accuracy)
5. [10] Distributed IDS: Threshold-based Detection (~100% accuracy)
6. [11] Random Forest: Multi-Attack Detection (85-88% accuracy)
7. [12] FLBT-RPL: Federated Learning Sybil Detection (98% accuracy)
8. [13] Hybrid IDS: Combined Approach (95% estimated)
9. [14] UVM: Unweighted Voting Method (100% with voting)
10. [15] Jamming Detection: Signal Analysis (51-99% variable)

---

## Programming Languages and Tools Used

### Programming Languages
- **Python**: Main backend logic, expert system integration, and API endpoints (Flask, CLIPS integration).
- **JavaScript**: Front-end interactivity, AJAX requests, and dynamic UI updates.
- **HTML/CSS**: User interface structure and styling (dashboard, hacker, defense, report, topology pages).

### Tools, Libraries, and Frameworks
- **Flask**: Python web framework for backend API and web server.
- **Flask-SocketIO**: Real-time communication between server and client (WebSocket events).
- **CLIPS (clipspy)**: Expert system engine for rule-based reasoning and attack detection.
- **Jinja2**: Templating engine for rendering HTML pages from Flask.
- **pip**: Python package manager for dependency management.
- **Virtual Environment (venv)**: Isolated Python environment for package management.

### Front-End Libraries
- **Bootstrap**: Responsive UI components and layout (if used in templates).
- **jQuery**: Simplified DOM manipulation and AJAX (if used in scripts).

### Other
- **Batch Scripts (.bat)**: For starting the application on Windows.
- **requirements.txt**: Lists Python dependencies for easy setup.

---

*Document generated for IoT-Guardian Expert System v1.0*
*© 2026 IoT-Guardian - All Rights Reserved*
