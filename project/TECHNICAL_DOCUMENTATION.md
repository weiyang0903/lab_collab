# IoT-Guardian Expert System - Technical Documentation

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

*Document generated for IoT-Guardian Expert System v1.0*
*© 2026 IoT-Guardian - All Rights Reserved*
