"""
IoT-Guardian: Expert System for IoT Network Security
Main Flask Application with CLIPS Integration
"""

import os
import json
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
import clips

# ===========================================
# Flask Application Configuration
# ===========================================
app = Flask(__name__)
app.config['SECRET_KEY'] = 'iot-guardian-secret-key-2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# ===========================================
# Global CLIPS Environment
# ===========================================
clips_env = clips.Environment()

# Track last attack target for alert node_id mapping
last_attack_target = 'gateway-001'

# In-memory Fact Base for network simulation
fact_base = {
    'packets': [],
    'devices': [],
    'attacks': [],
    'alerts': [],
    'defenses': [],
    'inference_paths': [],
    'reasons': [],
    'inference_log': []
}

# Attack history for reporting
attack_history = []

# ===========================================
# CLIPS Utility Functions
# ===========================================

def load_clips_rules(rules_file='rules/rpl_rules.clp'):
    """Load CLIPS rules from .clp file"""
    global clips_env
    try:
        rules_path = os.path.join(os.path.dirname(__file__), rules_file)
        clips_env.clear()
        clips_env.load(rules_path)
        clips_env.reset()
        log_inference(f"Loaded rules from {rules_file}")
        return True, "Rules loaded successfully"
    except Exception as e:
        error_msg = f"Error loading rules: {str(e)}"
        log_inference(error_msg)
        return False, error_msg


def reset_clips_environment():
    """Reset the CLIPS environment to initial state"""
    global clips_env, fact_base
    try:
        clips_env.reset()
        fact_base = {
            'packets': [],
            'devices': [],
            'attacks': [],
            'alerts': [],
            'defenses': [],
            'inference_paths': [],
            'reasons': [],
            'inference_log': []
        }
        log_inference("Environment reset to initial state")
        return True
    except Exception as e:
        log_inference(f"Reset error: {str(e)}")
        return False


# Server-side topology storage for cross-page synchronization
current_topology = {
    'nodes': [
        {'id': 'gateway-001', 'label': 'IoT Gateway\n(Border Router)', 'type': 'gateway'},
        {'id': 'router-001', 'label': 'Router-01', 'type': 'router'},
        {'id': 'sensor-001', 'label': 'Temp Sensor', 'type': 'sensor'},
        {'id': 'sensor-002', 'label': 'Humidity', 'type': 'sensor'},
        {'id': 'camera-001', 'label': 'Security Cam', 'type': 'camera'},
        {'id': 'actuator-001', 'label': 'Smart Lock', 'type': 'actuator'}
    ],
    'edges': [
        {'from': 'gateway-001', 'to': 'router-001'},
        {'from': 'router-001', 'to': 'sensor-001'},
        {'from': 'router-001', 'to': 'sensor-002'},
        {'from': 'gateway-001', 'to': 'camera-001'},
        {'from': 'gateway-001', 'to': 'actuator-001'}
    ]
}


def log_inference(message):
    """Log inference steps"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        'timestamp': timestamp,
        'message': message
    }
    fact_base['inference_log'].append(log_entry)
    # Emit to connected clients via WebSocket
    socketio.emit('inference_update', log_entry)


def clear_intermediate_facts(node_id):
    """Clear intermediate classification facts for a specific node to allow re-attack"""
    global clips_env
    try:
        # List of intermediate fact templates used by conflict resolution rules
        intermediate_templates = [
            'rf-attack-class',          # RF Multi-Attack classification
            'dio-threat-score',         # DIO Suppression threat score
            'jamming-index',            # Jamming classification
            'xai-anomaly-class',        # XAI anomaly classification
            'sinkhole-suspicion-class', # PRBA/UVM Sinkhole classification
        ]
        
        # Also clear existing attack alerts for the node to allow re-detection
        alert_templates = [
            'attack-alert',
        ]
        
        facts_to_retract = []
        for fact in clips_env.facts():
            fact_str = str(fact)
            # Check if fact belongs to intermediate templates and matches node_id
            for template in intermediate_templates + alert_templates:
                if template in fact_str and node_id in fact_str:
                    facts_to_retract.append(fact)
                    break
        
        # Retract found facts
        for fact in facts_to_retract:
            try:
                fact.retract()
                log_inference(f"Cleared intermediate fact for node {node_id}")
            except:
                pass  # Fact may already be retracted
                
    except Exception as e:
        log_inference(f"Warning: Could not clear intermediate facts: {str(e)}")


def inject_attack_fact(attack_type, source='attacker-node', target='gateway-001', **kwargs):
    """Inject an attack indicator fact into CLIPS (RPL-based) - Based on Literature Rules"""
    global clips_env, last_attack_target
    # Store target for alert node_id mapping
    last_attack_target = target
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    current_ts = int(datetime.now().timestamp()) % 10000
    
    # Clear intermediate classification facts for the source node to allow re-attack
    # This enables users to attack the same node multiple times without needing to reset
    clear_intermediate_facts(source)
    
    # Map attack types to severity and configuration (Based on Literature)
    # Attack configuration mapping
    # 
    # Confidence values are derived from literature-reported accuracy/detection rates:
    # [2] SRPL-RP: Accuracy 98.30% (Version), 98.48% (Rank) - Cooja, 20 nodes
    # [3] PRBA: Accuracy 90-100%, FPR 0-0.2% - RPL-NIDDS17 dataset
    # [6] XAI (Isolation Forest): Accuracy 98-100%, F1 96-100% - IoMT Sinkhole/Blackhole
    # [9] FLSec-RPL: Accuracy 97-100% (static), 75-100% (mobile), F1 91-100%
    # [10] Distributed IDS: ~100% detection, FPR 1-2% - Contiki-NG, Rank attacks
    # [11] RF Multi-Attack: Rank 88.4%, SF 87.1%, DoS 85.2% - 50 nodes, Cooja
    # [12] FLBT-RPL: Detection Rate 98% - Smart Healthcare CPS, 90 nodes
    # [13] Hybrid IDS: High accuracy (not quantified), CPU <2% - 6 attack types
    # [14] UVM: DR 100% (voting), 90% (no voting), Accuracy 94.5% - RPL-NIDDS17
    # [15] Jamming FLIDS: Accuracy 51.49-99.70% (location dependent) - Multiple jammers
    #
    attack_config = {
        # [9] FLSec-RPL: 97-100% static → use 97 (conservative)
        'DIO-Suppression': {'severity': 'CRITICAL', 'confidence': 97, 'description': 'DIO Neighbor Suppression Attack - Excessive DIO messages with short intervals'},
        # [15] Jamming: 51.49-99.70% → use 76 (median, highly variable)
        'Jamming': {'severity': 'CRITICAL', 'confidence': 76, 'description': 'Wireless Signal Jamming Attack - High ETX and retransmissions'},
        # [3] PRBA: 90-100% → use 95 (midpoint)
        'Sinkhole': {'severity': 'CRITICAL', 'confidence': 95, 'description': 'Sinkhole Attack - Malicious node forges low Rank to attract traffic'},
        # [3] PRBA: 90-100% → use 92 (slightly lower for bidirectional)
        'Sinkhole-Bidirectional': {'severity': 'HIGH', 'confidence': 92, 'description': 'Bidirectional Behavior Anomaly - Suspicious traffic patterns detected'},
        # [3]+[14] PRBA/UVM Combined: use 95 (integrated conflict resolution)
        'Sinkhole-PRBA': {'severity': 'CRITICAL', 'confidence': 95, 'description': 'Sinkhole Attack - PRBA/UVM combined detection with 5-rule scoring'},
        # [11] RF: SF 87.1% → use 87
        'SelectiveForwarding': {'severity': 'HIGH', 'confidence': 87, 'description': 'Selective Forwarding Attack - Abnormal packet drop rate detected'},
        # [11] RF: DoS 85.2% → use 85
        'DoS': {'severity': 'CRITICAL', 'confidence': 85, 'description': 'DoS Attack - Abnormal duplicate packet rate and forwarding rate'},
        # [11] RF: Rank 88.4% → use 88
        'RankAttack': {'severity': 'HIGH', 'confidence': 88, 'description': 'Rank Attack - Significant Rank value manipulation detected'},
        # [6] XAI: 98-100% → use 98
        'XAI-Anomaly': {'severity': 'HIGH', 'confidence': 98, 'description': 'Anomaly Detected - Unusual behavior pattern identified'},
        # [14] UVM: 100% with voting → use 100
        'Sinkhole-UVM': {'severity': 'CRITICAL', 'confidence': 100, 'description': 'Sinkhole Attack - Multiple detection rules confirmed malicious behavior'},
        # [13] Hybrid IDS: High accuracy → use 95 (estimated)
        'HelloFlood': {'severity': 'HIGH', 'confidence': 95, 'description': 'Hello Flood Attack - DIO message flooding (threshold: 20)'},
        # [11] RF Rule 5: DIS Flooding
        'DIS-Flooding': {'severity': 'HIGH', 'confidence': 87, 'description': 'DIS Flooding Attack - DIS message flooding (threshold: 15)'},
        # [13] Hybrid IDS + [2] SRPL-RP: 98.30% → use 98
        'VersionNumber': {'severity': 'HIGH', 'confidence': 98, 'description': 'Version Number Attack - Forged version triggers DODAG reconstruction'},
        # [10] Distributed IDS: ~100% → use 98
        'RankDecrease': {'severity': 'HIGH', 'confidence': 98, 'description': 'Rank Decrease Attack - Suspicious Rank reduction detected'},
        # [2] SRPL-RP: 98.48% → use 98
        'SRPL-Malicious': {'severity': 'CRITICAL', 'confidence': 98, 'description': 'Malicious Node - Parent-Child Rank Violation detected'},
        # [2] SRPL-RP: 98.48% → use 98
        'SRPL-RankDecrease': {'severity': 'CRITICAL', 'confidence': 98, 'description': 'Abnormal Rank Decrease - Beyond acceptable threshold'},
        # [2] SRPL-RP: 98.30% → use 98
        'SRPL-RankIncrease': {'severity': 'HIGH', 'confidence': 98, 'description': 'Abnormal Rank Increase - Potential manipulation detected'},
        # [10] Distributed IDS: ~100%, FPR 1-2% → use 98
        'Dist-IDS-Violation': {'severity': 'HIGH', 'confidence': 98, 'description': 'Security Violation - Threshold exceeded in monitoring window'},
        # [12] FLBT-RPL: DR 98% → use 98
        'Sybil': {'severity': 'CRITICAL', 'confidence': 98, 'description': 'Sybil Attack - Multiple fake identities detected from single node'}
    }
    
    config = attack_config.get(attack_type, {
        'severity': 'UNKNOWN', 
        'confidence': 50, 
        'description': 'Unknown attack type'
    })
    
    facts_to_assert = []
    
    # Build attack-specific CLIPS facts based on Literature Rules
    
    # ========== FLSec-RPL (reference[9]) ==========
    if attack_type == 'DIO-Suppression':
        dio_level = kwargs.get('dio_level', 'High')
        dti_level = kwargs.get('dti_level', 'Low')
        stia_level = kwargs.get('stia_level', 'Low')
        facts_to_assert.append(f'(dio-counter (node-id "{source}") (count 100) (level {dio_level}))')
        facts_to_assert.append(f'(dti-record (node-id "{source}") (interval 0.1) (level {dti_level}))')
        facts_to_assert.append(f'(stia-record (node-id "{source}") (value 0.2) (level {stia_level}))')
    
    # ========== Jamming (reference[15]) ==========
    elif attack_type == 'Jamming':
        etx_level = kwargs.get('etx_level', 'High')
        retrans_level = kwargs.get('retrans_level', 'High')
        facts_to_assert.append(f'(etx-record (node-id "{source}") (value 5.0) (level {etx_level}))')
        facts_to_assert.append(f'(retransmission-record (node-id "{source}") (count 50) (level {retrans_level}))')
    
    # ========== PRBA Sinkhole (reference[3]) ==========
    elif attack_type == 'Sinkhole':
        prev_rank = kwargs.get('prev_rank', 150)
        curr_rank = kwargs.get('curr_rank', 1)
        facts_to_assert.append(f'(node-rank-history (node-id "{source}") (previous-rank {prev_rank}) (current-rank {curr_rank}) (timestamp {current_ts}))')
        
    elif attack_type == 'Sinkhole-Bidirectional':
        parent_id = kwargs.get('parent_id', 'parent-001')
        count = kwargs.get('count', 6)
        facts_to_assert.append(f'(bidirectional-behavior (child-id "{source}") (parent-id "{parent_id}") (count {count}) (timestamp {current_ts}))')
    
    # ========== PRBA/UVM Sinkhole Combined (reference[3],[14]) ==========
    elif attack_type == 'Sinkhole-PRBA':
        # Comprehensive Sinkhole detection using 5 rules:
        # Rule 1&2: Bidirectional behavior
        parent_id = kwargs.get('parent_id', 'parent-001')
        bid_count = kwargs.get('bid_count', 6)
        # Rule 3: Power consumption
        power_value = float(kwargs.get('power_value', 85.0))
        power_threshold = float(kwargs.get('power_threshold', 50.0))
        # Rule 4: DIO frequency
        dio_current = kwargs.get('dio_current', 15)
        dio_previous = kwargs.get('dio_previous', 5)
        # Rule 5: Rank harmony - NRP > SRN triggers (malicious node fakes low rank)
        # Default: Parent=100, Node=50, Sink=1 → NRP=50, SRN=49 → NRP > SRN ✓
        parent_rank = kwargs.get('parent_rank', 100)
        node_rank = kwargs.get('node_rank', 50)  # Malicious node fakes low rank
        sink_rank = kwargs.get('sink_rank', 1)
        
        # Inject all relevant facts for comprehensive detection
        facts_to_assert.append(f'(bidirectional-behavior (child-id "{source}") (parent-id "{parent_id}") (count {bid_count}) (timestamp {current_ts}))')
        facts_to_assert.append(f'(power-consumption (node-id "{source}") (value {power_value}) (threshold {power_threshold}))')
        facts_to_assert.append(f'(dio-message-stats (node-id "{source}") (current-count {dio_current}) (previous-count {dio_previous}))')
        facts_to_assert.append(f'(rank-harmony (node-id "{source}") (parent-rank {parent_rank}) (node-rank {node_rank}) (sink-rank {sink_rank}))')
    
    # ========== RF Multi-Attack (reference[11]) ==========
    elif attack_type == 'SelectiveForwarding':
        drop_rate = kwargs.get('drop_rate', 0.35)
        threshold = kwargs.get('threshold', 0.2)
        facts_to_assert.append(f'(pdrr-record (node-id "{source}") (rate {drop_rate}) (threshold {threshold}))')
        
    elif attack_type == 'DoS':
        dpr = kwargs.get('dpr', 0.8)
        pfr = kwargs.get('pfr', 0.9)
        facts_to_assert.append(f'(dpr-record (node-id "{source}") (rate {dpr}) (threshold 0.5))')
        facts_to_assert.append(f'(pfr-record (node-id "{source}") (rate {pfr}) (threshold 0.6))')
        
    elif attack_type == 'RankAttack':
        prev_rank = kwargs.get('prev_rank', 200)
        curr_rank = kwargs.get('curr_rank', 50)
        facts_to_assert.append(f'(node-rank-history (node-id "{source}") (previous-rank {prev_rank}) (current-rank {curr_rank}) (timestamp {current_ts}))')
    
    # ========== XAI Anomaly (reference[6]) ==========
    elif attack_type == 'XAI-Anomaly':
        npc = float(kwargs.get('npc', 1.0))
        nc = float(kwargs.get('nc', 2.0))
        udp_recv = float(kwargs.get('udp_recv', 15.0))
        udp_trans = float(kwargs.get('udp_trans', 2.0))
        udp_fwd = float(kwargs.get('udp_fwd', 0.3))
        pf_rate = float(kwargs.get('pf_rate', 0.4))
        facts_to_assert.append(f'(npc-record (node-id "{source}") (count {npc:.2f}) (timestamp {current_ts}))')
        facts_to_assert.append(f'(nc-record (node-id "{source}") (count {nc:.2f}))')
        facts_to_assert.append(f'(udp-received (node-id "{source}") (count {udp_recv:.2f}))')
        facts_to_assert.append(f'(udp-transmitted (node-id "{source}") (count {udp_trans:.2f}))')
        facts_to_assert.append(f'(udp-forwarded (node-id "{source}") (count {udp_fwd:.2f}))')
        facts_to_assert.append(f'(packet-forwarding (node-id "{source}") (rate {pf_rate:.2f}))')
    
    # ========== UVM Voting (reference[14]) ==========
    elif attack_type == 'Sinkhole-UVM':
        abnormal = kwargs.get('abnormal_count', 4)
        total = kwargs.get('total_rules', 5)
        facts_to_assert.append(f'(voting-result (node-id "{source}") (abnormal-count {abnormal}) (total-rules {total}))')
    
    # ========== Hybrid IDS (reference[13]) ==========
    elif attack_type == 'HelloFlood':
        dio_count = kwargs.get('dio_count', 50)
        dis_count = kwargs.get('dis_count', 5)   # Default below threshold for DIO-focused attack
        dao_count = kwargs.get('dao_count', 5)   # Default below threshold
        facts_to_assert.append(f'(control-message-counter (node-id "{source}") (dio-count {dio_count}) (dis-count {dis_count}) (dao-count {dao_count}) (dio-threshold 20) (dis-threshold 15) (dao-threshold 10))')
    
    # ========== DIS Flooding (RF Rule 5) ==========
    elif attack_type == 'DIS-Flooding':
        dis_count = kwargs.get('dis_count', 30)
        dio_count = kwargs.get('dio_count', 5)   # Default below threshold
        dao_count = kwargs.get('dao_count', 5)   # Default below threshold
        facts_to_assert.append(f'(control-message-counter (node-id "{source}") (dio-count {dio_count}) (dis-count {dis_count}) (dao-count {dao_count}) (dio-threshold 20) (dis-threshold 15) (dao-threshold 10))')
            
    elif attack_type == 'VersionNumber':
        prev_version = kwargs.get('prev_version', 5)
        curr_version = kwargs.get('curr_version', 15)
        facts_to_assert.append(f'(version-record (node-id "{source}") (previous-version {prev_version}) (current-version {curr_version}) (timestamp {current_ts}))')
        
    elif attack_type == 'RankDecrease':
        recv_rank = kwargs.get('recv_rank', 50)
        avg_rank = kwargs.get('avg_rank', 200)
        max_rank = kwargs.get('max_rank', 300)
        k_factor = kwargs.get('k_factor', 0.3)
        facts_to_assert.append(f'(neighbor-rank-stats (node-id "{source}") (received-rank {recv_rank}) (avg-neighbor-rank {avg_rank}) (max-neighbor-rank {max_rank}) (k-factor {k_factor}))')
    
    # ========== SRPL-RP (reference[2]) ==========
    elif attack_type == 'SRPL-Malicious':
        ncr = kwargs.get('ncr', 100)
        npr = kwargs.get('npr', 150)
        facts_to_assert.append(f'(srpl-rank-check (node-id "{source}") (ncr {ncr}) (npr {npr}) (nor 120) (msr 130) (mcr 140) (pst 10))')
        
    elif attack_type == 'SRPL-RankDecrease':
        ncr = kwargs.get('ncr', 80)
        nor = kwargs.get('nor', 150)
        msr = kwargs.get('msr', 120)
        pst = kwargs.get('pst', 20)
        facts_to_assert.append(f'(srpl-rank-check (node-id "{source}") (ncr {ncr}) (npr 200) (nor {nor}) (msr {msr}) (mcr 180) (pst {pst}))')
        
    elif attack_type == 'SRPL-RankIncrease':
        ncr = kwargs.get('ncr', 200)
        nor = kwargs.get('nor', 150)
        mcr = kwargs.get('mcr', 180)
        facts_to_assert.append(f'(srpl-rank-check (node-id "{source}") (ncr {ncr}) (npr 100) (nor {nor}) (msr 160) (mcr {mcr}) (pst 10))')
    
    # ========== Distributed IDS (reference[10]) ==========
    elif attack_type == 'Dist-IDS-Violation':
        violation_count = kwargs.get('violation_count', 6)
        threshold = kwargs.get('threshold', 5)
        facts_to_assert.append(f'(violation-counter (node-id "{source}") (count {violation_count}) (threshold {threshold}) (time-window 30))')
    
    # ========== FLBT-RPL Sybil (reference[12]) ==========
    elif attack_type == 'Sybil':
        ics = kwargs.get('ics', 0.9)
        scs = kwargs.get('scs', 0.8)
        res = kwargs.get('res', 0.7)
        rms = kwargs.get('rms', 0.85)
        bis = kwargs.get('bis', 0.75)
        tds = kwargs.get('tds', 0.6)
        facts_to_assert.append(f'(sybil-indicators (node-id "{source}") (ics {ics}) (scs {scs}) (res {res}) (rms {rms}) (bis {bis}) (tds {tds}) (ics-threshold 0.7) (scs-threshold 0.7) (res-threshold 0.7) (rms-threshold 0.7) (bis-threshold 0.7) (tds-threshold 0.7))')
    
    else:
        # Generic fallback
        facts_to_assert.append(f'(rpl-packet (node-id "{source}") (rank 100) (packet-type "DIO"))')
    
    try:
        # Assert all facts in CLIPS
        for fact_str in facts_to_assert:
            clips_env.assert_string(fact_str)
            log_inference(f"Asserted fact: {fact_str[:80]}...")
        
        log_inference(f"Injected {attack_type} attack facts from {source}")
        
        # Store in fact base
        attack_record = {
            'type': attack_type,
            'source': source,
            'target': target,
            'severity': config['severity'],
            'confidence': config['confidence'],
            'description': config['description'],
            'timestamp': timestamp
        }
        fact_base['attacks'].append(attack_record)
        attack_history.append(attack_record)
        
        return True, attack_record
    except Exception as e:
        error_msg = f"Error injecting attack: {str(e)}"
        log_inference(error_msg)
        return False, error_msg


def run_inference():
    """Run the CLIPS inference engine"""
    global clips_env
    try:
        log_inference("Starting inference engine...")
        rules_fired = clips_env.run()
        log_inference(f"Inference complete. Rules fired: {rules_fired}")
        
        # Collect results
        collect_inference_results()
        
        return True, rules_fired
    except Exception as e:
        error_msg = f"Inference error: {str(e)}"
        log_inference(error_msg)
        return False, 0


def collect_inference_results():
    """Collect facts generated by inference (RPL rules)"""
    global clips_env, fact_base
    
    # Collect new results without clearing (add to existing)
    new_alerts = []
    new_defenses = []
    new_paths = []
    new_reasons = []
    
    # Use a running counter based on existing items to generate unique IDs
    # This ensures each attack generates unique IDs even after CLIPS reset
    base_alert_id = len(fact_base.get('alerts', []))
    base_defense_id = len(fact_base.get('defenses', []))
    base_path_id = len(fact_base.get('inference_paths', []))
    
    # Use timestamp to allow same attack type on same node at different times
    current_timestamp = datetime.now().strftime("%H:%M:%S")
    
    # Track (node_id, attack_type, timestamp) - allow repeated attacks at different times
    # But avoid duplicates within the SAME attack (CLIPS may generate multiple facts)
    session_alert_keys = set()
    session_defense_keys = set()
    session_path_keys = set()
    
    try:
        fact_count = 0
        for fact in clips_env.facts():
            fact_str = str(fact)
            fact_count += 1
            
            # Parse attack-alert facts (RPL rules)
            if 'attack-alert' in fact_str:
                alert = parse_attack_alert_fact(fact)
                if alert:
                    # Use message as part of key to differentiate attacks with different parameters
                    alert_key = (alert.get('node_id', ''), alert.get('attack_type', ''), alert.get('message', '')[:50])
                    if alert_key not in session_alert_keys:
                        # Assign unique ID based on running count
                        alert['alert_id'] = base_alert_id + len(new_alerts) + 1
                        alert['timestamp'] = current_timestamp
                        new_alerts.append(alert)
                        session_alert_keys.add(alert_key)
                        log_inference(f"Found new alert: {alert.get('attack_type')} for node {alert.get('node_id')}")
            
            # Parse defense-action facts
            elif 'defense-action' in fact_str:
                defense = parse_defense_fact(fact)
                if defense:
                    # Include description to differentiate same action type with different details
                    defense_key = (defense.get('target_node', ''), defense.get('action_type', ''), defense.get('description', '')[:50])
                    if defense_key not in session_defense_keys:
                        # Assign unique ID based on running count
                        defense['defense_id'] = base_defense_id + len(new_defenses) + 1
                        defense['timestamp'] = current_timestamp
                        new_defenses.append(defense)
                        session_defense_keys.add(defense_key)
                        log_inference(f"Found new defense: {defense.get('action_type')} for node {defense.get('target_node')}")
            
            # Parse inference-path facts
            elif 'inference-path' in fact_str:
                path = parse_inference_path_fact(fact)
                if path:
                    # Include trigger condition to differentiate paths
                    path_key = (path.get('rule_name', ''), path.get('node_id', ''), path.get('trigger_condition', '')[:30])
                    if path_key not in session_path_keys:
                        path['step_id'] = base_path_id + len(new_paths) + 1
                        new_paths.append(path)
                        session_path_keys.add(path_key)
                        log_inference(f"Found new inference path: {path.get('rule_name')}")
            
            # Parse reason facts
            elif '(reason' in fact_str:
                reason = parse_reason_fact(fact)
                if reason:
                    new_reasons.append(reason)
                    log_inference(f"Found new reason: {reason.get('attack_type')}")
        
        log_inference(f"Scanned {fact_count} facts, found {len(new_alerts)} alerts, {len(new_defenses)} defenses, {len(new_paths)} paths, {len(new_reasons)} reasons")
        
        # Add new items to fact_base
        fact_base['alerts'].extend(new_alerts)
        fact_base['defenses'].extend(new_defenses)
        fact_base['inference_paths'].extend(new_paths)
        fact_base['reasons'].extend(new_reasons)
        
        # Emit ONLY new results via WebSocket
        for alert in new_alerts:
            # Include attack_type in alert for topology to determine correct node color
            alert_with_type = alert.copy()
            # Map attack type to action type for color determination (case-insensitive)
            attack_type = alert.get('attack_type', '').upper()
            if 'MALICIOUS' in attack_type:
                alert_with_type['action_type'] = 'BLOCK_PERMANENT'
            elif 'QUARANTINE' in attack_type:
                alert_with_type['action_type'] = 'QUARANTINE'
            elif 'VICTIM' in attack_type:
                alert_with_type['action_type'] = 'VICTIM'
            log_inference(f"Emitting alert with node_id: {alert.get('node_id')}, level: {alert.get('level')}, action_type: {alert_with_type.get('action_type')}, attack_type: {alert.get('attack_type')}")
            socketio.emit('new_alert', alert_with_type, namespace='/')
        for defense in new_defenses:
            # Add attack_type and level for topology color determination
            defense_with_type = defense.copy()
            action_type = defense.get('action_type', '').upper()
            # Determine attack_type from action_type for color matching
            if 'BLOCK_PERMANENT' in action_type or 'BLOCK-PERMANENT' in action_type:
                defense_with_type['attack_type'] = 'Malicious'
                defense_with_type['level'] = 'CRITICAL'
            elif 'QUARANTINE' in action_type or 'ISOLATE' in action_type:
                defense_with_type['attack_type'] = 'Quarantine'
                defense_with_type['level'] = 'HIGH'
            elif 'VICTIM' in action_type:
                defense_with_type['attack_type'] = 'Victim'
                defense_with_type['level'] = 'HIGH'
            else:
                defense_with_type['level'] = defense.get('priority', 'MEDIUM')
            log_inference(f"Emitting defense: {defense.get('action_type')} for target: {defense.get('target')}, attack_type: {defense_with_type.get('attack_type')}")
            socketio.emit('new_defense', defense_with_type, namespace='/')
        for path in new_paths:
            log_inference(f"Emitting inference_path: {path.get('rule_name')}")
            socketio.emit('inference_path', path, namespace='/')
        for reason in new_reasons:
            log_inference(f"Emitting reason: {reason.get('explanation')[:50]}...")
            socketio.emit('new_reason', reason, namespace='/')
                    
    except Exception as e:
        log_inference(f"Error collecting results: {str(e)}")


def parse_attack_alert_fact(fact):
    """Parse an attack-alert fact into dictionary (RPL rules)"""
    global last_attack_target
    try:
        node_id = str(fact['node-id']) if hasattr(fact, '__getitem__') else 'N/A'
        
        # Use last attack target if available, otherwise try mapping
        if hasattr(parse_attack_alert_fact, 'last_target') and parse_attack_alert_fact.last_target:
            display_node = parse_attack_alert_fact.last_target
        elif 'last_attack_target' in globals() and last_attack_target:
            display_node = last_attack_target
        else:
            # Fallback: Map common attack node IDs to topology node IDs
            topology_node_map = {
                'malicious-node-001': 'gateway-001',
                'compromised-sensor': 'sensor-001',
                'rogue-device': 'router-001',
                'external-attacker': 'gateway-001'
            }
            display_node = topology_node_map.get(node_id, node_id)
            if display_node not in ['gateway-001', 'sensor-001', 'sensor-002', 'camera-001', 'actuator-001', 'router-001']:
                display_node = 'gateway-001'  # Default to gateway for visualization
        
        return {
            'alert_id': fact['alert-id'] if hasattr(fact, '__getitem__') else 0,
            'level': str(fact['severity']) if hasattr(fact, '__getitem__') else 'UNKNOWN',
            'attack_type': str(fact['attack-type']) if hasattr(fact, '__getitem__') else 'UNKNOWN',
            'node_id': display_node,
            'source_node': node_id,
            'message': str(fact['message']) if hasattr(fact, '__getitem__') else str(fact),
            'timestamp': str(fact['timestamp']) if hasattr(fact, '__getitem__') else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except:
        fact_str = str(fact)
        return {
            'alert_id': 0,
            'level': 'INFO',
            'attack_type': 'UNKNOWN',
            'node_id': 'gateway-001',
            'source_node': 'N/A',
            'message': fact_str,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }


def parse_inference_path_fact(fact):
    """Parse an inference-path fact into dictionary (推理路径)"""
    try:
        return {
            'step_id': fact['step-id'] if hasattr(fact, '__getitem__') else 0,
            'rule_name': str(fact['rule-name']) if hasattr(fact, '__getitem__') else 'UNKNOWN',
            'trigger_condition': str(fact['trigger-condition']) if hasattr(fact, '__getitem__') else '',
            'conclusion': str(fact['conclusion']) if hasattr(fact, '__getitem__') else '',
            'node_id': str(fact['node-id']) if hasattr(fact, '__getitem__') else 'N/A',
            'timestamp': str(fact['timestamp']) if hasattr(fact, '__getitem__') else ''
        }
    except:
        fact_str = str(fact)
        return {
            'step_id': 0,
            'rule_name': 'UNKNOWN',
            'trigger_condition': fact_str,
            'conclusion': '',
            'node_id': 'N/A',
            'timestamp': ''
        }


def parse_reason_fact(fact):
    """Parse a reason fact into dictionary (原因解释)"""
    try:
        return {
            'attack_type': str(fact['attack-type']) if hasattr(fact, '__getitem__') else 'UNKNOWN',
            'node_id': str(fact['node-id']) if hasattr(fact, '__getitem__') else 'N/A',
            'explanation': str(fact['explanation']) if hasattr(fact, '__getitem__') else '',
            'evidence': str(fact['evidence']) if hasattr(fact, '__getitem__') else ''
        }
    except:
        fact_str = str(fact)
        return {
            'attack_type': 'UNKNOWN',
            'node_id': 'N/A',
            'explanation': fact_str,
            'evidence': ''
        }


def parse_alert_fact(fact):
    """Parse a system-alert fact into dictionary"""
    try:
        return {
            'alert_id': fact['alert-id'] if hasattr(fact, '__getitem__') else 0,
            'level': str(fact['alert-level']) if hasattr(fact, '__getitem__') else 'UNKNOWN',
            'message': str(fact['message']) if hasattr(fact, '__getitem__') else str(fact),
            'timestamp': str(fact['timestamp']) if hasattr(fact, '__getitem__') else datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    except:
        # Fallback parsing from string representation
        fact_str = str(fact)
        return {
            'alert_id': 0,
            'level': 'INFO',
            'message': fact_str,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }


def parse_defense_fact(fact):
    """Parse a defense-action fact into dictionary"""
    try:
        return {
            'action_id': fact['action-id'] if hasattr(fact, '__getitem__') else 0,
            'action_type': str(fact['action-type']) if hasattr(fact, '__getitem__') else 'UNKNOWN',
            'target': str(fact['target-node']) if hasattr(fact, '__getitem__') else 'N/A',
            'target_node': str(fact['target-node']) if hasattr(fact, '__getitem__') else 'N/A',
            'priority': str(fact['priority']) if hasattr(fact, '__getitem__') else 'MEDIUM',
            'description': str(fact['description']) if hasattr(fact, '__getitem__') else str(fact),
            'status': 'pending',
            'timestamp': datetime.now().strftime("%H:%M:%S")
        }
    except:
        fact_str = str(fact)
        return {
            'action_id': 0,
            'action_type': 'GENERIC',
            'target': 'N/A',
            'target_node': 'N/A',
            'priority': 'MEDIUM',
            'description': fact_str,
            'status': 'pending',
            'timestamp': datetime.now().strftime("%H:%M:%S")
        }


def simulate_network_packets(count=5):
    """Simulate network packets for the fact base"""
    import random
    
    protocols = ['TCP', 'UDP', 'MQTT', 'CoAP', 'HTTP']
    ips = ['192.168.1.10', '192.168.1.11', '192.168.1.20', '192.168.1.30', '192.168.1.1']
    
    packets = []
    for i in range(count):
        packet = {
            'packet_id': i + 1,
            'source_ip': random.choice(ips),
            'dest_ip': random.choice(ips),
            'protocol': random.choice(protocols),
            'port': random.choice([80, 443, 1883, 5683, 8080]),
            'payload_size': random.randint(64, 1500),
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'packet_type': random.choice(['DATA', 'CONTROL', 'HEARTBEAT'])
        }
        packets.append(packet)
    
    fact_base['packets'] = packets
    return packets


# ===========================================
# Flask Routes
# ===========================================

@app.route('/')
def dashboard():
    """Dashboard - Main monitoring view"""
    return render_template('dashboard.html')


@app.route('/hacker')
def hacker():
    """Hacker Simulator - Attack injection interface"""
    return render_template('hacker.html')


@app.route('/defense')
def defense():
    """Defense View - Inference and recommendations display"""
    return render_template('defense.html')


@app.route('/report')
def report():
    """Report View - Diagnostic reports"""
    return render_template('report.html')


@app.route('/topology')
def topology():
    """Network Topology Visualization"""
    return render_template('topology.html')


# ===========================================
# API Endpoints
# ===========================================

@app.route('/api/status', methods=['GET'])
def api_status():
    """Get system status"""
    return jsonify({
        'status': 'online',
        'facts_count': len(list(clips_env.facts())),
        'attacks_detected': len(fact_base['attacks']),
        'alerts_count': len(fact_base['alerts']),
        'defenses_count': len(fact_base['defenses'])
    })


@app.route('/api/defense_data', methods=['GET'])
def api_defense_data():
    """Get all defense data (alerts, defenses, inference paths, reasons)"""
    return jsonify({
        'alerts': fact_base.get('alerts', []),
        'defenses': fact_base.get('defenses', []),
        'inference_paths': fact_base.get('inference_paths', []),
        'reasons': fact_base.get('reasons', []),
        'attacks': fact_base.get('attacks', [])
    })


@app.route('/api/clear_defense_data', methods=['POST'])
def api_clear_defense_data():
    """Clear all defense data from fact_base"""
    global fact_base
    fact_base['alerts'] = []
    fact_base['defenses'] = []
    fact_base['inference_paths'] = []
    fact_base['reasons'] = []
    fact_base['attacks'] = []
    fact_base['inference_log'] = []
    # Also reset CLIPS environment
    reset_clips_environment()
    load_clips_rules()
    # Notify all clients
    socketio.emit('data_cleared', {'message': 'All data cleared'}, namespace='/')
    return jsonify({'success': True, 'message': 'Defense data cleared'})


@app.route('/api/topology', methods=['GET', 'POST'])
def api_topology():
    """Get or update network topology - syncs across all pages"""
    global current_topology
    if request.method == 'POST':
        data = request.get_json()
        # Store topology on server for synchronization
        if data and 'nodes' in data and 'edges' in data:
            current_topology = {
                'nodes': data['nodes'],
                'edges': data['edges']
            }
            log_inference(f"Topology updated: {len(data['nodes'])} nodes, {len(data['edges'])} edges")
        # Broadcast topology update to all clients
        socketio.emit('topology_updated', current_topology, namespace='/')
        return jsonify({'success': True, 'message': 'Topology updated and synced'})
    # GET: Return current server-stored topology
    return jsonify({'success': True, 'topology': current_topology})


@app.route('/api/load_rules', methods=['POST'])
def api_load_rules():
    """Load CLIPS rules"""
    success, message = load_clips_rules()
    return jsonify({'success': success, 'message': message})


@app.route('/api/reset', methods=['POST'])
def api_reset():
    """Reset the expert system"""
    success = reset_clips_environment()
    load_clips_rules()
    return jsonify({'success': success, 'message': 'System reset complete'})


@app.route('/inject_attack', methods=['POST'])
def inject_attack():
    """
    API endpoint to inject an attack
    Receives attack type from frontend, converts to CLIPS facts, runs inference
    """
    global clips_env
    data = request.get_json()
    attack_type = data.get('attack_type', 'Sinkhole')
    source = data.get('source', 'malicious-node-001')
    target = data.get('target', 'gateway-001')
    
    # CRITICAL FIX: Clear CLIPS completely and reload rules before each attack
    # This ensures rules can fire again for new attacks
    try:
        clips_env.clear()
        rules_path = os.path.join(os.path.dirname(__file__), 'rules/rpl_rules.clp')
        clips_env.load(rules_path)
        clips_env.reset()
        log_inference(f"CLIPS environment cleared and reset for new attack: {attack_type}")
    except Exception as e:
        log_inference(f"Warning: Could not reset CLIPS: {e}")
    
    # Get optional parameters for RPL attacks
    kwargs = {}
    if attack_type == 'Sinkhole':
        kwargs['prev_rank'] = data.get('prev_rank', 150)
        kwargs['curr_rank'] = data.get('curr_rank', 1)
    elif attack_type == 'HelloFlood':
        kwargs['dio_count'] = data.get('dio_count', 50)
    elif attack_type == 'DIS-Flooding':
        kwargs['dis_count'] = data.get('dis_count', 30)
    elif attack_type == 'VersionNumber':
        kwargs['prev_version'] = data.get('prev_version', 5)
        kwargs['curr_version'] = data.get('curr_version', 15)
    elif attack_type == 'DIO-Suppression':
        kwargs['dio_level'] = data.get('dio_level', 'High')
        kwargs['dti_level'] = data.get('dti_level', 'Low')
        kwargs['stia_level'] = data.get('stia_level', 'Low')
    elif attack_type == 'Jamming':
        kwargs['etx_level'] = data.get('etx_level', 'High')
        kwargs['retrans_level'] = data.get('retrans_level', 'High')
    elif attack_type == 'SelectiveForwarding':
        kwargs['drop_rate'] = data.get('drop_rate', 0.35)
        kwargs['threshold'] = data.get('threshold', 0.2)
    elif attack_type == 'DoS':
        kwargs['dpr'] = data.get('dpr', 0.8)
        kwargs['pfr'] = data.get('pfr', 0.9)
    elif attack_type == 'RankAttack':
        kwargs['prev_rank'] = data.get('prev_rank', 200)
        kwargs['curr_rank'] = data.get('curr_rank', 50)
    elif attack_type == 'XAI-Anomaly':
        kwargs['npc'] = data.get('npc', 1.0)
        kwargs['nc'] = data.get('nc', 2.0)
        kwargs['udp_recv'] = data.get('udp_recv', 15.0)
        kwargs['udp_trans'] = data.get('udp_trans', 2.0)
        kwargs['udp_fwd'] = data.get('udp_fwd', 0.3)
        kwargs['pf_rate'] = data.get('pf_rate', 0.4)
    elif attack_type == 'Sinkhole-UVM':
        kwargs['abnormal_count'] = data.get('abnormal_count', 4)
        kwargs['total_rules'] = data.get('total_rules', 5)
    elif attack_type == 'RankDecrease':
        kwargs['recv_rank'] = data.get('recv_rank', 50)
        kwargs['avg_rank'] = data.get('avg_rank', 200)
        kwargs['max_rank'] = data.get('max_rank', 300)
        kwargs['k_factor'] = data.get('k_factor', 0.3)
    elif attack_type == 'SRPL-Malicious':
        kwargs['ncr'] = data.get('ncr', 100)
        kwargs['npr'] = data.get('npr', 150)
    elif attack_type == 'SRPL-RankDecrease':
        kwargs['ncr'] = data.get('ncr', 80)
        kwargs['nor'] = data.get('nor', 150)
        kwargs['msr'] = data.get('msr', 120)
        kwargs['pst'] = data.get('pst', 20)
    elif attack_type == 'SRPL-RankIncrease':
        kwargs['ncr'] = data.get('ncr', 200)
        kwargs['nor'] = data.get('nor', 150)
        kwargs['mcr'] = data.get('mcr', 180)
    elif attack_type == 'Sinkhole-Bidirectional':
        kwargs['parent_id'] = data.get('parent_id', 'parent-001')
        kwargs['count'] = data.get('count', 6)
    elif attack_type == 'Sinkhole-PRBA':
        # Comprehensive Sinkhole detection parameters
        kwargs['parent_id'] = data.get('parent_id', 'parent-001')
        kwargs['bid_count'] = data.get('bid_count', 6)
        kwargs['power_value'] = data.get('power_value', 85.0)
        kwargs['power_threshold'] = data.get('power_threshold', 50.0)
        kwargs['dio_current'] = data.get('dio_current', 15)
        kwargs['dio_previous'] = data.get('dio_previous', 5)
        kwargs['parent_rank'] = data.get('parent_rank', 100)
        kwargs['node_rank'] = data.get('node_rank', 150)
        kwargs['sink_rank'] = data.get('sink_rank', 10)
    elif attack_type == 'Sybil':
        kwargs['ics'] = data.get('ics', 0.9)
        kwargs['scs'] = data.get('scs', 0.8)
        kwargs['res'] = data.get('res', 0.7)
        kwargs['rms'] = data.get('rms', 0.85)
        kwargs['bis'] = data.get('bis', 0.75)
        kwargs['tds'] = data.get('tds', 0.6)
    elif attack_type == 'Dist-IDS-Violation':
        kwargs['violation_count'] = data.get('violation_count', 6)
        kwargs['threshold'] = data.get('threshold', 5)
    
    # Validate attack parameters and generate warnings if attack won't be effective
    warnings = []
    if attack_type == 'Sinkhole':
        prev_rank = kwargs.get('prev_rank', 150)
        curr_rank = kwargs.get('curr_rank', 1)
        # Rule requires: curr_rank < prev_rank / 2
        if curr_rank >= prev_rank / 2:
            warnings.append(f"⚠️ Ineffective Attack: Forged Rank ({curr_rank}) must be less than half of Original Rank ({prev_rank}/2 = {prev_rank//2}) to trigger detection rules.")
            warnings.append(f"💡 Suggestion: Set Forged Rank to a value less than {prev_rank//2} (e.g., 1 or {max(1, prev_rank//4)}).")
    elif attack_type == 'HelloFlood':
        dio_count = kwargs.get('dio_count', 50)
        dio_threshold = 20
        if dio_count <= dio_threshold:
            warnings.append(f"⚠️ Ineffective Attack: DIO count ({dio_count}) must exceed threshold ({dio_threshold}) to trigger detection.")
    elif attack_type == 'DIS-Flooding':
        dis_count = kwargs.get('dis_count', 30)
        dis_threshold = 15
        if dis_count <= dis_threshold:
            warnings.append(f"⚠️ Ineffective Attack: DIS count ({dis_count}) must exceed threshold ({dis_threshold}) to trigger detection.")
    elif attack_type == 'VersionNumber':
        prev_version = kwargs.get('prev_version', 5)
        curr_version = kwargs.get('curr_version', 15)
        if curr_version <= prev_version:
            warnings.append(f"⚠️ Ineffective Attack: Forged Version ({curr_version}) must be greater than Original Version ({prev_version}).")
    elif attack_type == 'SelectiveForwarding':
        drop_rate = kwargs.get('drop_rate', 0.35)
        threshold = kwargs.get('threshold', 0.2)
        if drop_rate <= threshold:
            warnings.append(f"⚠️ Ineffective Attack: PDRR ({drop_rate}) must be greater than threshold ({threshold}) to trigger detection.")
    elif attack_type == 'DoS':
        dpr = kwargs.get('dpr', 0.8)
        pfr = kwargs.get('pfr', 0.9)
        if dpr <= 0.5 or pfr <= 0.6:
            warnings.append(f"⚠️ Ineffective Attack: Both DPR ({dpr}) > 0.5 AND PFR ({pfr}) > 0.6 required to trigger detection.")
    elif attack_type == 'RankAttack':
        prev_rank = kwargs.get('prev_rank', 200)
        curr_rank = kwargs.get('curr_rank', 50)
        if curr_rank >= prev_rank / 2:
            warnings.append(f"⚠️ Ineffective Attack: Current Rank ({curr_rank}) must be less than half of Previous Rank ({prev_rank}/2 = {prev_rank//2}).")
    # DIO-Suppression: All 27 combinations are now valid - handled by threat score calculation
    # No ineffective attack check needed - the system classifies all combinations
    
    # Inject the attack fact
    success, result = inject_attack_fact(attack_type, source, target, **kwargs)
    
    if success:
        # Record the alert count BEFORE running inference
        alerts_before = len(fact_base.get('alerts', []))
        
        # Run inference engine
        inf_success, rules_fired = run_inference()
        
        # Get only the NEW alerts from this attack (not historical ones)
        all_alerts = fact_base.get('alerts', [])
        new_alerts = all_alerts[alerts_before:] if alerts_before < len(all_alerts) else []
        
        # Determine actual severity from NEW alerts only (not historical)
        # If no rules fired or normal behavior detected, severity should be LOW
        actual_severity = 'LOW'  # Default to LOW
        if rules_fired > 0 and new_alerts:
            # Get the highest severity from NEW alerts only
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
            max_severity = 'LOW'
            for alert in new_alerts:
                alert_sev = alert.get('level', 'MEDIUM')
                if severity_order.get(alert_sev, 0) > severity_order.get(max_severity, 0):
                    max_severity = alert_sev
            actual_severity = max_severity
        elif rules_fired == 0:
            actual_severity = 'LOW'
        
        # Update the result with actual severity
        result['actual_severity'] = actual_severity
        
        # Get only new defenses, paths, reasons
        defenses_before = alerts_before  # Approximate
        new_defenses = fact_base.get('defenses', [])[defenses_before:] if defenses_before < len(fact_base.get('defenses', [])) else fact_base.get('defenses', [])[-rules_fired:] if rules_fired > 0 else []
        
        response = {
            'success': True,
            'attack': result,
            'actual_severity': actual_severity,
            'rules_fired': rules_fired,
            'alerts': new_alerts if new_alerts else fact_base.get('alerts', [])[-rules_fired:] if rules_fired > 0 else [],
            'defenses': new_defenses if new_defenses else fact_base.get('defenses', [])[-rules_fired:] if rules_fired > 0 else [],
            'inference_paths': fact_base.get('inference_paths', [])[-rules_fired:] if rules_fired > 0 else [],
            'reasons': fact_base.get('reasons', [])[-rules_fired:] if rules_fired > 0 else []
        }
        
        # Add warnings if attack parameters won't trigger rules
        if warnings:
            response['warnings'] = warnings
            response['attack_effective'] = False
        else:
            response['attack_effective'] = rules_fired > 0
        
        # Emit report_update event with complete data for Report page sync
        report_data = {
            'attack': result,
            'source': source,
            'target': target,
            'rules_fired': rules_fired,
            'alerts': response['alerts'],
            'defenses': response['defenses'],
            'inference_paths': response['inference_paths'],
            'reasons': response['reasons'],
            'actual_severity': actual_severity,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        socketio.emit('report_update', report_data, namespace='/')
        log_inference(f"Emitted report_update event with attack: {result.get('type')}")
        
        return jsonify(response)
    else:
        return jsonify({
            'success': False,
            'error': result
        }), 400


@app.route('/api/facts', methods=['GET'])
def api_get_facts():
    """Get all current facts"""
    facts = []
    try:
        for fact in clips_env.facts():
            facts.append(str(fact))
    except Exception as e:
        pass
    
    return jsonify({
        'clips_facts': facts,
        'fact_base': fact_base
    })


@app.route('/api/inference_log', methods=['GET'])
def api_inference_log():
    """Get inference log"""
    return jsonify({
        'log': fact_base['inference_log']
    })


@app.route('/api/simulate_packets', methods=['POST'])
def api_simulate_packets():
    """Simulate network packets"""
    count = request.get_json().get('count', 5) if request.get_json() else 5
    packets = simulate_network_packets(count)
    return jsonify({
        'success': True,
        'packets': packets
    })


@app.route('/api/attack_history', methods=['GET'])
def api_attack_history():
    """Get attack history for reports"""
    return jsonify({
        'history': attack_history,
        'total_attacks': len(attack_history),
        'alerts': fact_base['alerts'],
        'defenses': fact_base['defenses']
    })


@app.route('/api/generate_report', methods=['GET'])
def api_generate_report():
    """Generate diagnostic report"""
    report = {
        'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'summary': {
            'total_attacks': len(attack_history),
            'total_alerts': len(fact_base['alerts']),
            'total_defenses': len(fact_base['defenses']),
            'critical_alerts': len([a for a in fact_base['alerts'] if a.get('level') == 'CRITICAL']),
            'high_priority_defenses': len([d for d in fact_base['defenses'] if d.get('priority') == 'HIGH' or d.get('priority') == 'CRITICAL'])
        },
        'attack_breakdown': {},
        'attacks': attack_history,
        'alerts': fact_base['alerts'],
        'defenses': fact_base['defenses'],
        'inference_paths': fact_base.get('inference_paths', []),
        'reasons': fact_base.get('reasons', []),
        'inference_log': fact_base['inference_log'][-20:]  # Last 20 entries
    }
    
    # Count attacks by type
    for attack in attack_history:
        attack_type = attack.get('type', 'Unknown')
        report['attack_breakdown'][attack_type] = report['attack_breakdown'].get(attack_type, 0) + 1
    
    return jsonify(report)


# ===========================================
# WebSocket Events
# ===========================================

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'status': 'Connected to IoT-Guardian'})
    log_inference("New client connected")


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    log_inference("Client disconnected")


@socketio.on('request_status')
def handle_status_request():
    """Handle status request via WebSocket"""
    emit('status_update', {
        'attacks': len(fact_base['attacks']),
        'alerts': len(fact_base['alerts']),
        'defenses': len(fact_base['defenses'])
    })


# ===========================================
# Application Initialization
# ===========================================

def initialize_app():
    """Initialize the application on startup"""
    print("=" * 50)
    print("  IoT-Guardian Expert System")
    print("  Initializing...")
    print("=" * 50)
    
    # Load CLIPS rules
    success, message = load_clips_rules()
    print(f"  Rules: {message}")
    
    # Initialize fact base with simulated data
    simulate_network_packets(10)
    print("  Network packets simulated")
    
    print("=" * 50)
    print("  System Ready!")
    print("=" * 50)


if __name__ == '__main__':
    initialize_app()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
