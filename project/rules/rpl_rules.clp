;;;======================================================
;;; RPL Protocol Attack Detection Expert System
;;; Based on Literature Review Rules
;;; 
;;; References:
;;; [2] FLSec-RPL: Fuzzy Logic for DIO Neighbor Suppression
;;; [4][5] Jamming Attack Detection
;;; [7][8][9] PRBA - Passive Rule-Based Approach
;;; [10] Random Forest Multi-Attack Detection
;;; [11][13] XAI Anomaly Detection (Isolation Forest)
;;; [14][16][17] UVM - Unweighted Voting Method
;;; [18]-[21] Hybrid IDS
;;; [22][24] SRPL-RP Rank & Version Attack Defense
;;; [26] Distributed IDS
;;; [28] FLBT-RPL Sybil Detection
;;;======================================================

;;; ===========================================
;;; FACT TEMPLATES - Fact Template Definitions
;;; ===========================================

;;; RPL Packet Template
(deftemplate rpl-packet
   "RPL Protocol Data Packet"
   (slot node-id (type STRING))
   (slot rank (type INTEGER))
   (slot packet-type (type STRING)))

;;; Node Rank History Record
(deftemplate node-rank-history
   "Records historical Rank values of a node"
   (slot node-id (type STRING))
   (slot previous-rank (type INTEGER))
   (slot current-rank (type INTEGER))
   (slot timestamp (type INTEGER)))

;;; DIO Message Counter (for FLSec-RPL)
(deftemplate dio-counter
   "Counts DIO messages from a node"
   (slot node-id (type STRING))
   (slot count (type INTEGER))
   (slot level (type SYMBOL) (allowed-symbols Low Medium High)))

;;; DTI - DIO Transaction Interval (for FLSec-RPL)
(deftemplate dti-record
   "DIO Transaction Interval"
   (slot node-id (type STRING))
   (slot interval (type FLOAT))
   (slot level (type SYMBOL) (allowed-symbols Low Medium High)))

;;; STIA - Same Trickle Interval Aggregation (for FLSec-RPL)
(deftemplate stia-record
   "Same Trickle Interval Aggregation"
   (slot node-id (type STRING))
   (slot value (type FLOAT))
   (slot level (type SYMBOL) (allowed-symbols Low Medium High)))

;;; ETX Record (for Jamming Detection)
(deftemplate etx-record
   "Expected Transmission Count"
   (slot node-id (type STRING))
   (slot value (type FLOAT))
   (slot level (type SYMBOL) (allowed-symbols Low Medium High)))

;;; Retransmission Record (for Jamming Detection)
(deftemplate retransmission-record
   "Retransmission Count Record"
   (slot node-id (type STRING))
   (slot count (type INTEGER))
   (slot level (type SYMBOL) (allowed-symbols Low Medium High)))

;;; Bidirectional Behavior Record (for PRBA Sinkhole Detection)
(deftemplate bidirectional-behavior
   "Bidirectional Behavior Record"
   (slot child-id (type STRING))
   (slot parent-id (type STRING))
   (slot count (type INTEGER))
   (slot timestamp (type INTEGER)))

;;; Power Consumption Record (for PRBA)
(deftemplate power-consumption
   "Node Power Consumption Record"
   (slot node-id (type STRING))
   (slot value (type FLOAT))
   (slot threshold (type FLOAT)))

;;; Packet Drop Rate Record (for RF Multi-Attack Detection)
(deftemplate pdrr-record
   "Packet Drop Rate Record"
   (slot node-id (type STRING))
   (slot rate (type FLOAT))
   (slot threshold (type FLOAT)))

;;; Duplicate Packet Rate Record (for DoS Detection)
(deftemplate dpr-record
   "Duplicate Packet Rate"
   (slot node-id (type STRING))
   (slot rate (type FLOAT))
   (slot threshold (type FLOAT)))

;;; Packet Forwarding Rate Record (for DoS Detection)
(deftemplate pfr-record
   "Packet Forwarding Rate"
   (slot node-id (type STRING))
   (slot rate (type FLOAT))
   (slot threshold (type FLOAT)))

;;; Number of Parent Changes (for XAI Anomaly Detection)
(deftemplate npc-record
   "Number of Parent Changes"
   (slot node-id (type STRING))
   (slot count (type FLOAT))
   (slot timestamp (type INTEGER)))

;;; Number of Children (for XAI Anomaly Detection)
(deftemplate nc-record
   "Number of Children"
   (slot node-id (type STRING))
   (slot count (type FLOAT)))

;;; UDP Received Record (for XAI Anomaly Detection)
(deftemplate udp-received
   "UDP Packets Received"
   (slot node-id (type STRING))
   (slot count (type FLOAT)))

;;; UDP Transmitted Record (for XAI Anomaly Detection)
(deftemplate udp-transmitted
   "UDP Packets Transmitted"
   (slot node-id (type STRING))
   (slot count (type FLOAT)))

;;; Packet Forwarding Statistics (for XAI)
(deftemplate packet-forwarding
   "Packet Forwarding Statistics"
   (slot node-id (type STRING))
   (slot rate (type FLOAT)))

;;; DIO Message Statistics (for UVM)
(deftemplate dio-message-stats
   "DIO Message Statistics for UVM"
   (slot node-id (type STRING))
   (slot current-count (type INTEGER))
   (slot previous-count (type INTEGER)))

;;; Rank Harmony Record (for UVM)
(deftemplate rank-harmony
   "Rank Harmony for UVM"
   (slot node-id (type STRING))
   (slot parent-rank (type INTEGER))
   (slot node-rank (type INTEGER))
   (slot sink-rank (type INTEGER)))

;;; Voting Result (for UVM)
(deftemplate voting-result
   "Voting Result for UVM"
   (slot node-id (type STRING))
   (slot abnormal-count (type INTEGER))
   (slot total-rules (type INTEGER)))

;;; Control Message Counter (for Hybrid IDS)
(deftemplate control-message-counter
   "Control Message Counter for Hybrid IDS"
   (slot node-id (type STRING))
   (slot dio-count (type INTEGER))
   (slot dis-count (type INTEGER))
   (slot dao-count (type INTEGER))
   (slot dio-threshold (type INTEGER))
   (slot dis-threshold (type INTEGER))
   (slot dao-threshold (type INTEGER)))

;;; Version Record (for Hybrid IDS)
(deftemplate version-record
   "DODAG Version Number Record"
   (slot node-id (type STRING))
   (slot previous-version (type INTEGER))
   (slot current-version (type INTEGER))
   (slot timestamp (type INTEGER)))

;;; Neighbor Rank Statistics (for Hybrid IDS)
(deftemplate neighbor-rank-stats
   "Neighbor Rank Statistics"
   (slot node-id (type STRING))
   (slot received-rank (type INTEGER))
   (slot avg-neighbor-rank (type INTEGER))
   (slot max-neighbor-rank (type INTEGER))
   (slot k-factor (type FLOAT)))

;;; SRPL-RP Rank Check Record
(deftemplate srpl-rank-check
   "SRPL-RP Rank Check Record"
   (slot node-id (type STRING))
   (slot ncr (type INTEGER))          ; Node Current Rank
   (slot npr (type INTEGER))          ; Node Parent Rank
   (slot nor (type INTEGER))          ; Node Old Rank
   (slot msr (type INTEGER))          ; Min Sibling Rank
   (slot mcr (type INTEGER))          ; Min Child Rank
   (slot pst (type INTEGER)))         ; Parent Switch Threshold

;;; Violation Counter (for Distributed IDS)
(deftemplate violation-counter
   "Violation Counter for Distributed IDS"
   (slot node-id (type STRING))
   (slot count (type INTEGER))
   (slot threshold (type INTEGER))
   (slot time-window (type INTEGER)))

;;; Sybil Detection Indicators (for FLBT-RPL)
(deftemplate sybil-indicators
   "Sybil Attack Detection Indicators"
   (slot node-id (type STRING))
   (slot ics (type FLOAT))    ; Identity Consistency Score
   (slot scs (type FLOAT))    ; Signal Consistency Score
   (slot res (type FLOAT))    ; Resource Score
   (slot rms (type FLOAT))    ; Rank Manipulation Score
   (slot bis (type FLOAT))    ; Behavior Inconsistency Score
   (slot tds (type FLOAT))    ; Time-based Detection Score
   (slot ics-threshold (type FLOAT))
   (slot scs-threshold (type FLOAT))
   (slot res-threshold (type FLOAT))
   (slot rms-threshold (type FLOAT))
   (slot bis-threshold (type FLOAT))
   (slot tds-threshold (type FLOAT)))

;;; Attack Alert Template
(deftemplate attack-alert
   "Security Attack Alert"
   (slot alert-id (type INTEGER))
   (slot attack-type (type STRING))
   (slot node-id (type STRING))
   (slot severity (type STRING))
   (slot message (type STRING))
   (slot timestamp (type INTEGER)))

;;; Inference Path Template
(deftemplate inference-path
   "Inference Path Record"
   (slot step-id (type INTEGER))
   (slot rule-name (type STRING))
   (slot trigger-condition (type STRING))
   (slot conclusion (type STRING))
   (slot node-id (type STRING))
   (slot timestamp (type INTEGER)))

;;; Reason Explanation Template
(deftemplate reason
   "Attack Reason Explanation"
   (slot attack-type (type STRING))
   (slot node-id (type STRING))
   (slot explanation (type STRING))
   (slot evidence (type STRING)))

;;; Defense Action Template
(deftemplate defense-action
   "Defense Measure Recommendation"
   (slot action-id (type INTEGER))
   (slot action-type (type STRING))
   (slot target-node (type STRING))
   (slot priority (type STRING))
   (slot description (type STRING)))

;;; Global Counter
(deftemplate global-counter
   "Global Counter for Unique ID Generation"
   (slot counter-name (type STRING))
   (slot value (type INTEGER)))

;;; ===========================================
;;; INITIAL FACTS - Initial Facts
;;; ===========================================

(deffacts initial-facts
   "Initialize System State"
   (global-counter (counter-name "alert-id") (value 0))
   (global-counter (counter-name "step-id") (value 0))
   (global-counter (counter-name "action-id") (value 0)))


;;;============================================
;;; SECTION 1: FLSec-RPL RULES (Reference [2])
;;; DIO Neighbor Suppression Attack Detection - Fuzzy Logic Rules
;;;============================================

;;; R_FLSec_1: High DIO + Low DTI + Low STIA = Malicious
(defrule R-FLSec-1-Malicious
   "FLSec-RPL: Detect Malicious Node - DIO High, DTI Low, STIA Low"
   (declare (salience 100))
   
   (dio-counter (node-id ?nid) (level High))
   (dti-record (node-id ?nid) (level Low))
   (stia-record (node-id ?nid) (level Low))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "DIO-Suppression-Malicious") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "DIO-Suppression-Malicious")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "DIO Suppression: Node " ?nid " identified as MALICIOUS - High DIO frequency, Low transaction interval, Low Trickle aggregation"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "DIO-Suppression-Malicious-Detection")
      (trigger-condition (str-cat "DIO_Counter=High AND DTI=Low AND STIA=Low"))
      (conclusion "Aggressive_Weight = Malicious (Malicious Node)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "DIO-Suppression-Malicious")
      (node-id ?nid)
      (explanation "DIO Suppression Detection: Node sends excessive DIO messages with very short intervals, attempting to suppress neighbor nodes")
      (evidence "DIO_Counter=High, DTI=Low, STIA=Low")))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "BLOCK_PERMANENT")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Permanently isolate malicious node " ?nid ", remove from neighbor table"))))
   
   (printout t ">>> [DIO-Suppression] MALICIOUS Node Detected: " ?nid crlf))


;;; R_FLSec_2: High DIO + Low DTI + Medium STIA = Quarantine
(defrule R-FLSec-2-Quarantine
   "FLSec-RPL: Detect Suspicious Node for Quarantine - DIO High, DTI Low, STIA Medium"
   (declare (salience 100))
   
   (dio-counter (node-id ?nid) (level High))
   (dti-record (node-id ?nid) (level Low))
   (stia-record (node-id ?nid) (level Medium))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "DIO-Suppression-Quarantine") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "DIO-Suppression-Quarantine")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "DIO Suppression: Node " ?nid " requires QUARANTINE - High DIO frequency, Low transaction interval, Medium Trickle aggregation"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "DIO-Suppression-Quarantine-Detection")
      (trigger-condition (str-cat "DIO_Counter=High AND DTI=Low AND STIA=Medium"))
      (conclusion "Aggressive_Weight = Quarantine (Requires Isolation for Observation)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "DIO-Suppression-Quarantine")
      (node-id ?nid)
      (explanation "DIO Suppression Detection: Node behavior is suspicious, requires isolation for further observation")
      (evidence "DIO_Counter=High, DTI=Low, STIA=Medium")))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "QUARANTINE")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Temporarily isolate suspicious node " ?nid ", monitor subsequent behavior"))))
   
   (printout t ">>> [DIO-Suppression] QUARANTINE Required for Node: " ?nid crlf))


;;; R_FLSec_3: Medium DIO + Medium DTI + Medium STIA = Normal
(defrule R-FLSec-3-Normal
   "FLSec-RPL: Identify Normal Node - DIO Medium, DTI Medium, STIA Medium"
   (declare (salience 90))
   
   (dio-counter (node-id ?nid) (level Medium))
   (dti-record (node-id ?nid) (level Medium))
   (stia-record (node-id ?nid) (level Medium))
   
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (inference-path (rule-name "DIO-Behavior-Normal-Check") (node-id ?nid)))
   
   =>
   
   (retract ?step-counter)
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "DIO-Behavior-Normal-Check")
      (trigger-condition (str-cat "DIO_Counter=Medium AND DTI=Medium AND STIA=Medium"))
      (conclusion "Aggressive_Weight = Normal (Normal Node)")
      (node-id ?nid)
      (timestamp 0)))
   
   (printout t ">>> [DIO-Suppression] NORMAL Node Identified: " ?nid crlf))


;;; R_FLSec_4: Low DIO + Low DTI + Low STIA = Quarantine (Possibly Suppressed Node)
(defrule R-FLSec-4-Quarantine-Suppressed
   "FLSec-RPL: Detect Possibly Suppressed Node - DIO Low, DTI Low, STIA Low"
   (declare (salience 100))
   
   (dio-counter (node-id ?nid) (level Low))
   (dti-record (node-id ?nid) (level Low))
   (stia-record (node-id ?nid) (level Low))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (attack-alert (attack-type "DIO-Suppression-Victim") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "DIO-Suppression-Victim")
      (node-id ?nid)
      (severity "MEDIUM")
      (message (str-cat "DIO Suppression: Node " ?nid " may be a VICTIM of DIO suppression attack"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "DIO-Suppression-Victim-Detection")
      (trigger-condition (str-cat "DIO_Counter=Low AND DTI=Low AND STIA=Low"))
      (conclusion "Node may be suppressed by malicious node, investigation required")
      (node-id ?nid)
      (timestamp 0)))
   
   (printout t ">>> [DIO-Suppression] VICTIM (Possibly Suppressed): " ?nid crlf))


;;;============================================
;;; SECTION 2: JAMMING ATTACK DETECTION (Reference [4][5])
;;; Jamming Attack Detection Rules
;;;============================================

;;; R_Jam_1: Low ETX + Low Retransmissions = NO ATTACK
(defrule R-Jam-1-NoAttack
   "Jamming: ETX Low, Retransmissions Low = No Attack"
   (declare (salience 90))
   
   (etx-record (node-id ?nid) (level Low))
   (retransmission-record (node-id ?nid) (level Low))
   
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (inference-path (rule-name "Jamming-Normal-Check") (node-id ?nid)))
   
   =>
   
   (retract ?step-counter)
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Jamming-Normal-Check")
      (trigger-condition "ETX=Low AND Retransmissions=Low")
      (conclusion "Jamming Index = NO ATTACK (No Jamming Attack Detected)")
      (node-id ?nid)
      (timestamp 0)))
   
   (printout t ">>> [JAMMING] NO ATTACK for Node: " ?nid crlf))


;;; R_Jam_2: Low ETX + Medium Retransmissions = LOW Jamming
(defrule R-Jam-2-LowJamming
   "Jamming: ETX Low, Retransmissions Medium = Low Level Jamming"
   (declare (salience 95))
   
   (etx-record (node-id ?nid) (level Low))
   (retransmission-record (node-id ?nid) (level Medium))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (attack-alert (attack-type "Jamming-Low") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Jamming-Low")
      (node-id ?nid)
      (severity "LOW")
      (message (str-cat "Jamming: Node " ?nid " detected LOW level jamming attack"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Jamming-Low-Detection")
      (trigger-condition "ETX=Low AND Retransmissions=Medium")
      (conclusion "Jamming Index = LOW (Low Level Jamming)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Jamming-Low")
      (node-id ?nid)
      (explanation "Detected mild signal interference, abnormal retransmission count but normal ETX")
      (evidence "ETX=Low, Retransmissions=Medium")))
   
   (printout t ">>> [JAMMING] LOW Level Jamming: " ?nid crlf))


;;; R_Jam_3: High ETX + High Retransmissions = HIGH Jamming
(defrule R-Jam-3-HighJamming
   "Jamming: ETX High, Retransmissions High = High Level Jamming Attack"
   (declare (salience 100))
   
   (etx-record (node-id ?nid) (level High))
   (retransmission-record (node-id ?nid) (level High))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "Jamming-High") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Jamming-High")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "Jamming: Node " ?nid " detected HIGH level jamming attack!"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Jamming-High-Detection")
      (trigger-condition "ETX=High AND Retransmissions=High")
      (conclusion "Jamming Index = HIGH (Severe Jamming Attack)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Jamming-High")
      (node-id ?nid)
      (explanation "Detected severe signal jamming attack, both ETX and retransmission count are abnormally high")
      (evidence "ETX=High, Retransmissions=High")))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "CHANNEL_HOP")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Interference detected near node " ?nid ", recommend switching communication channel or enabling frequency hopping"))))
   
   (printout t ">>> [JAMMING] HIGH Level Jamming Attack: " ?nid crlf))


;;;============================================
;;; SECTION 3: PRBA SINKHOLE DETECTION (Reference [7][8][9])
;;; Passive Rule-Based Approach
;;;============================================

;;; R_PRBA_1: Bidirectional Behavior Detection
(defrule R-PRBA-1-Bidirectional
   "PRBA: Detect Bidirectional Behavior - Parent and Child nodes pointing to each other simultaneously"
   (declare (salience 100))
   
   (bidirectional-behavior 
      (child-id ?cid) 
      (parent-id ?pid) 
      (count ?cnt&:(> ?cnt 0))
      (timestamp ?ts))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (attack-alert (attack-type "Sinkhole-Bidirectional") (node-id ?cid)))
   
   =>
   
   (retract ?counter ?step-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Sinkhole-Bidirectional")
      (node-id ?cid)
      (severity "MEDIUM")
      (message (str-cat "Sinkhole Detection: Suspicious bidirectional behavior detected - Node " ?cid " and " ?pid " pointing to each other"))
      (timestamp ?ts)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Sinkhole-Bidirectional-Detection")
      (trigger-condition (str-cat "Child(" ?cid ") -> Parent(" ?pid ") AND Parent -> Child exist simultaneously"))
      (conclusion "Suspicious behaviour detected - Possible Sinkhole attack")
      (node-id ?cid)
      (timestamp ?ts)))
   
   (assert (reason
      (attack-type "Sinkhole-Bidirectional")
      (node-id ?cid)
      (explanation "Parent and child nodes pointing to each other at the same time is a typical characteristic of Sinkhole attack")
      (evidence (str-cat "Detected bidirectional pointing behavior between node " ?cid " and " ?pid))))
   
   (printout t ">>> [Sinkhole] Bidirectional Behavior Detected: " ?cid " <-> " ?pid crlf))


;;; R_PRBA_2: Frequent Bidirectional Behavior
(defrule R-PRBA-2-FrequentBidirectional
   "PRBA: Frequent Bidirectional Behavior Exceeds Threshold"
   (declare (salience 100))
   
   (bidirectional-behavior 
      (child-id ?cid) 
      (parent-id ?pid) 
      (count ?cnt&:(> ?cnt 5))  ; Threshold th = 5
      (timestamp ?ts))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "Sinkhole-FrequentBidirectional") (node-id ?cid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Sinkhole-FrequentBidirectional")
      (node-id ?cid)
      (severity "HIGH")
      (message (str-cat "Sinkhole Detection: Node " ?cid " frequent bidirectional behavior count (" ?cnt ") exceeds threshold"))
      (timestamp ?ts)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Sinkhole-Frequent-Bidirectional")
      (trigger-condition (str-cat "Bidirectional_Count(" ?cnt ") > Threshold(5)"))
      (conclusion "Confirmed suspicious behavior - High probability of Sinkhole attack")
      (node-id ?cid)
      (timestamp ?ts)))
   
   (assert (reason
      (attack-type "Sinkhole-FrequentBidirectional")
      (node-id ?cid)
      (explanation "Frequent bidirectional behavior indicates the node may be conducting a Sinkhole attack")
      (evidence (str-cat "Bidirectional behavior count: " ?cnt " times, exceeds threshold 5"))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "ISOLATE_NODE")
      (target-node ?cid)
      (priority "HIGH")
      (description (str-cat "Isolate suspicious node " ?cid " and verify its routing information"))))
   
   (printout t ">>> [Sinkhole] Frequent Bidirectional Behavior Alert: " ?cid crlf))


;;; R_PRBA_3: Power Consumption Anomaly
(defrule R-PRBA-3-PowerConsumption
   "PRBA: Power Consumption Anomaly Detection"
   (declare (salience 100))
   
   (power-consumption 
      (node-id ?nid) 
      (value ?pwr) 
      (threshold ?th&:(< ?th ?pwr)))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (attack-alert (attack-type "Sinkhole-PowerAnomaly") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Sinkhole-PowerAnomaly")
      (node-id ?nid)
      (severity "MEDIUM")
      (message (str-cat "Sinkhole Detection: Node " ?nid " power consumption anomaly exceeds threshold"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Sinkhole-Power-Anomaly")
      (trigger-condition (str-cat "PowerConsumption(" ?pwr ") > Threshold(" ?th ")"))
      (conclusion "Power anomaly - Node may be processing large amounts of malicious routing traffic")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Sinkhole-PowerAnomaly")
      (node-id ?nid)
      (explanation "Abnormally high node power consumption, possibly due to Sinkhole attack causing traffic convergence")
      (evidence (str-cat "Power: " ?pwr ", Threshold: " ?th))))
   
   (printout t ">>> [Sinkhole] Power Anomaly: " ?nid crlf))


;;;============================================
;;; SECTION 4: RF MULTI-ATTACK DETECTION (Reference [10])
;;; Random Forest-based Multi-Attack Detection
;;;============================================

;;; R_RF_1: Selective Forwarding Detection
(defrule R-RF-1-SelectiveForwarding
   "RF: Selective Forwarding Attack Detection - Packet Drop Rate Exceeds Threshold"
   (declare (salience 100))
   
   (pdrr-record 
      (node-id ?nid) 
      (rate ?rate) 
      (threshold ?th&:(< ?th ?rate)))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "SelectiveForwarding") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "SelectiveForwarding")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "Attack Detection: Selective Forwarding attack detected - Node " ?nid " packet drop rate anomaly"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "SelectiveForwarding-Detection")
      (trigger-condition (str-cat "PDRR(" ?rate ") > delta_PDRR(" ?th ")"))
      (conclusion "Send message (Selective Forwarding, NodeID) to Sink")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "SelectiveForwarding")
      (node-id ?nid)
      (explanation "Node selectively drops packets, causing abnormally high packet drop rate")
      (evidence (str-cat "Packet Drop Rate: " ?rate ", Threshold: " ?th))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "REROUTE")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Bypass node " ?nid " and re-plan routing path"))))
   
   (printout t ">>> [Attack-Detection] Selective Forwarding Attack: " ?nid crlf))


;;; R_RF_2: DoS Attack Detection
(defrule R-RF-2-DoS
   "RF: DoS Attack Detection - Both Duplicate Packet Rate and Forwarding Rate Exceed Thresholds"
   (declare (salience 100))
   
   (dpr-record 
      (node-id ?nid) 
      (rate ?dpr) 
      (threshold ?dpr-th&:(< ?dpr-th ?dpr)))
   (pfr-record 
      (node-id ?nid) 
      (rate ?pfr) 
      (threshold ?pfr-th&:(< ?pfr-th ?pfr)))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "DoS") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "DoS")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "Attack Detection: DoS attack detected - Node " ?nid " duplicate packet rate and forwarding rate anomaly"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "DoS-Attack-Detection")
      (trigger-condition (str-cat "DPR(" ?dpr ") > delta_DPR AND PFR(" ?pfr ") > delta_PFR"))
      (conclusion "Send message (DoS attack, NodeID) to Sink")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "DoS")
      (node-id ?nid)
      (explanation "Node sends large amounts of duplicate packets and attempts to forward, typical DoS attack behavior")
      (evidence (str-cat "DPR: " ?dpr ", PFR: " ?pfr))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "RATE_LIMIT")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Apply strict rate limiting to node " ?nid " and notify Sink"))))
   
   (printout t ">>> [Attack-Detection] DoS Attack: " ?nid crlf))


;;; R_RF_3: Rank Attack Detection
(defrule R-RF-3-RankAttack
   "RF: Rank Attack Detection - Rank Mismatch"
   (declare (salience 100))
   
   (node-rank-history 
      (node-id ?nid)
      (previous-rank ?prev)
      (current-rank ?curr)
      (timestamp ?ts))
   
   ;; Rank mismatch condition: decrease over 50%
   (test (and (> ?prev 0) (< ?curr (/ ?prev 2))))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "RankAttack") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "RankAttack")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "Attack Detection: Rank Attack detected - Node " ?nid " Rank changed from " ?prev " to " ?curr " abnormally"))
      (timestamp ?ts)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Rank-Attack-Detection")
      (trigger-condition (str-cat "Node-rank mismatch: " ?prev " -> " ?curr))
      (conclusion "Send message (Rank-attack, NodeID) to Sink")
      (node-id ?nid)
      (timestamp ?ts)))
   
   (assert (reason
      (attack-type "RankAttack")
      (node-id ?nid)
      (explanation "Node Rank value mismatch, possibly forging low Rank to attract traffic")
      (evidence (str-cat "Rank change: " ?prev " -> " ?curr " (decreased over 50%)"))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "VERIFY_RANK")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Verify the legitimacy of node " ?nid " Rank"))))
   
   (printout t ">>> [Attack-Detection] Rank Attack: " ?nid crlf))


;;;============================================
;;; SECTION 5: XAI ANOMALY DETECTION (Reference [11][13])
;;; Isolation Forest-based Anomaly Detection
;;;============================================

;;; R_XAI_1: Anomaly Detection Rule 1
(defrule R-XAI-1-Anomaly
   "XAI: Anomaly Detection Rule 1 - NPC, NC, UDP_received combination"
   (declare (salience 100))
   
   (npc-record (node-id ?nid) (count ?npc&:(and (<= ?npc 1.62) (> ?npc 0.08))))
   (nc-record (node-id ?nid) (count ?nc&:(> ?nc 1.74)))
   (udp-received (node-id ?nid) (count ?udp&:(> ?udp 11.62)))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "XAI-Anomaly") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "XAI-Anomaly")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "Anomaly Detection: Node " ?nid " detected anomalous behavior pattern"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Anomaly-Pattern-Detection")
      (trigger-condition (str-cat "NPC<=1.62 AND NPC>0.08 AND NC>" ?nc " AND UDP_recv>" ?udp))
      (conclusion "Anomaly Detected")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "XAI-Anomaly")
      (node-id ?nid)
      (explanation "Isolation Forest detected anomaly: Number of parent changes, child count, and UDP received combination is anomalous")
      (evidence (str-cat "NPC=" ?npc ", NC=" ?nc ", UDP_recv=" ?udp))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "MONITOR")
      (target-node ?nid)
      (priority "MEDIUM")
      (description (str-cat "Enhance monitoring of node " ?nid " behavior pattern"))))
   
   (printout t ">>> [Anomaly] Anomaly Detection: " ?nid crlf))


;;;============================================
;;; SECTION 6: UVM VOTING METHOD (Reference [14][16][17])
;;; Unweighted Voting Method
;;;============================================

;;; R_UVM_1: DIO Frequency Behavior
(defrule R-UVM-1-DIOFrequency
   "UVM: DIO Frequency Anomaly Detection"
   (declare (salience 100))
   
   (dio-message-stats 
      (node-id ?nid) 
      (current-count ?curr) 
      (previous-count ?prev&:(< ?prev ?curr)))
   
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (inference-path (rule-name "DIO-Frequency-Analysis") (node-id ?nid)))
   
   =>
   
   (retract ?step-counter)
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "DIO-Frequency-Analysis")
      (trigger-condition (str-cat "DIO_Current(" ?curr ") > DIO_Previous(" ?prev ")"))
      (conclusion "Suspicious behavior (DIO Transaction Frequency Behavior)")
      (node-id ?nid)
      (timestamp 0)))
   
   (printout t ">>> [Voting] DIO Frequency Anomaly: " ?nid crlf))


;;; R_UVM_2: Rank Harmony Behavior
(defrule R-UVM-2-RankHarmony
   "UVM: Rank Harmony Anomaly Detection"
   (declare (salience 100))
   
   (rank-harmony 
      (node-id ?nid) 
      (parent-rank ?pr) 
      (node-rank ?nr) 
      (sink-rank ?sr))
   
   ;; Condition: |Parent_Rank - Node_Rank| < |Sink_Rank - Node_Rank|
   (test (< (abs (- ?pr ?nr)) (abs (- ?sr ?nr))))
   
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (inference-path (rule-name "Rank-Harmony-Check") (node-id ?nid)))
   
   =>
   
   (retract ?step-counter)
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Rank-Harmony-Check")
      (trigger-condition (str-cat "NRP(" (abs (- ?pr ?nr)) ") > SRN(" (abs (- ?sr ?nr)) ") anomaly"))
      (conclusion "Suspicious behavior (Rank Harmony Behavior)")
      (node-id ?nid)
      (timestamp 0)))
   
   (printout t ">>> [Voting] Rank Harmony Anomaly: " ?nid crlf))


;;; R_UVM_3: Voting Decision
(defrule R-UVM-3-VotingDecision
   "UVM: Voting Decision - Over 65% rules triggered indicates Sinkhole attack"
   (declare (salience 90))
   
   (voting-result 
      (node-id ?nid) 
      (abnormal-count ?abn) 
      (total-rules ?total&:(> ?total 0)))
   
   ;; Condition: abnormal ratio > 65%
   (test (> (/ (* ?abn 100) ?total) 65))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "Sinkhole-UVM") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Sinkhole-UVM")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "Voting Detection: Node " ?nid " voting determined as Sinkhole attack"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Voting-Decision-Sinkhole")
      (trigger-condition (str-cat "Abnormal behaviors(" ?abn ")/Total rules(" ?total ") > 65%"))
      (conclusion "Determined as Sinkhole attack (Alert = True)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Sinkhole-UVM")
      (node-id ?nid)
      (explanation "UVM Voting Method: Over 65% of rules detected anomalous behavior")
      (evidence (str-cat "Abnormal rule count: " ?abn "/" ?total))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "ISOLATE_NODE")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Immediately isolate Sinkhole attack node " ?nid))))
   
   (printout t ">>> [Voting] Sinkhole Attack Confirmed: " ?nid crlf))


;;;============================================
;;; SECTION 7: HYBRID IDS (Reference [18]-[21])
;;; Hybrid Intrusion Detection System
;;;============================================

;;; R_Hybrid_1: Control Message Flooding
(defrule R-Hybrid-1-ControlMessageFlood
   "Hybrid IDS: Control Message Flooding Attack Detection"
   (declare (salience 100))
   
   (control-message-counter 
      (node-id ?nid) 
      (dio-count ?dio) 
      (dis-count ?dis) 
      (dao-count ?dao)
      (dio-threshold ?dio-th) 
      (dis-threshold ?dis-th) 
      (dao-threshold ?dao-th))
   
   ;; Any count exceeds threshold
   (test (or (> ?dio ?dio-th) (> ?dis ?dis-th) (> ?dao ?dao-th)))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "HelloFlood") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (bind ?attack-subtype 
      (if (> ?dio ?dio-th) then "Hello Flood (DIO)"
       else (if (> ?dis ?dis-th) then "DIS Attack"
       else "DAO Insider Attack")))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "HelloFlood")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "Intrusion Detection: Node " ?nid " detected control message flooding - " ?attack-subtype))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "HelloFlood-Detection")
      (trigger-condition (str-cat "DIO(" ?dio ")>T(" ?dio-th ") OR DIS(" ?dis ")>T(" ?dis-th ") OR DAO(" ?dao ")>T(" ?dao-th ")"))
      (conclusion (str-cat "Generate alert: " ?attack-subtype))
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "HelloFlood")
      (node-id ?nid)
      (explanation "Detected control message flooding attack, node sending excessive DIO/DIS/DAO messages")
      (evidence (str-cat "DIO:" ?dio ", DIS:" ?dis ", DAO:" ?dao))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "RATE_LIMIT")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Apply control message rate limiting to node " ?nid))))
   
   (printout t ">>> [IDS] Control Message Flooding: " ?nid crlf))


;;; R_Hybrid_2: Version Number Attack
(defrule R-Hybrid-2-VersionNumber
   "Hybrid IDS: Version Number Attack Detection"
   (declare (salience 100))
   
   (version-record 
      (node-id ?nid) 
      (previous-version ?prev) 
      (current-version ?curr&:(> ?curr ?prev))
      (timestamp ?ts))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "VersionNumber") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "VersionNumber")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "Intrusion Detection: Node " ?nid " version number changed from " ?prev " to " ?curr " abnormally"))
      (timestamp ?ts)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "VersionNumber-Attack-Detection")
      (trigger-condition (str-cat "Received_Version(" ?curr ") > Current_Version(" ?prev ")"))
      (conclusion "Generate alert (Version Number Attack)")
      (node-id ?nid)
      (timestamp ?ts)))
   
   (assert (reason
      (attack-type "VersionNumber")
      (node-id ?nid)
      (explanation "Detected Version Number attack, malicious node forges high version number to trigger DODAG reconstruction")
      (evidence (str-cat "Version: " ?prev " -> " ?curr))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "VERIFY_VERSION")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Verify node " ?nid " version number legitimacy, resync from Root if necessary"))))
   
   (printout t ">>> [IDS] Version Number Attack: " ?nid crlf))


;;; R_Hybrid_3: Rank Decrease Attack
(defrule R-Hybrid-3-RankDecrease
   "Hybrid IDS: Rank Decrease Attack Detection"
   (declare (salience 100))
   
   (neighbor-rank-stats 
      (node-id ?nid) 
      (received-rank ?recv) 
      (avg-neighbor-rank ?avg) 
      (max-neighbor-rank ?max) 
      (k-factor ?k))
   
   ;; Condition: Received_Rank < (Avg_Neighbor_Rank - Max_Neighbor_Rank * K)
   (test (< ?recv (- ?avg (* ?max ?k))))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "RankDecrease") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "RankDecrease")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "Intrusion Detection: Node " ?nid " Rank(" ?recv ") abnormally lower than neighbor average"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "RankDecrease-Attack-Detection")
      (trigger-condition (str-cat "Rank(" ?recv ") < (AvgRank(" ?avg ") - MaxRank(" ?max ") * K(" ?k "))"))
      (conclusion "Node is attacker (Rank Decrease Attack)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "RankDecrease")
      (node-id ?nid)
      (explanation "Detected Rank Decrease attack, node forges abnormally low Rank value")
      (evidence (str-cat "Recv_Rank:" ?recv ", Avg:" ?avg ", Max:" ?max ", K:" ?k))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "ISOLATE_NODE")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Isolate Rank attack node " ?nid))))
   
   (printout t ">>> [IDS] Rank Decrease Attack: " ?nid crlf))


;;;============================================
;;; SECTION 8: SRPL-RP DEFENSE (Reference [22][24])
;;; Rank and Version Attack Defense
;;;============================================

;;; R_SRPL_1: Parent-Child Rank Check
(defrule R-SRPL-1-ParentChildRank
   "SRPL-RP: Parent-Child Rank Check - NCR < NPR indicates malicious"
   (declare (salience 100))
   
   (srpl-rank-check 
      (node-id ?nid) 
      (ncr ?ncr) 
      (npr ?npr))
   
   ;; Condition: Node Current Rank < Node Parent Rank (violates RPL rules)
   (test (< ?ncr ?npr))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "SRPL-Malicious") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "SRPL-Malicious")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "Rank Violation: Node " ?nid " NCR(" ?ncr ") < NPR(" ?npr "), identified as MALICIOUS"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "ParentChild-Rank-Violation")
      (trigger-condition (str-cat "NCR(" ?ncr ") < NPR(" ?npr ")"))
      (conclusion "Malicious node, block permanently")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "SRPL-Malicious")
      (node-id ?nid)
      (explanation "SRPL-RP Detection: Node Rank is less than its parent Rank, violates RPL protocol rules")
      (evidence (str-cat "NCR:" ?ncr ", NPR:" ?npr))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "BLOCK_PERMANENT")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Permanently block malicious node " ?nid))))
   
   (printout t ">>> [Rank-Check] Malicious Node (Parent-Child Rank): " ?nid crlf))


;;; R_SRPL_2: Rank Decrease Check
(defrule R-SRPL-2-RankDecreaseCheck
   "SRPL-RP: Rank Decrease Check"
   (declare (salience 100))
   
   (srpl-rank-check 
      (node-id ?nid) 
      (ncr ?ncr) 
      (nor ?nor) 
      (msr ?msr) 
      (pst ?pst))
   
   ;; Condition: NCR < NOR AND NCR < (MSR - PST)
   (test (and (< ?ncr ?nor) (< ?ncr (- ?msr ?pst))))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "SRPL-RankDecrease") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "SRPL-RankDecrease")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "Rank Violation: Node " ?nid " Rank abnormally decreased, identified as MALICIOUS"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Abnormal-Rank-Decrease")
      (trigger-condition (str-cat "NCR(" ?ncr ") < NOR(" ?nor ") AND NCR < (MSR(" ?msr ") - PST(" ?pst "))"))
      (conclusion "Malicious node, block permanently")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "SRPL-RankDecrease")
      (node-id ?nid)
      (explanation "SRPL-RP Detection: Node Rank abnormally decreased and below sibling threshold")
      (evidence (str-cat "NCR:" ?ncr ", NOR:" ?nor ", MSR:" ?msr ", PST:" ?pst))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "BLOCK_PERMANENT")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Permanently block Rank decrease attack node " ?nid))))
   
   (printout t ">>> [Rank-Check] Rank Decrease Attack: " ?nid crlf))


;;; R_SRPL_3: Rank Increase Check
(defrule R-SRPL-3-RankIncreaseCheck
   "SRPL-RP: Rank Increase Check"
   (declare (salience 100))
   
   (srpl-rank-check 
      (node-id ?nid) 
      (ncr ?ncr) 
      (nor ?nor) 
      (mcr ?mcr))
   
   ;; Condition: NCR > NOR AND NCR >= MCR
   (test (and (> ?ncr ?nor) (>= ?ncr ?mcr)))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "SRPL-RankIncrease") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "SRPL-RankIncrease")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "Rank Violation: Node " ?nid " Rank abnormally increased, temporarily blocked"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Abnormal-Rank-Increase")
      (trigger-condition (str-cat "NCR(" ?ncr ") > NOR(" ?nor ") AND NCR >= MCR(" ?mcr ")"))
      (conclusion "Malicious node, block temporarily")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "SRPL-RankIncrease")
      (node-id ?nid)
      (explanation "SRPL-RP Detection: Node Rank abnormally increased and exceeds minimum child Rank")
      (evidence (str-cat "NCR:" ?ncr ", NOR:" ?nor ", MCR:" ?mcr))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "BLOCK_TEMPORARY")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Temporarily block suspicious node " ?nid ", observe subsequent behavior"))))
   
   (printout t ">>> [Rank-Check] Rank Increase Attack: " ?nid crlf))


;;;============================================
;;; SECTION 9: DISTRIBUTED IDS (Reference [25][26])
;;; Distributed Intrusion Detection System
;;;============================================

;;; R_Dist_1: Parent Rank Deviation
(defrule R-Dist-1-RankDeviation
   "Distributed IDS: Parent Rank Deviation Exceeds One Hop"
   (declare (salience 100))
   
   (node-rank-history 
      (node-id ?nid) 
      (previous-rank ?prev) 
      (current-rank ?curr)
      (timestamp ?ts))
   
   ;; Check if deviation exceeds one hop increment (assume each hop increment is 256)
   (test (> (abs (- ?curr ?prev)) 256))
   
   ?vc <- (violation-counter (node-id ?nid) (count ?cnt) (threshold ?th))
   
   =>
   
   (retract ?vc)
   (assert (violation-counter 
      (node-id ?nid) 
      (count (+ ?cnt 1)) 
      (threshold ?th)
      (time-window 30)))
   
   (printout t ">>> [IDS] Rank Deviation: " ?nid ", Violation Count: " (+ ?cnt 1) crlf))


;;; R_Dist_2: Violation Threshold Exceeded
(defrule R-Dist-2-ViolationThreshold
   "Distributed IDS: Violation Count Exceeds Threshold"
   (declare (salience 100))
   
   (violation-counter 
      (node-id ?nid) 
      (count ?cnt) 
      (threshold ?th&:(>= ?cnt ?th)))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "Dist-IDS-Violation") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Dist-IDS-Violation")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "Distributed IDS: Node " ?nid " violation count(" ?cnt ") exceeds threshold(" ?th ")"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Security-Violation-Threshold")
      (trigger-condition (str-cat "Violation_Counter(" ?cnt ") >= Threshold(" ?th ")"))
      (conclusion "Isolate the parent")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Dist-IDS-Violation")
      (node-id ?nid)
      (explanation "Distributed IDS Detection: Node violated multiple times, exceeds allowed threshold")
      (evidence (str-cat "Violation count: " ?cnt ", Threshold: " ?th ", Time window: 30 seconds"))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "ISOLATE_PARENT")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Isolate parent node " ?nid ", select alternate parent"))))
   
   (printout t ">>> [IDS] Isolate Node: " ?nid crlf))


;;;============================================
;;; SECTION 10: FLBT-RPL SYBIL DETECTION (Reference [28])
;;; Sybil Attack Detection
;;;============================================

;;; R_FLBT_1: Sybil Attack Detection
(defrule R-FLBT-1-SybilDetection
   "FLBT-RPL: Sybil Attack Detection"
   (declare (salience 100))
   
   (sybil-indicators 
      (node-id ?nid)
      (ics ?ics) (ics-threshold ?ics-th)
      (scs ?scs) (scs-threshold ?scs-th)
      (res ?res) (res-threshold ?res-th)
      (rms ?rms) (rms-threshold ?rms-th)
      (bis ?bis) (bis-threshold ?bis-th)
      (tds ?tds) (tds-threshold ?tds-th))
   
   ;; Any indicator exceeds threshold
   (test (or (>= ?ics ?ics-th) (>= ?scs ?scs-th) (>= ?res ?res-th) 
             (>= ?rms ?rms-th) (>= ?bis ?bis-th) (>= ?tds ?tds-th)))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "Sybil") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Sybil")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "Sybil Detection: Node " ?nid " detected Sybil attack"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Sybil-Attack-Detection")
      (trigger-condition "ICS>=theta OR SCS>=theta OR RES>=theta OR RMS>=theta OR BIS>=theta OR TDS>=theta")
      (conclusion "Attack Node = True (Sybil attack node detected)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Sybil")
      (node-id ?nid)
      (explanation "FLBT-RPL detected Sybil attack: Single node forges multiple identities")
      (evidence (str-cat "ICS:" ?ics ", SCS:" ?scs ", RES:" ?res ", RMS:" ?rms ", BIS:" ?bis ", TDS:" ?tds))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "BLOCK_ALL_IDENTITIES")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Block all identities of node " ?nid ", verify physical node"))))
   
   (printout t ">>> [Sybil] Sybil Attack: " ?nid crlf))


;;;============================================
;;; UTILITY RULES - Utility Rules
;;;============================================

;;; Initialize Violation Counter
(defrule init-violation-counter
   "Initialize Violation Counter for New Node"
   (declare (salience 250))
   
   (node-rank-history (node-id ?nid))
   (not (violation-counter (node-id ?nid)))
   
   =>
   
   (assert (violation-counter 
      (node-id ?nid) 
      (count 0) 
      (threshold 5)
      (time-window 30))))


;;; Combined Attack Escalation Rule
(defrule escalate-combined-attack
   "Detect Combined Attack - Same node exhibits multiple attack behaviors"
   (declare (salience 50))
   
   (attack-alert (attack-type ?type1) (node-id ?nid))
   (attack-alert (attack-type ?type2&:(neq ?type2 ?type1)) (node-id ?nid))
   
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (inference-path (rule-name "escalate-combined-attack") (node-id ?nid)))
   
   =>
   
   (retract ?step-counter)
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "escalate-combined-attack")
      (trigger-condition (str-cat "Node " ?nid " triggered both " ?type1 " and " ?type2 " attack detection"))
      (conclusion "Escalate to HIGH-RISK node - Possible complex coordinated attack")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "CombinedAttack")
      (node-id ?nid)
      (explanation (str-cat "Node " ?nid " exhibits multiple attack characteristics (" ?type1 " + " ?type2 ")"))
      (evidence "Multiple attack indicators triggered simultaneously")))
   
   (printout t ">>> [ESCALATION] Combined Attack! Node: " ?nid " Triggered: " ?type1 " + " ?type2 crlf))
