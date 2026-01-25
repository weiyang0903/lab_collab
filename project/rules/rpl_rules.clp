;;;======================================================
;;; RPL Protocol Attack Detection Expert System
;;; Based on Literature Review Rules
;;; 
;;; References:
;;; [9] FLSec-RPL: Fuzzy Logic for DIO Neighbor Suppression
;;; [15] Jamming Attack Detection
;;; [3] PRBA - Passive Rule-Based Approach
;;; [11] Random Forest Multi-Attack Detection
;;; [6] XAI Anomaly Detection (Isolation Forest)
;;; [14] UVM - Unweighted Voting Method
;;; [13] Hybrid IDS
;;; [2] SRPL-RP Rank & Version Attack Defense
;;; [10] Distributed IDS
;;; [12] FLBT-RPL Sybil Detection
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

;;; UDP Forwarded Record (for XAI Anomaly Detection)
(deftemplate udp-forwarded
   "UDP Packets Forwarded"
   (slot node-id (type STRING))
   (slot count (type FLOAT)))

;;; Packet Forwarding Statistics (for XAI)
(deftemplate packet-forwarding
   "Packet Forwarding Rate"
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
;;; SECTION 1: FLSec-RPL RULES (Reference [9])
;;; DIO Neighbor Suppression Attack Detection - Fuzzy Logic with Conflict Resolution
;;; 
;;; CONFLICT RESOLUTION STRATEGY:
;;; 1. Calculate threat-score using inverted weights for DTI and STIA
;;;    DIO: H=3, M=2, L=1 (higher DIO = more suspicious)
;;;    DTI: L=3, M=2, H=1 (lower DTI = more suspicious - frequent sending)
;;;    STIA: L=3, M=2, H=1 (lower STIA = more suspicious)
;;; 2. Score range: [3, 9]
;;; 3. Classification with STIA-based refinement:
;;;    - Malicious: Score >= 8 AND STIA=L (Rules 1,4,10)
;;;    - Normal: Score <= 5 OR (Score=6 AND (STIA=H OR DIO=H))
;;;    - Quarantine: All other cases
;;;
;;; LITERATURE TABLE MAPPING (27 Rules):
;;; Score=9: Rule 1 (H,L,L) → Malicious
;;; Score=8+STIA=L: Rules 4,10 → Malicious  
;;; Score=8+STIA≠L: Rule 2 → Quarantine
;;; Score=7: Rules 3,5,7,11,13,19 → Quarantine
;;; Score=6+edge: Rules 6,8,12→Normal, 16,20,22→Quarantine
;;; Score<=5: Rules 9,14,15,17,18,21,23,24,25,26,27 → Normal
;;;============================================

;;; Threat Score Template for intermediate calculation
(deftemplate dio-threat-score
   "DIO Suppression Threat Score"
   (slot node-id (type STRING))
   (slot dio-level (type SYMBOL))
   (slot dti-level (type SYMBOL))
   (slot stia-level (type SYMBOL))
   (slot score (type INTEGER))
   (slot classification (type SYMBOL) (allowed-symbols Malicious Quarantine Normal)))

;;;--------------------------------------------
;;; PHASE 1: Calculate Threat Score (salience 150)
;;; Consolidates all 27 combinations into score calculation
;;;--------------------------------------------
(defrule R-FLSec-CalcScore
   "FLSec-RPL: Calculate DIO Suppression Threat Score"
   (declare (salience 150))
   
   (dio-counter (node-id ?nid) (level ?dio-lvl))
   (dti-record (node-id ?nid) (level ?dti-lvl))
   (stia-record (node-id ?nid) (level ?stia-lvl))
   
   (not (dio-threat-score (node-id ?nid)))
   
   =>
   
   ;; Calculate weights with INVERTED DTI and STIA (low = more dangerous)
   ;; DIO: H=3, M=2, L=1 | DTI: L=3, M=2, H=1 | STIA: L=3, M=2, H=1
   (bind ?dio-w (if (eq ?dio-lvl High) then 3 else (if (eq ?dio-lvl Medium) then 2 else 1)))
   (bind ?dti-w (if (eq ?dti-lvl Low) then 3 else (if (eq ?dti-lvl Medium) then 2 else 1)))
   (bind ?stia-w (if (eq ?stia-lvl Low) then 3 else (if (eq ?stia-lvl Medium) then 2 else 1)))
   
   ;; Threat score: range [3, 9]
   (bind ?score (+ ?dio-w ?dti-w ?stia-w))
   
   ;; Classification with STIA and DIO based refinement for edge cases
   ;; Malicious: Score >= 8 AND STIA = Low
   ;; Normal: Score <= 5 OR (Score = 6 AND (STIA = High OR DIO = High))
   ;; Quarantine: Everything else (Score=7, Score>=8 with STIA≠L, Score=6 edge cases)
   (bind ?class 
      (if (and (>= ?score 8) (eq ?stia-lvl Low)) then Malicious
         else (if (or (<= ?score 5) 
                      (and (eq ?score 6) 
                           (or (eq ?stia-lvl High) (eq ?dio-lvl High))))
                  then Normal
                  else Quarantine)))
   
   (assert (dio-threat-score
      (node-id ?nid)
      (dio-level ?dio-lvl)
      (dti-level ?dti-lvl)
      (stia-level ?stia-lvl)
      (score ?score)
      (classification ?class)))
   
   (printout t ">>> [DIO-Score] Node " ?nid ": DIO=" ?dio-lvl " DTI=" ?dti-lvl " STIA=" ?stia-lvl " => Score=" ?score " Class=" ?class crlf))


;;;--------------------------------------------
;;; PHASE 2: Malicious Detection (Highest Priority - salience 120)
;;; Rules 1, 4, 10: Score >= 8 AND STIA = Low
;;; Rule 1: H,L,L (Score=9) | Rule 4: H,M,L (Score=8) | Rule 10: M,L,L (Score=8)
;;;--------------------------------------------
(defrule R-FLSec-Malicious
   "FLSec-RPL: Detect Malicious Node - Score >= 8 AND STIA = Low"
   (declare (salience 120))
   
   (dio-threat-score (node-id ?nid) (dio-level ?dio) (dti-level ?dti) (stia-level ?stia&Low) 
                     (score ?score&:(>= ?score 8)) (classification Malicious))
   
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
      (message (str-cat "DIO Suppression: Node " ?nid " MALICIOUS [Score=" ?score "] DIO=" ?dio " DTI=" ?dti " STIA=" ?stia))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "DIO-Suppression-Malicious-Detection")
      (trigger-condition (str-cat "ThreatScore=" ?score ">=8 [DIO=" ?dio ",DTI=" ?dti ",STIA=" ?stia "]"))
      (conclusion "Aggressive_Weight = Malicious (Confirmed Attacker)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "DIO-Suppression-Malicious")
      (node-id ?nid)
      (explanation "Conflict Resolution: High threat score indicates aggressive DIO flooding behavior")
      (evidence (str-cat "Score=" ?score " [DIO=" ?dio ",DTI=" ?dti ",STIA=" ?stia "]"))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "BLOCK_PERMANENT")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Permanently block malicious node " ?nid " - remove from neighbor table"))))
   
   (printout t ">>> [DIO-Suppression] MALICIOUS Node: " ?nid " Score=" ?score crlf))


;;;--------------------------------------------
;;; PHASE 2: Quarantine Detection (Medium Priority - salience 110)
;;; Rules 2,3,5,7,11,13,16,19,20,22: Score=7 OR (Score>=8 AND STIA≠L) OR (Score=6 edge cases)
;;;--------------------------------------------
(defrule R-FLSec-Quarantine
   "FLSec-RPL: Quarantine Suspicious Node - Score=7 or edge cases"
   (declare (salience 110))
   
   (dio-threat-score (node-id ?nid) (dio-level ?dio) (dti-level ?dti) (stia-level ?stia)
                     (score ?score) (classification Quarantine))
   
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
      (message (str-cat "DIO Suppression: Node " ?nid " QUARANTINE [Score=" ?score "] DIO=" ?dio " DTI=" ?dti " STIA=" ?stia))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "DIO-Suppression-Quarantine-Detection")
      (trigger-condition (str-cat "5<=ThreatScore=" ?score "<8 [DIO=" ?dio ",DTI=" ?dti ",STIA=" ?stia "]"))
      (conclusion "Aggressive_Weight = Quarantine (Requires Monitoring)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "DIO-Suppression-Quarantine")
      (node-id ?nid)
      (explanation "Conflict Resolution: Medium threat score - suspicious but not confirmed malicious")
      (evidence (str-cat "Score=" ?score " [DIO=" ?dio ",DTI=" ?dti ",STIA=" ?stia "]"))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "QUARANTINE")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Temporarily isolate node " ?nid " for observation"))))
   
   (printout t ">>> [DIO-Suppression] QUARANTINE Node: " ?nid " Score=" ?score crlf))


;;;--------------------------------------------
;;; PHASE 2: Normal Classification (Lowest Priority - salience 100)
;;; Rules 6,8,9,12,14,15,17,18,21,23,24,25,26,27: Score<=5 OR (Score=6 with STIA=H or DIO=H)
;;;--------------------------------------------
(defrule R-FLSec-Normal
   "FLSec-RPL: Normal Node - Score<=5 or edge case with STIA=H/DIO=H"
   (declare (salience 100))
   
   (dio-threat-score (node-id ?nid) (dio-level ?dio) (dti-level ?dti) (stia-level ?stia)
                     (score ?score) (classification Normal))
   
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (inference-path (rule-name "DIO-Behavior-Normal-Check") (node-id ?nid)))
   
   =>
   
   (retract ?step-counter)
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "DIO-Behavior-Normal-Check")
      (trigger-condition (str-cat "ThreatScore=" ?score "<5 [DIO=" ?dio ",DTI=" ?dti ",STIA=" ?stia "]"))
      (conclusion "Aggressive_Weight = Normal (Legitimate Node)")
      (node-id ?nid)
      (timestamp 0)))
   
   (printout t ">>> [DIO-Suppression] NORMAL Node: " ?nid " Score=" ?score crlf))


;;;============================================
;;; SECTION 2: JAMMING ATTACK DETECTION (Reference [15])
;;; Jamming Attack Detection with Conflict Resolution
;;;
;;; CONFLICT RESOLUTION STRATEGY:
;;; 1. Retransmissions is the PRIMARY indicator (more weight)
;;; 2. Classification rules:
;;;    - NO ATTACK: Retrans=L (Rules 1,4) regardless of ETX
;;;    - LOW: Retrans=M AND ETX∈{L,M} OR (Retrans=L AND ETX=H) (Rules 2,5,7)
;;;    - MEDIUM: Retrans=H AND ETX∈{L,M} OR (Retrans=M AND ETX=H) (Rules 3,6,8)
;;;    - HIGH: Retrans=H AND ETX=H (Rule 9 only)
;;;
;;; LITERATURE TABLE (9 Rules):
;;; Rules 1,4: (L,L), (M,L) → NO ATTACK [Retrans=L dominates]
;;; Rules 2,5: (L,M), (M,M) → LOW
;;; Rule 7: (H,L) → LOW [Exception: High ETX but Low Retrans]
;;; Rules 3,6: (L,H), (M,H) → MEDIUM
;;; Rule 8: (H,M) → MEDIUM  
;;; Rule 9: (H,H) → HIGH
;;;============================================

;;; Jamming Index Score Template
(deftemplate jamming-index
   "Jamming Index Score"
   (slot node-id (type STRING))
   (slot etx-level (type SYMBOL))
   (slot retrans-level (type SYMBOL))
   (slot classification (type SYMBOL) (allowed-symbols NoAttack Low Medium High)))

;;;--------------------------------------------
;;; PHASE 1: Calculate Jamming Classification (salience 150)
;;; Uses Retrans as primary indicator with ETX adjustment
;;;--------------------------------------------
(defrule R-Jam-CalcIndex
   "Jamming: Calculate Jamming Index Classification"
   (declare (salience 150))
   
   (etx-record (node-id ?nid) (level ?etx-lvl))
   (retransmission-record (node-id ?nid) (level ?retrans-lvl))
   
   (not (jamming-index (node-id ?nid)))
   
   =>
   
   ;; Classification based on Retrans (primary) and ETX (secondary)
   ;; Rules 1,4: Retrans=L → NO ATTACK (except H,L→LOW)
   ;; Rule 7: H,L → LOW (exception)
   ;; Rules 2,5: Retrans=M AND ETX∈{L,M} → LOW
   ;; Rule 8: H,M → MEDIUM
   ;; Rules 3,6: Retrans=H AND ETX∈{L,M} → MEDIUM
   ;; Rule 9: H,H → HIGH
   (bind ?class 
      (if (and (eq ?etx-lvl High) (eq ?retrans-lvl High)) then High
         else (if (eq ?retrans-lvl High) then Medium
            else (if (and (eq ?etx-lvl High) (eq ?retrans-lvl Medium)) then Medium
               else (if (eq ?retrans-lvl Medium) then Low
                  else (if (eq ?etx-lvl High) then Low
                     else NoAttack))))))
   
   (assert (jamming-index
      (node-id ?nid)
      (etx-level ?etx-lvl)
      (retrans-level ?retrans-lvl)
      (classification ?class)))
   
   (printout t ">>> [Jamming-Index] Node " ?nid ": ETX=" ?etx-lvl " Retrans=" ?retrans-lvl " => JI=" ?class crlf))


;;;--------------------------------------------
;;; PHASE 2: HIGH Jamming Detection (Highest Priority - salience 120)
;;; Rule 9: ETX=H AND Retrans=H → HIGH
;;;--------------------------------------------
(defrule R-Jam-High
   "Jamming: HIGH Level - ETX High AND Retransmissions High (Rule 9)"
   (declare (salience 120))
   
   (jamming-index (node-id ?nid) (etx-level ?etx) (retrans-level ?retrans) (classification High))
   
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
      (message (str-cat "Jamming: Node " ?nid " HIGH [ETX=" ?etx ",Retrans=" ?retrans "]"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Jamming-High-Detection")
      (trigger-condition (str-cat "ETX=" ?etx " AND Retrans=" ?retrans " => JI=HIGH"))
      (conclusion "Jamming Index = HIGH (Severe Jamming Attack)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Jamming-High")
      (node-id ?nid)
      (explanation "Conflict Resolution: Both ETX and Retransmissions at High level indicate severe jamming")
      (evidence (str-cat "ETX=" ?etx ",Retrans=" ?retrans))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "CHANNEL_HOP")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Enable frequency hopping or switch channel for node " ?nid))))
   
   (printout t ">>> [JAMMING] HIGH Level Attack: " ?nid crlf))


;;;--------------------------------------------
;;; PHASE 2: MEDIUM Jamming Detection (salience 110)
;;; Rules 3,6,8: Retrans=H OR (ETX=H AND Retrans=M)
;;;--------------------------------------------
(defrule R-Jam-Medium
   "Jamming: MEDIUM Level - Rules 3,6,8"
   (declare (salience 110))
   
   (jamming-index (node-id ?nid) (etx-level ?etx) (retrans-level ?retrans) (classification Medium))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "Jamming-Medium") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Jamming-Medium")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "Jamming: Node " ?nid " MEDIUM [ETX=" ?etx ",Retrans=" ?retrans "]"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Jamming-Medium-Detection")
      (trigger-condition (str-cat "ETX=" ?etx " AND Retrans=" ?retrans " => JI=MEDIUM"))
      (conclusion "Jamming Index = MEDIUM (Moderate Jamming)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Jamming-Medium")
      (node-id ?nid)
      (explanation "Conflict Resolution: High Retrans or High ETX with Medium Retrans indicates moderate jamming")
      (evidence (str-cat "ETX=" ?etx ",Retrans=" ?retrans))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "INCREASE_POWER")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Increase transmission power or adjust antenna for node " ?nid))))
   
   (printout t ">>> [JAMMING] MEDIUM Level: " ?nid crlf))


;;;--------------------------------------------
;;; PHASE 2: LOW Jamming Detection (salience 105)
;;; Rules 2,5,7: Retrans=M (ETX∈{L,M}) OR (ETX=H AND Retrans=L)
;;;--------------------------------------------
(defrule R-Jam-Low
   "Jamming: LOW Level - Rules 2,5,7"
   (declare (salience 105))
   
   (jamming-index (node-id ?nid) (etx-level ?etx) (retrans-level ?retrans) (classification Low))
   
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
      (severity "MEDIUM")
      (message (str-cat "Jamming: Node " ?nid " LOW [ETX=" ?etx ",Retrans=" ?retrans "]"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Jamming-Low-Detection")
      (trigger-condition (str-cat "ETX=" ?etx " AND Retrans=" ?retrans " => JI=LOW"))
      (conclusion "Jamming Index = LOW (Mild Interference)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Jamming-Low")
      (node-id ?nid)
      (explanation "Conflict Resolution: Medium Retrans or High ETX alone indicates mild interference")
      (evidence (str-cat "ETX=" ?etx ",Retrans=" ?retrans))))
   
   (printout t ">>> [JAMMING] LOW Level: " ?nid crlf))


;;;--------------------------------------------
;;; PHASE 2: NO ATTACK Classification (Lowest Priority - salience 100)
;;; Rules 1,4: Retrans=L AND ETX∈{L,M}
;;;--------------------------------------------
(defrule R-Jam-NoAttack
   "Jamming: NO ATTACK - Rules 1,4"
   (declare (salience 100))
   
   (jamming-index (node-id ?nid) (etx-level ?etx) (retrans-level ?retrans) (classification NoAttack))
   
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (inference-path (rule-name "Jamming-NoAttack-Check") (node-id ?nid)))
   
   =>
   
   (retract ?step-counter)
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Jamming-NoAttack-Check")
      (trigger-condition (str-cat "ETX=" ?etx " AND Retrans=" ?retrans " => JI=NO_ATTACK"))
      (conclusion "Jamming Index = NO ATTACK (Normal Operation)")
      (node-id ?nid)
      (timestamp 0)))
   
   (printout t ">>> [JAMMING] NO ATTACK: " ?nid crlf))


;;;============================================
;;; SECTION 3: PRBA/UVM SINKHOLE DETECTION (Reference [3],[14])
;;; Passive Rule-Based Approach + Unweighted Voting Method
;;; with Conflict Resolution Strategy
;;;
;;; Sinkhole Detection Rules (5 Rules):
;;; Rule 1: IF Child refers to Parent AND Parent refers to Child (Bi-Directional) THEN Suspicious
;;; Rule 2: IF Count(Bi-Directional Events) > Threshold THEN Suspicious
;;; Rule 3: IF Power Consumption > Threshold THEN Suspicious
;;; Rule 4: IF DIO_Frequency_Current > DIO_Frequency_Previous THEN Suspicious
;;; Rule 5: IF NRP > SRN (Rank Harmony) THEN Suspicious
;;;
;;; Conflict Resolution Strategy:
;;; - Priority: Combined Indicators (highest) > Single Indicators
;;; - Use intermediate classification fact (sinkhole-suspicion-class) to resolve conflicts
;;; - Suspicion score: 0-5 based on triggered rules
;;;============================================

;;; Sinkhole Suspicion Classification Template
(deftemplate sinkhole-suspicion-class
   "Intermediate fact for Sinkhole detection classification"
   (slot node-id (type STRING))
   (slot suspicion-level (type STRING))       ; CRITICAL, HIGH, MEDIUM, LOW, NORMAL
   (slot suspicion-score (type INTEGER))      ; 0-5 based on triggered rules
   (slot bidirectional-flag (type INTEGER))   ; Rule 1: 0 or 1
   (slot freq-bidirect-flag (type INTEGER))   ; Rule 2: 0 or 1
   (slot power-anomaly-flag (type INTEGER))   ; Rule 3: 0 or 1
   (slot dio-frequency-flag (type INTEGER))   ; Rule 4: 0 or 1
   (slot rank-harmony-flag (type INTEGER))    ; Rule 5: 0 or 1
   (slot evidence (type STRING)))

;;; ===========================================
;;; CLASSIFICATION RULES (High Salience: 150-155)
;;; ===========================================

;;; Rule 1: Bidirectional Behavior Detection
(defrule R-PRBA-1-Bidirectional-Classify
   "PRBA Rule 1: Classify Bidirectional Behavior"
   (declare (salience 155))
   
   (bidirectional-behavior 
      (child-id ?cid) 
      (parent-id ?pid) 
      (count ?cnt&:(> ?cnt 0))
      (timestamp ?ts))
   
   (not (sinkhole-suspicion-class (node-id ?cid)))
   
   =>
   
   (assert (sinkhole-suspicion-class
      (node-id ?cid)
      (suspicion-level "LOW")
      (suspicion-score 1)
      (bidirectional-flag 1)
      (freq-bidirect-flag 0)
      (power-anomaly-flag 0)
      (dio-frequency-flag 0)
      (rank-harmony-flag 0)
      (evidence (str-cat "Bidirectional: " ?cid " <-> " ?pid " (count=" ?cnt ")"))))
   
   (printout t ">>> [SINKHOLE-CLASSIFY] Rule1 Bidirectional: " ?cid " <-> " ?pid crlf))


;;; Rule 2: Frequent Bidirectional - Update existing classification
(defrule R-PRBA-2-FreqBidirectional-Update
   "PRBA Rule 2: Update classification with Frequent Bidirectional"
   (declare (salience 154))
   
   (bidirectional-behavior 
      (child-id ?cid) 
      (parent-id ?pid) 
      (count ?cnt&:(> ?cnt 5)))  ; Threshold = 5
   
   ?class <- (sinkhole-suspicion-class 
      (node-id ?cid)
      (suspicion-score ?score)
      (freq-bidirect-flag 0)
      (evidence ?ev))
   
   =>
   
   (bind ?new-score (+ ?score 1))
   (bind ?new-level (if (>= ?new-score 4) then "CRITICAL"
                     else (if (>= ?new-score 3) then "HIGH"
                     else (if (>= ?new-score 2) then "MEDIUM" else "LOW"))))
   
   (modify ?class
      (suspicion-level ?new-level)
      (suspicion-score ?new-score)
      (freq-bidirect-flag 1)
      (evidence (str-cat ?ev " | FreqBidirect: count=" ?cnt " > threshold=5")))
   
   (printout t ">>> [SINKHOLE-CLASSIFY] Rule2 FreqBidirectional: " ?cid " count=" ?cnt crlf))


;;; Rule 2 Alternative: Create new classification if no existing
(defrule R-PRBA-2-FreqBidirectional-New
   "PRBA Rule 2: Create classification for Frequent Bidirectional (standalone)"
   (declare (salience 153))
   
   (bidirectional-behavior 
      (child-id ?cid) 
      (parent-id ?pid) 
      (count ?cnt&:(> ?cnt 5)))
   
   (not (sinkhole-suspicion-class (node-id ?cid)))
   
   =>
   
   (assert (sinkhole-suspicion-class
      (node-id ?cid)
      (suspicion-level "MEDIUM")
      (suspicion-score 2)
      (bidirectional-flag 1)
      (freq-bidirect-flag 1)
      (power-anomaly-flag 0)
      (dio-frequency-flag 0)
      (rank-harmony-flag 0)
      (evidence (str-cat "FreqBidirect: " ?cid " <-> " ?pid " count=" ?cnt " > 5"))))
   
   (printout t ">>> [SINKHOLE-CLASSIFY] Rule2 FreqBidirectional (new): " ?cid crlf))


;;; Rule 3: Power Consumption Anomaly - Update existing
(defrule R-PRBA-3-PowerConsumption-Update
   "PRBA Rule 3: Update classification with Power Consumption anomaly"
   (declare (salience 152))
   
   (power-consumption 
      (node-id ?nid) 
      (value ?pwr) 
      (threshold ?th&:(< ?th ?pwr)))
   
   ?class <- (sinkhole-suspicion-class 
      (node-id ?nid)
      (suspicion-score ?score)
      (power-anomaly-flag 0)
      (evidence ?ev))
   
   =>
   
   (bind ?new-score (+ ?score 1))
   (bind ?new-level (if (>= ?new-score 4) then "CRITICAL"
                     else (if (>= ?new-score 3) then "HIGH"
                     else (if (>= ?new-score 2) then "MEDIUM" else "LOW"))))
   
   (modify ?class
      (suspicion-level ?new-level)
      (suspicion-score ?new-score)
      (power-anomaly-flag 1)
      (evidence (str-cat ?ev " | Power: " ?pwr " > " ?th)))
   
   (printout t ">>> [SINKHOLE-CLASSIFY] Rule3 PowerAnomaly: " ?nid " power=" ?pwr crlf))


;;; Rule 3 Alternative: Create new classification
(defrule R-PRBA-3-PowerConsumption-New
   "PRBA Rule 3: Create classification for Power Consumption anomaly"
   (declare (salience 151))
   
   (power-consumption 
      (node-id ?nid) 
      (value ?pwr) 
      (threshold ?th&:(< ?th ?pwr)))
   
   (not (sinkhole-suspicion-class (node-id ?nid)))
   
   =>
   
   (assert (sinkhole-suspicion-class
      (node-id ?nid)
      (suspicion-level "LOW")
      (suspicion-score 1)
      (bidirectional-flag 0)
      (freq-bidirect-flag 0)
      (power-anomaly-flag 1)
      (dio-frequency-flag 0)
      (rank-harmony-flag 0)
      (evidence (str-cat "Power: " ?pwr " > threshold " ?th))))
   
   (printout t ">>> [SINKHOLE-CLASSIFY] Rule3 PowerAnomaly (new): " ?nid crlf))


;;; Rule 4: DIO Frequency Anomaly - Update existing
(defrule R-PRBA-4-DIOFrequency-Update
   "UVM Rule 4: Update classification with DIO Frequency anomaly"
   (declare (salience 150))
   
   (dio-message-stats 
      (node-id ?nid) 
      (current-count ?curr) 
      (previous-count ?prev&:(< ?prev ?curr)))
   
   ?class <- (sinkhole-suspicion-class 
      (node-id ?nid)
      (suspicion-score ?score)
      (dio-frequency-flag 0)
      (evidence ?ev))
   
   =>
   
   (bind ?new-score (+ ?score 1))
   (bind ?new-level (if (>= ?new-score 4) then "CRITICAL"
                     else (if (>= ?new-score 3) then "HIGH"
                     else (if (>= ?new-score 2) then "MEDIUM" else "LOW"))))
   
   (modify ?class
      (suspicion-level ?new-level)
      (suspicion-score ?new-score)
      (dio-frequency-flag 1)
      (evidence (str-cat ?ev " | DIOFreq: " ?curr " > " ?prev)))
   
   (printout t ">>> [SINKHOLE-CLASSIFY] Rule4 DIOFrequency: " ?nid " curr=" ?curr crlf))


;;; Rule 4 Alternative: Create new classification
(defrule R-PRBA-4-DIOFrequency-New
   "UVM Rule 4: Create classification for DIO Frequency anomaly"
   (declare (salience 149))
   
   (dio-message-stats 
      (node-id ?nid) 
      (current-count ?curr) 
      (previous-count ?prev&:(< ?prev ?curr)))
   
   (not (sinkhole-suspicion-class (node-id ?nid)))
   
   =>
   
   (assert (sinkhole-suspicion-class
      (node-id ?nid)
      (suspicion-level "LOW")
      (suspicion-score 1)
      (bidirectional-flag 0)
      (freq-bidirect-flag 0)
      (power-anomaly-flag 0)
      (dio-frequency-flag 1)
      (rank-harmony-flag 0)
      (evidence (str-cat "DIOFreq: curr=" ?curr " > prev=" ?prev))))
   
   (printout t ">>> [SINKHOLE-CLASSIFY] Rule4 DIOFrequency (new): " ?nid crlf))


;;; Rule 5: Rank Harmony Anomaly - Update existing
(defrule R-PRBA-5-RankHarmony-Update
   "UVM Rule 5: Update classification with Rank Harmony anomaly"
   (declare (salience 148))
   
   (rank-harmony 
      (node-id ?nid) 
      (parent-rank ?pr) 
      (node-rank ?nr) 
      (sink-rank ?sr))
   
   ;; Condition: NRP > SRN where NRP = |Parent_Rank - Node_Rank|, SRN = |Sink_Rank - Node_Rank|
   ;; If NRP > SRN, node claims to be closer to Sink than to Parent - Sinkhole indicator
   (test (> (abs (- ?pr ?nr)) (abs (- ?sr ?nr))))
   
   ?class <- (sinkhole-suspicion-class 
      (node-id ?nid)
      (suspicion-score ?score)
      (rank-harmony-flag 0)
      (evidence ?ev))
   
   =>
   
   (bind ?nrp (abs (- ?pr ?nr)))
   (bind ?srn (abs (- ?sr ?nr)))
   (bind ?new-score (+ ?score 1))
   (bind ?new-level (if (>= ?new-score 4) then "CRITICAL"
                     else (if (>= ?new-score 3) then "HIGH"
                     else (if (>= ?new-score 2) then "MEDIUM" else "LOW"))))
   
   (modify ?class
      (suspicion-level ?new-level)
      (suspicion-score ?new-score)
      (rank-harmony-flag 1)
      (evidence (str-cat ?ev " | RankHarmony: NRP=" ?nrp " < SRN=" ?srn)))
   
   (printout t ">>> [SINKHOLE-CLASSIFY] Rule5 RankHarmony: " ?nid " NRP=" ?nrp " < SRN=" ?srn crlf))


;;; Rule 5 Alternative: Create new classification
(defrule R-PRBA-5-RankHarmony-New
   "UVM Rule 5: Create classification for Rank Harmony anomaly"
   (declare (salience 147))
   
   (rank-harmony 
      (node-id ?nid) 
      (parent-rank ?pr) 
      (node-rank ?nr) 
      (sink-rank ?sr))
   
   ;; NRP > SRN indicates node falsely claims proximity to Sink
   (test (> (abs (- ?pr ?nr)) (abs (- ?sr ?nr))))
   
   (not (sinkhole-suspicion-class (node-id ?nid)))
   
   =>
   
   (bind ?nrp (abs (- ?pr ?nr)))
   (bind ?srn (abs (- ?sr ?nr)))
   
   (assert (sinkhole-suspicion-class
      (node-id ?nid)
      (suspicion-level "LOW")
      (suspicion-score 1)
      (bidirectional-flag 0)
      (freq-bidirect-flag 0)
      (power-anomaly-flag 0)
      (dio-frequency-flag 0)
      (rank-harmony-flag 1)
      (evidence (str-cat "RankHarmony: NRP=" ?nrp " < SRN=" ?srn))))
   
   (printout t ">>> [SINKHOLE-CLASSIFY] Rule5 RankHarmony (new): " ?nid crlf))


;;; ===========================================
;;; ALERT GENERATION RULES (Lower Salience: 100-130)
;;; ===========================================

;;; CRITICAL Alert: Score >= 4 (4-5 rules triggered)
(defrule R-PRBA-Alert-Critical
   "PRBA/UVM: Generate CRITICAL alert for Sinkhole attack"
   (declare (salience 130))
   
   (sinkhole-suspicion-class 
      (node-id ?nid)
      (suspicion-level "CRITICAL")
      (suspicion-score ?score)
      (bidirectional-flag ?bf)
      (freq-bidirect-flag ?ff)
      (power-anomaly-flag ?pf)
      (dio-frequency-flag ?df)
      (rank-harmony-flag ?rf)
      (evidence ?ev))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "Sinkhole-PRBA") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Sinkhole-PRBA")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "SINKHOLE CONFIRMED: Node " ?nid " - " ?score "/5 rules triggered (Critical confidence)"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Sinkhole-PRBA-Critical")
      (trigger-condition (str-cat "Score=" ?score "/5 [BD=" ?bf ",FBD=" ?ff ",PWR=" ?pf ",DIO=" ?df ",RH=" ?rf "]"))
      (conclusion "CRITICAL: Sinkhole attack confirmed with multiple indicators")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Sinkhole-PRBA")
      (node-id ?nid)
      (explanation (str-cat "Multiple Sinkhole indicators detected (" ?score "/5 rules). Immediate action required."))
      (evidence ?ev)))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "ISOLATE_NODE")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "URGENT: Isolate confirmed Sinkhole node " ?nid " immediately"))))
   
   (printout t ">>> [SINKHOLE] CRITICAL ALERT: " ?nid " Score=" ?score "/5" crlf))


;;; HIGH Alert: Score = 3
(defrule R-PRBA-Alert-High
   "PRBA/UVM: Generate HIGH alert for probable Sinkhole attack"
   (declare (salience 125))
   
   (sinkhole-suspicion-class 
      (node-id ?nid)
      (suspicion-level "HIGH")
      (suspicion-score ?score)
      (bidirectional-flag ?bf)
      (freq-bidirect-flag ?ff)
      (power-anomaly-flag ?pf)
      (dio-frequency-flag ?df)
      (rank-harmony-flag ?rf)
      (evidence ?ev))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "Sinkhole-PRBA") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Sinkhole-PRBA")
      (node-id ?nid)
      (severity "HIGH")
      (message (str-cat "SINKHOLE PROBABLE: Node " ?nid " - " ?score "/5 rules triggered"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Sinkhole-PRBA-High")
      (trigger-condition (str-cat "Score=" ?score "/5 [BD=" ?bf ",FBD=" ?ff ",PWR=" ?pf ",DIO=" ?df ",RH=" ?rf "]"))
      (conclusion "HIGH: Probable Sinkhole attack - monitor closely")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Sinkhole-PRBA")
      (node-id ?nid)
      (explanation (str-cat "Probable Sinkhole attack (" ?score "/5 rules triggered). Enhanced monitoring recommended."))
      (evidence ?ev)))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "MONITOR_NODE")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Monitor node " ?nid " closely and prepare isolation if behavior continues"))))
   
   (printout t ">>> [SINKHOLE] HIGH ALERT: " ?nid " Score=" ?score "/5" crlf))


;;; MEDIUM Alert: Score = 2
(defrule R-PRBA-Alert-Medium
   "PRBA/UVM: Generate MEDIUM alert for suspected Sinkhole activity"
   (declare (salience 120))
   
   (sinkhole-suspicion-class 
      (node-id ?nid)
      (suspicion-level "MEDIUM")
      (suspicion-score ?score)
      (bidirectional-flag ?bf)
      (freq-bidirect-flag ?ff)
      (power-anomaly-flag ?pf)
      (dio-frequency-flag ?df)
      (rank-harmony-flag ?rf)
      (evidence ?ev))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (attack-alert (attack-type "Sinkhole-PRBA") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Sinkhole-PRBA")
      (node-id ?nid)
      (severity "MEDIUM")
      (message (str-cat "SINKHOLE SUSPECTED: Node " ?nid " - " ?score "/5 rules triggered"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Sinkhole-PRBA-Medium")
      (trigger-condition (str-cat "Score=" ?score "/5 [BD=" ?bf ",FBD=" ?ff ",PWR=" ?pf ",DIO=" ?df ",RH=" ?rf "]"))
      (conclusion "MEDIUM: Suspected Sinkhole activity - continue monitoring")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Sinkhole-PRBA")
      (node-id ?nid)
      (explanation (str-cat "Suspected Sinkhole activity (" ?score "/5 rules). Continue monitoring for additional indicators."))
      (evidence ?ev)))
   
   (printout t ">>> [SINKHOLE] MEDIUM ALERT: " ?nid " Score=" ?score "/5" crlf))


;;; LOW Alert: Score = 1 (single indicator)
(defrule R-PRBA-Alert-Low
   "PRBA/UVM: Generate LOW alert for minimal Sinkhole indicators"
   (declare (salience 115))
   
   (sinkhole-suspicion-class 
      (node-id ?nid)
      (suspicion-level "LOW")
      (suspicion-score ?score)
      (bidirectional-flag ?bf)
      (freq-bidirect-flag ?ff)
      (power-anomaly-flag ?pf)
      (dio-frequency-flag ?df)
      (rank-harmony-flag ?rf)
      (evidence ?ev))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (attack-alert (attack-type "Sinkhole-PRBA") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Sinkhole-PRBA")
      (node-id ?nid)
      (severity "LOW")
      (message (str-cat "SINKHOLE INDICATOR: Node " ?nid " - " ?score "/5 rule triggered (minimal)"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Sinkhole-PRBA-Low")
      (trigger-condition (str-cat "Score=" ?score "/5 [BD=" ?bf ",FBD=" ?ff ",PWR=" ?pf ",DIO=" ?df ",RH=" ?rf "]"))
      (conclusion "LOW: Single Sinkhole indicator - log and monitor")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Sinkhole-PRBA")
      (node-id ?nid)
      (explanation (str-cat "Single Sinkhole indicator detected (" ?score "/5). May be normal variation, logging for trend analysis."))
      (evidence ?ev)))
   
   (printout t ">>> [SINKHOLE] LOW ALERT: " ?nid " Score=" ?score "/5" crlf))


;;;============================================
;;; SECTION 4: RF MULTI-ATTACK DETECTION (Reference [11])
;;; Random Forest-based Multi-Attack Detection with Conflict Resolution
;;;
;;; RF Detection Rules (5 Rules):
;;; Rule 1: IF PDRR > threshold THEN Selective Forwarding
;;; Rule 2: IF DPR > threshold AND PFR > threshold THEN DoS Attack  
;;; Rule 3: IF Node-Rank ≠ Expected_Rank THEN Rank Attack
;;; Rule 4: IF DIO_Counter > T_DIO THEN Hello Flood Attack
;;; Rule 5: IF DIS_Counter > T_DIS THEN DIS Flooding Attack
;;;
;;; Conflict Resolution Strategy:
;;; - Priority: DoS (highest) > SelectiveForwarding > RankAttack > HelloFlood > DIS-Flooding
;;; - Use intermediate classification fact to resolve conflicts
;;;============================================

;;; RF Attack Classification Template
(deftemplate rf-attack-class
   "Intermediate fact for RF multi-attack classification"
   (slot node-id (type STRING))
   (slot attack-type (type STRING))          ; SelectiveForwarding, DoS, RankAttack, HelloFlood, DIS-Flooding
   (slot severity (type STRING))             ; CRITICAL, HIGH, MEDIUM
   (slot confidence (type FLOAT))            ; 0.0 - 1.0
   (slot primary-indicator (type STRING))    ; Which indicator triggered detection
   (slot evidence (type STRING)))

;;; ===========================================
;;; RULE 1: Selective Forwarding Detection
;;; IF PDRR > threshold THEN Selective Forwarding
;;; ===========================================
(defrule R-RF-1-SelectiveForwarding-Classify
   "RF Rule 1: Classify Selective Forwarding based on PDRR threshold"
   (declare (salience 150))
   
   (pdrr-record 
      (node-id ?nid) 
      (rate ?rate) 
      (threshold ?th))
   
   (not (rf-attack-class (node-id ?nid)))
   
   =>
   
   (if (> ?rate ?th) then
      ;; PDRR exceeds threshold - Selective Forwarding
      (bind ?confidence (min 1.0 (/ ?rate (max 1.0 ?th))))
      (assert (rf-attack-class
         (node-id ?nid)
         (attack-type "SelectiveForwarding")
         (severity "HIGH")
         (confidence ?confidence)
         (primary-indicator "PDRR")
         (evidence (str-cat "PDRR(" ?rate ") > threshold(" ?th ")"))))
      (printout t ">>> [RF-Classify] Node " ?nid ": SelectiveForwarding (PDRR=" ?rate ">" ?th ")" crlf)
   else
      ;; Normal - no anomaly detected
      (assert (rf-attack-class
         (node-id ?nid)
         (attack-type "Normal")
         (severity "NONE")
         (confidence 0.9)
         (primary-indicator "PDRR")
         (evidence (str-cat "PDRR(" ?rate ") <= threshold(" ?th ") - Normal"))))
      (printout t ">>> [RF-Classify] Node " ?nid ": Normal (PDRR within threshold)" crlf)))

;;; ===========================================
;;; RULE 2: DoS Attack Detection (Higher Priority)
;;; IF DPR > threshold AND PFR > threshold THEN DoS Attack
;;; ===========================================
(defrule R-RF-2-DoS-Classify
   "RF Rule 2: Classify DoS Attack based on DPR AND PFR thresholds"
   (declare (salience 155))  ; Higher priority than SelectiveForwarding
   
   (dpr-record 
      (node-id ?nid) 
      (rate ?dpr) 
      (threshold ?dpr-th))
   (pfr-record 
      (node-id ?nid) 
      (rate ?pfr) 
      (threshold ?pfr-th))
   
   (not (rf-attack-class (node-id ?nid)))
   
   =>
   
   (if (and (> ?dpr ?dpr-th) (> ?pfr ?pfr-th)) then
      ;; Both thresholds exceeded - DoS Attack (CRITICAL)
      (bind ?confidence (min 1.0 (* 0.5 (+ (/ ?dpr (max 1.0 ?dpr-th)) (/ ?pfr (max 1.0 ?pfr-th))))))
      (assert (rf-attack-class
         (node-id ?nid)
         (attack-type "DoS")
         (severity "CRITICAL")
         (confidence ?confidence)
         (primary-indicator "DPR+PFR")
         (evidence (str-cat "DPR(" ?dpr ")>" ?dpr-th " AND PFR(" ?pfr ")>" ?pfr-th))))
      (printout t ">>> [RF-Classify] Node " ?nid ": DoS Attack (DPR=" ?dpr ", PFR=" ?pfr ")" crlf)
   else
      ;; Partial condition or normal
      (if (> ?dpr ?dpr-th) then
         ;; Only DPR exceeded - suspicious but not confirmed DoS
         (assert (rf-attack-class
            (node-id ?nid)
            (attack-type "Suspicious")
            (severity "MEDIUM")
            (confidence 0.6)
            (primary-indicator "DPR")
            (evidence (str-cat "DPR(" ?dpr ")>" ?dpr-th " only - partial DoS indicator"))))
      else (if (> ?pfr ?pfr-th) then
         ;; Only PFR exceeded
         (assert (rf-attack-class
            (node-id ?nid)
            (attack-type "Suspicious")
            (severity "MEDIUM")
            (confidence 0.5)
            (primary-indicator "PFR")
            (evidence (str-cat "PFR(" ?pfr ")>" ?pfr-th " only - partial DoS indicator"))))
      else
         ;; Both within thresholds
         (assert (rf-attack-class
            (node-id ?nid)
            (attack-type "Normal")
            (severity "NONE")
            (confidence 0.9)
            (primary-indicator "DPR+PFR")
            (evidence (str-cat "DPR(" ?dpr ")<=" ?dpr-th " AND PFR(" ?pfr ")<=" ?pfr-th " - Normal"))))))))

;;; ===========================================
;;; RULE 3: Rank Attack Detection
;;; IF Node-Rank ≠ Expected_Rank THEN Rank Attack
;;; ===========================================
(defrule R-RF-3-RankAttack-Classify
   "RF Rule 3: Classify Rank Attack based on rank mismatch"
   (declare (salience 145))
   
   (node-rank-history 
      (node-id ?nid)
      (previous-rank ?prev)
      (current-rank ?curr)
      (timestamp ?ts))
   
   (not (rf-attack-class (node-id ?nid)))
   
   =>
   
   (if (and (> ?prev 0) (< ?curr (/ ?prev 2))) then
      ;; Rank decreased by more than 50% - Rank Attack
      (bind ?drop-ratio (/ (- ?prev ?curr) ?prev))
      (bind ?confidence (min 1.0 (* 2.0 ?drop-ratio)))
      (assert (rf-attack-class
         (node-id ?nid)
         (attack-type "RankAttack")
         (severity "HIGH")
         (confidence ?confidence)
         (primary-indicator "Rank-Mismatch")
         (evidence (str-cat "Rank: " ?prev " -> " ?curr " (dropped " (round (* 100 ?drop-ratio)) "%)"))))
      (printout t ">>> [RF-Classify] Node " ?nid ": Rank Attack (Rank " ?prev "->" ?curr ")" crlf)
   else
      ;; Rank within normal variation
      (assert (rf-attack-class
         (node-id ?nid)
         (attack-type "Normal")
         (severity "NONE")
         (confidence 0.85)
         (primary-indicator "Rank")
         (evidence (str-cat "Rank change " ?prev " -> " ?curr " within normal range"))))))

;;; ===========================================
;;; RULE 4: Hello Flood Attack Detection
;;; IF DIO_Counter > T_DIO THEN Hello Flood Attack
;;; ===========================================
(defrule R-RF-4-HelloFlood-Classify
   "RF Rule 4: Classify Hello Flood based on DIO counter threshold"
   (declare (salience 140))
   
   (control-message-counter 
      (node-id ?nid) 
      (dio-count ?dio) 
      (dis-count ?dis) 
      (dao-count ?dao)
      (dio-threshold ?dio-th) 
      (dis-threshold ?dis-th) 
      (dao-threshold ?dao-th))
   
   (not (rf-attack-class (node-id ?nid)))
   
   =>
   
   (if (> ?dio ?dio-th) then
      ;; DIO count exceeds threshold - Hello Flood
      (bind ?confidence (min 1.0 (/ ?dio (max 1.0 ?dio-th))))
      (assert (rf-attack-class
         (node-id ?nid)
         (attack-type "HelloFlood")
         (severity "HIGH")
         (confidence ?confidence)
         (primary-indicator "DIO-Counter")
         (evidence (str-cat "DIO_Counter(" ?dio ") > T_DIO(" ?dio-th ")"))))
      (printout t ">>> [RF-Classify] Node " ?nid ": Hello Flood (DIO=" ?dio ">" ?dio-th ")" crlf)
   else (if (> ?dis ?dis-th) then
      ;; DIS count exceeds threshold - DIS Flooding (Rule 5)
      (bind ?confidence (min 1.0 (/ ?dis (max 1.0 ?dis-th))))
      (assert (rf-attack-class
         (node-id ?nid)
         (attack-type "DIS-Flooding")
         (severity "HIGH")
         (confidence ?confidence)
         (primary-indicator "DIS-Counter")
         (evidence (str-cat "DIS_Counter(" ?dis ") > T_DIS(" ?dis-th ")"))))
      (printout t ">>> [RF-Classify] Node " ?nid ": DIS Flooding (DIS=" ?dis ">" ?dis-th ")" crlf)
   else (if (> ?dao ?dao-th) then
      ;; DAO count exceeds threshold - DAO Flooding
      (bind ?confidence (min 1.0 (/ ?dao (max 1.0 ?dao-th))))
      (assert (rf-attack-class
         (node-id ?nid)
         (attack-type "DAO-Flooding")
         (severity "MEDIUM")
         (confidence ?confidence)
         (primary-indicator "DAO-Counter")
         (evidence (str-cat "DAO_Counter(" ?dao ") > T_DAO(" ?dao-th ")"))))
      (printout t ">>> [RF-Classify] Node " ?nid ": DAO Flooding (DAO=" ?dao ">" ?dao-th ")" crlf)
   else
      ;; All counters within thresholds
      (assert (rf-attack-class
         (node-id ?nid)
         (attack-type "Normal")
         (severity "NONE")
         (confidence 0.9)
         (primary-indicator "ControlMsg")
         (evidence (str-cat "All counters normal: DIO=" ?dio ", DIS=" ?dis ", DAO=" ?dao))))))))

;;; ===========================================
;;; RF Attack Alert Generation Rules
;;; Generate alerts based on classification with conflict resolution
;;; ===========================================

;;; Alert for Selective Forwarding
(defrule R-RF-Alert-SelectiveForwarding
   "Generate alert for Selective Forwarding attack"
   (declare (salience 120))
   
   (rf-attack-class 
      (node-id ?nid) 
      (attack-type "SelectiveForwarding")
      (severity ?sev)
      (confidence ?conf)
      (evidence ?ev))
   
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
      (severity ?sev)
      (message (str-cat "RF Detection: Selective Forwarding Attack - Node " ?nid " [Confidence: " (round (* 100 ?conf)) "%]"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "RF-SelectiveForwarding")
      (trigger-condition ?ev)
      (conclusion "Send message (Selective Forwarding, NodeID) to Sink")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "SelectiveForwarding")
      (node-id ?nid)
      (explanation "RF Rule 1: PDRR exceeds threshold indicating selective packet dropping")
      (evidence ?ev)))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "REROUTE")
      (target-node ?nid)
      (priority ?sev)
      (description (str-cat "Bypass node " ?nid " and establish alternative routing path"))))
   
   (printout t ">>> [RF-ALERT] Selective Forwarding Attack detected: Node " ?nid crlf))

;;; Alert for DoS Attack (Highest Priority)
(defrule R-RF-Alert-DoS
   "Generate alert for DoS attack"
   (declare (salience 125))  ; Highest alert priority
   
   (rf-attack-class 
      (node-id ?nid) 
      (attack-type "DoS")
      (severity ?sev)
      (confidence ?conf)
      (evidence ?ev))
   
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
      (severity ?sev)
      (message (str-cat "RF Detection: DoS Attack - Node " ?nid " [Confidence: " (round (* 100 ?conf)) "%]"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "RF-DoS-Attack")
      (trigger-condition ?ev)
      (conclusion "Send message (DoS attack, NodeID) to Sink - CRITICAL")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "DoS")
      (node-id ?nid)
      (explanation "RF Rule 2: Both DPR and PFR exceed thresholds indicating coordinated DoS attack")
      (evidence ?ev)))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "RATE_LIMIT")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Apply strict rate limiting to node " ?nid " and notify Sink immediately"))))
   
   (printout t ">>> [RF-ALERT] DoS Attack detected: Node " ?nid " - CRITICAL" crlf))

;;; Alert for Rank Attack
(defrule R-RF-Alert-RankAttack
   "Generate alert for Rank Attack"
   (declare (salience 115))
   
   (rf-attack-class 
      (node-id ?nid) 
      (attack-type "RankAttack")
      (severity ?sev)
      (confidence ?conf)
      (evidence ?ev))
   
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
      (severity ?sev)
      (message (str-cat "RF Detection: Rank Attack - Node " ?nid " [Confidence: " (round (* 100 ?conf)) "%]"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "RF-RankAttack")
      (trigger-condition ?ev)
      (conclusion "Send message (Rank-attack, NodeID) to Sink")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "RankAttack")
      (node-id ?nid)
      (explanation "RF Rule 3: Node-Rank mismatch detected, possible rank forgery to attract traffic")
      (evidence ?ev)))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "VERIFY_RANK")
      (target-node ?nid)
      (priority ?sev)
      (description (str-cat "Verify legitimacy of node " ?nid " Rank value and reset if necessary"))))
   
   (printout t ">>> [RF-ALERT] Rank Attack detected: Node " ?nid crlf))

;;; Alert for Hello Flood Attack
(defrule R-RF-Alert-HelloFlood
   "Generate alert for Hello Flood attack"
   (declare (salience 110))
   
   (rf-attack-class 
      (node-id ?nid) 
      (attack-type "HelloFlood")
      (severity ?sev)
      (confidence ?conf)
      (evidence ?ev))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "HelloFlood") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "HelloFlood")
      (node-id ?nid)
      (severity ?sev)
      (message (str-cat "RF Detection: Hello Flood Attack - Node " ?nid " [Confidence: " (round (* 100 ?conf)) "%]"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "RF-HelloFlood")
      (trigger-condition ?ev)
      (conclusion "Generate alert (Hello Flood Attack)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "HelloFlood")
      (node-id ?nid)
      (explanation "RF Rule 4: DIO_Counter exceeds threshold indicating Hello Flood attack")
      (evidence ?ev)))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "RATE_LIMIT")
      (target-node ?nid)
      (priority ?sev)
      (description (str-cat "Apply DIO message rate limiting to node " ?nid))))
   
   (printout t ">>> [RF-ALERT] Hello Flood Attack detected: Node " ?nid crlf))

;;; Alert for DIS Flooding Attack
(defrule R-RF-Alert-DISFlooding
   "Generate alert for DIS Flooding attack"
   (declare (salience 105))
   
   (rf-attack-class 
      (node-id ?nid) 
      (attack-type "DIS-Flooding")
      (severity ?sev)
      (confidence ?conf)
      (evidence ?ev))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "DIS-Flooding") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "DIS-Flooding")
      (node-id ?nid)
      (severity ?sev)
      (message (str-cat "RF Detection: DIS Flooding Attack - Node " ?nid " [Confidence: " (round (* 100 ?conf)) "%]"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "RF-DISFlooding")
      (trigger-condition ?ev)
      (conclusion "Generate alert (DIS Flooding Attack)")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "DIS-Flooding")
      (node-id ?nid)
      (explanation "RF Rule 5: DIS_Counter exceeds threshold indicating DIS Flooding attack")
      (evidence ?ev)))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "RATE_LIMIT")
      (target-node ?nid)
      (priority ?sev)
      (description (str-cat "Apply DIS message rate limiting to node " ?nid))))
   
   (printout t ">>> [RF-ALERT] DIS Flooding Attack detected: Node " ?nid crlf))

;;; Alert for Suspicious Activity (Partial Indicators)
(defrule R-RF-Alert-Suspicious
   "Generate alert for suspicious activity with partial indicators"
   (declare (salience 100))
   
   (rf-attack-class 
      (node-id ?nid) 
      (attack-type "Suspicious")
      (severity ?sev)
      (confidence ?conf)
      (primary-indicator ?ind)
      (evidence ?ev))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (attack-alert (attack-type "Suspicious") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "Suspicious")
      (node-id ?nid)
      (severity ?sev)
      (message (str-cat "RF Detection: Suspicious Activity - Node " ?nid " (" ?ind ") [Confidence: " (round (* 100 ?conf)) "%]"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "RF-Suspicious")
      (trigger-condition ?ev)
      (conclusion "Monitor node for potential escalation")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "Suspicious")
      (node-id ?nid)
      (explanation "Partial attack indicators detected, requires monitoring")
      (evidence ?ev)))
   
   (printout t ">>> [RF-ALERT] Suspicious Activity: Node " ?nid " (" ?ind ")" crlf))


;;;============================================
;;; SECTION 5: XAI ANOMALY DETECTION (Reference [6])
;;; Isolation Forest-based Anomaly Detection with Conflict Resolution
;;;
;;; CONFLICT RESOLUTION STRATEGY:
;;; 1. Calculate anomaly score based on rule matches
;;; 2. Classification with specific attack type identification:
;;;    - Sinkhole: Rule 1 (NPC<=1.62, NC>1.74, UDP_recv>11.62)
;;;    - Blackhole: Rule 4 (NPC>0.37, NC<=2.44, UDP_trans>1.62, PF<=0.58)
;;;    - Generic Anomaly: Rules 2,3,5
;;; 3. Salience priority: Sinkhole/Blackhole(120) > Generic(110)
;;;
;;; LITERATURE RULES:
;;; Rule 1: NPC<=1.62 AND NC>1.74 AND UDP_recv>11.62 → Sinkhole
;;; Rule 2: 0.80<NPC<=2.33 AND NC<=3.64 AND UDP_recv>16.44 → Anomaly
;;; Rule 3: NPC<=1.62 AND NC>1.74 AND UDP_fwd<=0.43 AND UDP_trans<=2.67 → Anomaly
;;; Rule 4: NPC>0.37 AND NC<=2.44 AND UDP_trans>1.62 AND PF<=0.58 → Blackhole
;;; Rule 5: NPC>0.37 AND NC>2.57 AND UDP_recv>13.49 AND PF<=0.28 → Anomaly
;;;============================================

;;; XAI Anomaly Classification Template
(deftemplate xai-anomaly-class
   "XAI Anomaly Classification"
   (slot node-id (type STRING))
   (slot rule-matched (type INTEGER))
   (slot attack-type (type SYMBOL) (allowed-symbols Sinkhole Blackhole Anomaly Normal))
   (slot npc (type FLOAT))
   (slot nc (type FLOAT))
   (slot udp-recv (type FLOAT))
   (slot udp-trans (type FLOAT))
   (slot udp-fwd (type FLOAT))
   (slot pf-rate (type FLOAT)))

;;;--------------------------------------------
;;; PHASE 1: Calculate XAI Classification (salience 150)
;;;--------------------------------------------
(defrule R-XAI-CalcClass
   "XAI: Calculate Anomaly Classification"
   (declare (salience 150))
   
   (npc-record (node-id ?nid) (count ?npc))
   (nc-record (node-id ?nid) (count ?nc))
   (udp-received (node-id ?nid) (count ?udp-r))
   (udp-transmitted (node-id ?nid) (count ?udp-t))
   (udp-forwarded (node-id ?nid) (count ?udp-f))
   (packet-forwarding (node-id ?nid) (rate ?pf))
   
   (not (xai-anomaly-class (node-id ?nid)))
   
   =>
   
   ;; Determine which rule matches (priority: Sinkhole > Blackhole > Anomaly)
   (bind ?rule 0)
   (bind ?type Normal)
   
   ;; Rule 1: Sinkhole - NPC<=1.62 AND NC>1.74 AND UDP_recv>11.62
   (if (and (<= ?npc 1.62) (> ?nc 1.74) (> ?udp-r 11.62))
      then (bind ?rule 1) (bind ?type Sinkhole))
   
   ;; Rule 4: Blackhole - NPC>0.37 AND NC<=2.44 AND UDP_trans>1.62 AND PF<=0.58
   (if (and (eq ?type Normal) (> ?npc 0.37) (<= ?nc 2.44) (> ?udp-t 1.62) (<= ?pf 0.58))
      then (bind ?rule 4) (bind ?type Blackhole))
   
   ;; Rule 2: Anomaly - 0.80<NPC<=2.33 AND NC<=3.64 AND UDP_recv>16.44
   (if (and (eq ?type Normal) (> ?npc 0.80) (<= ?npc 2.33) (<= ?nc 3.64) (> ?udp-r 16.44))
      then (bind ?rule 2) (bind ?type Anomaly))
   
   ;; Rule 3: Anomaly - NPC<=1.62 AND NC>1.74 AND UDP_fwd<=0.43 AND UDP_trans<=2.67
   (if (and (eq ?type Normal) (<= ?npc 1.62) (> ?nc 1.74) (<= ?udp-f 0.43) (<= ?udp-t 2.67))
      then (bind ?rule 3) (bind ?type Anomaly))
   
   ;; Rule 5: Anomaly - NPC>0.37 AND NC>2.57 AND UDP_recv>13.49 AND PF<=0.28
   (if (and (eq ?type Normal) (> ?npc 0.37) (> ?nc 2.57) (> ?udp-r 13.49) (<= ?pf 0.28))
      then (bind ?rule 5) (bind ?type Anomaly))
   
   (assert (xai-anomaly-class
      (node-id ?nid)
      (rule-matched ?rule)
      (attack-type ?type)
      (npc ?npc)
      (nc ?nc)
      (udp-recv ?udp-r)
      (udp-trans ?udp-t)
      (udp-fwd ?udp-f)
      (pf-rate ?pf)))
   
   (printout t ">>> [XAI-Class] Node " ?nid ": Rule=" ?rule " Type=" ?type crlf))


;;;--------------------------------------------
;;; PHASE 2: Sinkhole Detection (Highest Priority - salience 120)
;;; Rule 1: NPC<=1.62 AND NC>1.74 AND UDP_recv>11.62
;;;--------------------------------------------
(defrule R-XAI-Sinkhole
   "XAI: Sinkhole Attack Detection (Rule 1)"
   (declare (salience 120))
   
   (xai-anomaly-class (node-id ?nid) (rule-matched 1) (attack-type Sinkhole)
                      (npc ?npc) (nc ?nc) (udp-recv ?udp-r))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "XAI-Sinkhole") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "XAI-Sinkhole")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "XAI Sinkhole: Node " ?nid " [Rule1] NPC=" ?npc " NC=" ?nc " UDP_recv=" ?udp-r))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "XAI-Sinkhole-Detection")
      (trigger-condition (str-cat "Rule1: NPC<=1.62(" ?npc ") AND NC>1.74(" ?nc ") AND UDP_recv>11.62(" ?udp-r ")"))
      (conclusion "Sinkhole Attack Detected via Isolation Forest")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "XAI-Sinkhole")
      (node-id ?nid)
      (explanation "Conflict Resolution: Rule 1 matched - Low parent changes with high child count and UDP traffic indicates Sinkhole")
      (evidence (str-cat "NPC=" ?npc ",NC=" ?nc ",UDP_recv=" ?udp-r))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "ISOLATE_NODE")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Isolate potential Sinkhole node " ?nid " - attracting traffic"))))
   
   (printout t ">>> [XAI] SINKHOLE Detected: " ?nid crlf))


;;;--------------------------------------------
;;; PHASE 2: Blackhole Detection (salience 120)
;;; Rule 4: NPC>0.37 AND NC<=2.44 AND UDP_trans>1.62 AND PF<=0.58
;;;--------------------------------------------
(defrule R-XAI-Blackhole
   "XAI: Blackhole Attack Detection (Rule 4)"
   (declare (salience 120))
   
   (xai-anomaly-class (node-id ?nid) (rule-matched 4) (attack-type Blackhole)
                      (npc ?npc) (nc ?nc) (udp-trans ?udp-t) (pf-rate ?pf))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "XAI-Blackhole") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "XAI-Blackhole")
      (node-id ?nid)
      (severity "CRITICAL")
      (message (str-cat "XAI Blackhole: Node " ?nid " [Rule4] NPC=" ?npc " NC=" ?nc " UDP_trans=" ?udp-t " PF=" ?pf))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "XAI-Blackhole-Detection")
      (trigger-condition (str-cat "Rule4: NPC>0.37(" ?npc ") AND NC<=2.44(" ?nc ") AND UDP_trans>1.62(" ?udp-t ") AND PF<=0.58(" ?pf ")"))
      (conclusion "Blackhole Attack Detected via Isolation Forest")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "XAI-Blackhole")
      (node-id ?nid)
      (explanation "Conflict Resolution: Rule 4 matched - Low forwarding rate with active transmission indicates Blackhole")
      (evidence (str-cat "NPC=" ?npc ",NC=" ?nc ",UDP_trans=" ?udp-t ",PF=" ?pf))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "BLOCK_PERMANENT")
      (target-node ?nid)
      (priority "CRITICAL")
      (description (str-cat "Block Blackhole node " ?nid " - dropping packets"))))
   
   (printout t ">>> [XAI] BLACKHOLE Detected: " ?nid crlf))


;;;--------------------------------------------
;;; PHASE 2: Generic Anomaly Detection (salience 110)
;;; Rules 2,3,5: Various anomaly patterns
;;;--------------------------------------------
(defrule R-XAI-Anomaly
   "XAI: Generic Anomaly Detection (Rules 2,3,5)"
   (declare (salience 110))
   
   (xai-anomaly-class (node-id ?nid) (rule-matched ?rule&:(and (> ?rule 0) (neq ?rule 1) (neq ?rule 4)))
                      (attack-type Anomaly) (npc ?npc) (nc ?nc) 
                      (udp-recv ?udp-r) (udp-trans ?udp-t) (udp-fwd ?udp-f) (pf-rate ?pf))
   
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
      (message (str-cat "XAI Anomaly: Node " ?nid " [Rule" ?rule "] detected anomalous pattern"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "XAI-Anomaly-Detection")
      (trigger-condition (str-cat "Rule" ?rule ": NPC=" ?npc " NC=" ?nc " UDP_recv=" ?udp-r " UDP_trans=" ?udp-t " UDP_fwd=" ?udp-f " PF=" ?pf))
      (conclusion "Anomaly Detected via Isolation Forest")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "XAI-Anomaly")
      (node-id ?nid)
      (explanation (str-cat "Conflict Resolution: Rule " ?rule " matched - Unusual behavior pattern detected"))
      (evidence (str-cat "NPC=" ?npc ",NC=" ?nc ",UDP_recv=" ?udp-r ",UDP_trans=" ?udp-t ",UDP_fwd=" ?udp-f ",PF=" ?pf))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "QUARANTINE")
      (target-node ?nid)
      (priority "HIGH")
      (description (str-cat "Quarantine anomalous node " ?nid " for investigation"))))
   
   (printout t ">>> [XAI] ANOMALY Rule" ?rule " Detected: " ?nid crlf))


;;;--------------------------------------------
;;; PHASE 2: Normal Classification (Lowest Priority - salience 100)
;;; No rule matched
;;;--------------------------------------------
(defrule R-XAI-Normal
   "XAI: Normal Node - No anomaly detected"
   (declare (salience 100))
   
   (xai-anomaly-class (node-id ?nid) (rule-matched 0) (attack-type Normal))
   
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   
   (not (inference-path (rule-name "XAI-Normal-Check") (node-id ?nid)))
   
   =>
   
   (retract ?step-counter)
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "XAI-Normal-Check")
      (trigger-condition "No XAI anomaly rule matched")
      (conclusion "Normal Behavior - No Anomaly Detected")
      (node-id ?nid)
      (timestamp 0)))
   
   (printout t ">>> [XAI] NORMAL: " ?nid crlf))


;;;============================================
;;; SECTION 6: UVM VOTING METHOD (Reference [14])
;;; NOTE: UVM rules (DIO Frequency and Rank Harmony) have been integrated
;;; into SECTION 3 (PRBA/UVM Sinkhole Detection) with conflict resolution.
;;; 
;;; The integrated approach combines all 5 Sinkhole detection rules:
;;; - Rule 1: Bidirectional Behavior
;;; - Rule 2: Frequent Bidirectional Events  
;;; - Rule 3: Power Consumption Anomaly
;;; - Rule 4: DIO Frequency Anomaly (from UVM)
;;; - Rule 5: Rank Harmony Anomaly (from UVM)
;;;
;;; Legacy voting-result based detection is kept for backward compatibility
;;; with manual voting result injection.
;;;============================================

;;; R_UVM_Legacy: Voting Decision (Backward Compatibility)
;;; This rule allows direct injection of voting-result for testing
(defrule R-UVM-Legacy-VotingDecision
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
   ;; Don't fire if PRBA already detected
   (not (attack-alert (attack-type "Sinkhole-PRBA") (node-id ?nid)))
   
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
;;; SECTION 7: HYBRID IDS (Reference [13])
;;; Hybrid Intrusion Detection System with Conflict Resolution
;;;
;;; Note: HelloFlood and DIS-Flooding detection is now handled by 
;;; SECTION 4 (RF Multi-Attack Detection) with conflict resolution.
;;; This section handles additional hybrid detection methods.
;;;============================================

;;; R_Hybrid_1: DAO Flooding Attack (DAO-specific, complements RF rules)
;;; Only fires if RF detection hasn't already classified the node
(defrule R-Hybrid-1-DAOFlood
   "Hybrid IDS: DAO Flooding Attack Detection"
   (declare (salience 95))  ; Lower than RF rules
   
   (control-message-counter 
      (node-id ?nid) 
      (dio-count ?dio) 
      (dis-count ?dis) 
      (dao-count ?dao)
      (dio-threshold ?dio-th) 
      (dis-threshold ?dis-th) 
      (dao-threshold ?dao-th))
   
   ;; DAO exceeds threshold but DIO and DIS are normal (complementary to RF Rule 4&5)
   (test (and (> ?dao ?dao-th) (<= ?dio ?dio-th) (<= ?dis ?dis-th)))
   
   ;; No RF classification exists for this node (avoid conflict)
   (not (rf-attack-class (node-id ?nid)))
   
   ?counter <- (global-counter (counter-name "alert-id") (value ?aid))
   ?step-counter <- (global-counter (counter-name "step-id") (value ?sid))
   ?action-counter <- (global-counter (counter-name "action-id") (value ?actid))
   
   (not (attack-alert (attack-type "DAO-Flooding") (node-id ?nid)))
   
   =>
   
   (retract ?counter ?step-counter ?action-counter)
   (assert (global-counter (counter-name "alert-id") (value (+ ?aid 1))))
   (assert (global-counter (counter-name "step-id") (value (+ ?sid 1))))
   (assert (global-counter (counter-name "action-id") (value (+ ?actid 1))))
   
   (assert (attack-alert
      (alert-id (+ ?aid 1))
      (attack-type "DAO-Flooding")
      (node-id ?nid)
      (severity "MEDIUM")
      (message (str-cat "Hybrid IDS: DAO Flooding Attack - Node " ?nid " excessive DAO messages"))
      (timestamp 0)))
   
   (assert (inference-path
      (step-id (+ ?sid 1))
      (rule-name "Hybrid-DAOFlood")
      (trigger-condition (str-cat "DAO(" ?dao ")>T(" ?dao-th ") with normal DIO/DIS"))
      (conclusion "Generate alert: DAO Flooding Attack")
      (node-id ?nid)
      (timestamp 0)))
   
   (assert (reason
      (attack-type "DAO-Flooding")
      (node-id ?nid)
      (explanation "Detected DAO flooding - node sending excessive DAO messages to disrupt routing")
      (evidence (str-cat "DAO:" ?dao " (threshold:" ?dao-th ")"))))
   
   (assert (defense-action
      (action-id (+ ?actid 1))
      (action-type "RATE_LIMIT")
      (target-node ?nid)
      (priority "MEDIUM")
      (description (str-cat "Apply DAO message rate limiting to node " ?nid))))
   
   (printout t ">>> [Hybrid-IDS] DAO Flooding: " ?nid crlf))


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
;;; SECTION 8: SRPL-RP DEFENSE (Reference [2])
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
;;; SECTION 9: DISTRIBUTED IDS (Reference [10])
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
;;; SECTION 10: FLBT-RPL SYBIL DETECTION (Reference [12])
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
