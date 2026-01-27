"""
SAT Solver Verification for RPL Expert System Rules
====================================================
This script uses PySAT to verify the consistency and correctness
of the expert system rules converted to CNF format.

Usage:
    pip install python-sat
    python sat_verify.py

References:
    - PySAT: https://pysathq.github.io/
    - DIMACS CNF format
"""

from pysat.solvers import Glucose3, Minisat22
from pysat.formula import CNF
from typing import List, Dict, Tuple
import os

# ============================================================
# VARIABLE ENCODING (must match rpl_rules.cnf)
# Based on rpl_rules.clp - 10 literature sources
# ============================================================

# Input Variables (1-50)
VARS = {
    # DIO Level [Ref 9: FLSec-RPL]
    'DIO_High': 1, 'DIO_Medium': 2, 'DIO_Low': 3,
    # DTI Level [Ref 9: FLSec-RPL]
    'DTI_High': 4, 'DTI_Medium': 5, 'DTI_Low': 6,
    # STIA Level [Ref 9: FLSec-RPL]
    'STIA_High': 7, 'STIA_Medium': 8, 'STIA_Low': 9,
    # ETX Level [Ref 15: Jamming]
    'ETX_High': 10, 'ETX_Medium': 11, 'ETX_Low': 12,
    # Retransmission Level [Ref 15: Jamming]
    'RET_High': 13, 'RET_Medium': 14, 'RET_Low': 15,
    # Rank Change [Ref 2,3: SRPL-RP, PRBA]
    'RANK_Decrease': 16, 'RANK_Increase': 17, 'RANK_Normal': 18,
    # Drop Rate [Ref 11: Random Forest]
    'DROP_High': 19, 'DROP_Medium': 20, 'DROP_Low': 21,
    # DPR - Duplicate Packet Rate [Ref 11: Random Forest]
    'DPR_High': 22, 'DPR_Normal': 23,
    # PFR - Packet Forwarding Rate [Ref 11: Random Forest]
    'PFR_High': 24, 'PFR_Normal': 25,
    # Version Number [Ref 13: Hybrid IDS]
    'VN_Forged': 26, 'VN_Normal': 27,
    # Message Flood [Ref 11,13: RF, Hybrid]
    'MSG_Flood': 28, 'MSG_Normal': 29,
    # Sybil [Ref 12: FLBT-RPL]
    'SYBIL_Multi': 30, 'SYBIL_Single': 31,
    # Bidirectional Behavior [Ref 3: PRBA]
    'BIDIRECT_Yes': 32, 'BIDIRECT_No': 33,
    # Power Anomaly [Ref 3: PRBA]
    'POWER_High': 34, 'POWER_Normal': 35,
    # NPC - Number of Parent Changes [Ref 6: XAI]
    'NPC_Low': 36, 'NPC_Medium': 37, 'NPC_High': 38,
    # NC - Number of Children [Ref 6: XAI]
    'NC_Low': 39, 'NC_Medium': 40, 'NC_High': 41,
    # UDP Received [Ref 6: XAI]
    'UDP_High': 42, 'UDP_Normal': 43,
    # Packet Forwarding Rate [Ref 6: XAI]
    'PF_Low': 44, 'PF_Normal': 45,
    
    # Output Variables - Attack Classifications (101-120)
    'MALICIOUS': 101, 'QUARANTINE': 102, 'VICTIM': 103, 'NORMAL': 104,
    'JAM_HIGH': 105, 'JAM_MEDIUM': 106, 'JAM_LOW': 107, 'JAM_NONE': 108,
    'SINKHOLE': 109, 'RANK_ATTACK': 110, 'DOS': 111, 'SELECTIVE_FWD': 112,
    'HELLO_FLOOD': 113, 'VERSION_NUM': 114, 'SYBIL_ATTACK': 115,
    'XAI_SINKHOLE': 116, 'XAI_BLACKHOLE': 117, 'XAI_ANOMALY': 118,
    'DAO_FLOOD': 119, 'DIS_FLOOD': 120,
    
    # Defense Actions (201-210)
    'DEFENSE_BLOCK': 201, 'DEFENSE_ISOLATE': 202, 'DEFENSE_MONITOR': 203,
    'DEFENSE_RATE_LIMIT': 204, 'DEFENSE_CHANNEL_HOP': 205, 'DEFENSE_REROUTE': 206,
    'DEFENSE_VERIFY_RANK': 207, 'DEFENSE_VERIFY_VERSION': 208,
}

# Reverse mapping for output
VAR_NAMES = {v: k for k, v in VARS.items()}


def build_cnf_rules() -> List[List[int]]:
    """
    Build CNF clauses representing the expert system rules.
    Based on rpl_rules.clp with 10 literature sources.
    """
    clauses = []
    
    # ========== Mutual Exclusion Constraints ==========
    
    # DIO levels: exactly one must be true
    clauses.append([VARS['DIO_High'], VARS['DIO_Medium'], VARS['DIO_Low']])
    clauses.append([-VARS['DIO_High'], -VARS['DIO_Medium']])
    clauses.append([-VARS['DIO_High'], -VARS['DIO_Low']])
    clauses.append([-VARS['DIO_Medium'], -VARS['DIO_Low']])
    
    # DTI levels
    clauses.append([VARS['DTI_High'], VARS['DTI_Medium'], VARS['DTI_Low']])
    clauses.append([-VARS['DTI_High'], -VARS['DTI_Medium']])
    clauses.append([-VARS['DTI_High'], -VARS['DTI_Low']])
    clauses.append([-VARS['DTI_Medium'], -VARS['DTI_Low']])
    
    # STIA levels
    clauses.append([VARS['STIA_High'], VARS['STIA_Medium'], VARS['STIA_Low']])
    clauses.append([-VARS['STIA_High'], -VARS['STIA_Medium']])
    clauses.append([-VARS['STIA_High'], -VARS['STIA_Low']])
    clauses.append([-VARS['STIA_Medium'], -VARS['STIA_Low']])
    
    # ETX levels
    clauses.append([VARS['ETX_High'], VARS['ETX_Medium'], VARS['ETX_Low']])
    clauses.append([-VARS['ETX_High'], -VARS['ETX_Medium']])
    clauses.append([-VARS['ETX_High'], -VARS['ETX_Low']])
    clauses.append([-VARS['ETX_Medium'], -VARS['ETX_Low']])
    
    # Retransmission levels
    clauses.append([VARS['RET_High'], VARS['RET_Medium'], VARS['RET_Low']])
    clauses.append([-VARS['RET_High'], -VARS['RET_Medium']])
    clauses.append([-VARS['RET_High'], -VARS['RET_Low']])
    clauses.append([-VARS['RET_Medium'], -VARS['RET_Low']])
    
    # ========== SECTION 1: FLSec-RPL Rules [Ref 9] ==========
    # DIO Suppression Attack Detection using Threat Score
    # Score = DIO_weight + DTI_weight + STIA_weight
    # DIO: H=3, M=2, L=1 | DTI: L=3, M=2, H=1 | STIA: L=3, M=2, H=1
    
    # Rules for MALICIOUS (Score >= 8 AND STIA = Low)
    # Rule 1: DIO=H(3) + DTI=L(3) + STIA=L(3) = 9
    clauses.append([-VARS['DIO_High'], -VARS['DTI_Low'], -VARS['STIA_Low'], VARS['MALICIOUS']])
    # Rule 4: DIO=H(3) + DTI=M(2) + STIA=L(3) = 8
    clauses.append([-VARS['DIO_High'], -VARS['DTI_Medium'], -VARS['STIA_Low'], VARS['MALICIOUS']])
    # Rule 10: DIO=M(2) + DTI=L(3) + STIA=L(3) = 8
    clauses.append([-VARS['DIO_Medium'], -VARS['DTI_Low'], -VARS['STIA_Low'], VARS['MALICIOUS']])
    
    # Rules for QUARANTINE (Score >= 6 with edge cases, or Score = 7)
    # Rule 2: DIO=H(3) + DTI=L(3) + STIA=M(2) = 8, STIA≠L
    clauses.append([-VARS['DIO_High'], -VARS['DTI_Low'], -VARS['STIA_Medium'], VARS['QUARANTINE']])
    # Rule 3: DIO=H(3) + DTI=L(3) + STIA=H(1) = 7
    clauses.append([-VARS['DIO_High'], -VARS['DTI_Low'], -VARS['STIA_High'], VARS['QUARANTINE']])
    # Rule 5: DIO=H(3) + DTI=M(2) + STIA=M(2) = 7
    clauses.append([-VARS['DIO_High'], -VARS['DTI_Medium'], -VARS['STIA_Medium'], VARS['QUARANTINE']])
    # Rule 7: DIO=H(3) + DTI=H(1) + STIA=L(3) = 7
    clauses.append([-VARS['DIO_High'], -VARS['DTI_High'], -VARS['STIA_Low'], VARS['QUARANTINE']])
    # Rule 11: DIO=M(2) + DTI=L(3) + STIA=M(2) = 7
    clauses.append([-VARS['DIO_Medium'], -VARS['DTI_Low'], -VARS['STIA_Medium'], VARS['QUARANTINE']])
    # Rule 13: DIO=M(2) + DTI=M(2) + STIA=L(3) = 7
    clauses.append([-VARS['DIO_Medium'], -VARS['DTI_Medium'], -VARS['STIA_Low'], VARS['QUARANTINE']])
    
    # Rule for VICTIM (DIO=Low with low DTI/STIA - suppression victim)
    # Rule 19: DIO=L(1) + DTI=L(3) + STIA=L(3) = 7, but DIO=Low indicates victim
    clauses.append([-VARS['DIO_Low'], -VARS['DTI_Low'], -VARS['STIA_Low'], VARS['VICTIM']])
    
    # Rules for NORMAL (Score <= 5 or edge cases)
    clauses.append([-VARS['DIO_Medium'], -VARS['DTI_Medium'], -VARS['STIA_Medium'], VARS['NORMAL']])
    clauses.append([-VARS['DIO_Low'], -VARS['DTI_Medium'], -VARS['STIA_Medium'], VARS['NORMAL']])
    clauses.append([-VARS['DIO_Low'], -VARS['DTI_High'], -VARS['STIA_Medium'], VARS['NORMAL']])
    clauses.append([-VARS['DIO_Low'], -VARS['DTI_High'], -VARS['STIA_High'], VARS['NORMAL']])
    
    # ========== SECTION 2: Jamming Rules [Ref 15] ==========
    # Classification based on ETX and Retransmissions (Retrans is PRIMARY)
    
    # JAM_NONE: Retrans=L (Rules 1,4)
    clauses.append([-VARS['ETX_Low'], -VARS['RET_Low'], VARS['JAM_NONE']])
    clauses.append([-VARS['ETX_Medium'], -VARS['RET_Low'], VARS['JAM_NONE']])
    
    # JAM_LOW: Retrans=M with ETX∈{L,M} or ETX=H with Retrans=L (Rules 2,5,7)
    clauses.append([-VARS['ETX_Low'], -VARS['RET_Medium'], VARS['JAM_LOW']])
    clauses.append([-VARS['ETX_Medium'], -VARS['RET_Medium'], VARS['JAM_LOW']])
    clauses.append([-VARS['ETX_High'], -VARS['RET_Low'], VARS['JAM_LOW']])
    
    # JAM_MEDIUM: Retrans=H with ETX∈{L,M} or ETX=H with Retrans=M (Rules 3,6,8)
    clauses.append([-VARS['ETX_Low'], -VARS['RET_High'], VARS['JAM_MEDIUM']])
    clauses.append([-VARS['ETX_Medium'], -VARS['RET_High'], VARS['JAM_MEDIUM']])
    clauses.append([-VARS['ETX_High'], -VARS['RET_Medium'], VARS['JAM_MEDIUM']])
    
    # JAM_HIGH: ETX=H AND Retrans=H (Rule 9)
    clauses.append([-VARS['ETX_High'], -VARS['RET_High'], VARS['JAM_HIGH']])
    
    # ========== SECTION 3: Sinkhole Detection [Ref 3,14] ==========
    clauses.append([-VARS['RANK_Decrease'], VARS['SINKHOLE']])
    
    # ========== SECTION 4: RF Multi-Attack Detection [Ref 11] ==========
    # RF Rule 1: DROP_High → SELECTIVE_FWD
    clauses.append([-VARS['DROP_High'], VARS['SELECTIVE_FWD']])
    
    # RF Rule 2: DPR_High ∧ PFR_High → DOS
    clauses.append([-VARS['DPR_High'], -VARS['PFR_High'], VARS['DOS']])
    
    # RF Rule 3: RANK_Increase → RANK_ATTACK
    clauses.append([-VARS['RANK_Increase'], VARS['RANK_ATTACK']])
    
    # RF Rule 4: MSG_Flood → HELLO_FLOOD
    clauses.append([-VARS['MSG_Flood'], VARS['HELLO_FLOOD']])
    
    # ========== SECTION 5: XAI Anomaly Detection [Ref 6] ==========
    # Rule 1: NPC_Low ∧ NC_High ∧ UDP_High → XAI_SINKHOLE
    clauses.append([-VARS['NPC_Low'], -VARS['NC_High'], -VARS['UDP_High'], VARS['XAI_SINKHOLE']])
    
    # Rule 4: NPC_High ∧ NC_Low ∧ PF_Low → XAI_BLACKHOLE
    clauses.append([-VARS['NPC_High'], -VARS['NC_Low'], -VARS['PF_Low'], VARS['XAI_BLACKHOLE']])
    
    # ========== SECTION 6: Hybrid IDS [Ref 13] ==========
    # VN_Forged → VERSION_NUM
    clauses.append([-VARS['VN_Forged'], VARS['VERSION_NUM']])
    
    # ========== SECTION 7: Sybil Detection [Ref 12] ==========
    clauses.append([-VARS['SYBIL_Multi'], VARS['SYBIL_ATTACK']])
    
    # ========== Defense Action Implications ==========
    
    # MALICIOUS → DEFENSE_BLOCK
    clauses.append([-VARS['MALICIOUS'], VARS['DEFENSE_BLOCK']])
    
    # QUARANTINE → DEFENSE_ISOLATE
    clauses.append([-VARS['QUARANTINE'], VARS['DEFENSE_ISOLATE']])
    
    # VICTIM → DEFENSE_MONITOR
    clauses.append([-VARS['VICTIM'], VARS['DEFENSE_MONITOR']])
    
    # JAM_HIGH → DEFENSE_CHANNEL_HOP
    clauses.append([-VARS['JAM_HIGH'], VARS['DEFENSE_CHANNEL_HOP']])
    
    # JAM_MEDIUM → DEFENSE_ISOLATE
    clauses.append([-VARS['JAM_MEDIUM'], VARS['DEFENSE_ISOLATE']])
    
    # SINKHOLE → DEFENSE_ISOLATE
    clauses.append([-VARS['SINKHOLE'], VARS['DEFENSE_ISOLATE']])
    
    # DOS → DEFENSE_RATE_LIMIT
    clauses.append([-VARS['DOS'], VARS['DEFENSE_RATE_LIMIT']])
    
    # SELECTIVE_FWD → DEFENSE_REROUTE
    clauses.append([-VARS['SELECTIVE_FWD'], VARS['DEFENSE_REROUTE']])
    
    # HELLO_FLOOD → DEFENSE_RATE_LIMIT
    clauses.append([-VARS['HELLO_FLOOD'], VARS['DEFENSE_RATE_LIMIT']])
    
    # VERSION_NUM → DEFENSE_VERIFY_VERSION
    clauses.append([-VARS['VERSION_NUM'], VARS['DEFENSE_VERIFY_VERSION']])
    
    # RANK_ATTACK → DEFENSE_VERIFY_RANK
    clauses.append([-VARS['RANK_ATTACK'], VARS['DEFENSE_VERIFY_RANK']])
    
    # SYBIL_ATTACK → DEFENSE_BLOCK
    clauses.append([-VARS['SYBIL_ATTACK'], VARS['DEFENSE_BLOCK']])
    
    # XAI_SINKHOLE → DEFENSE_ISOLATE
    clauses.append([-VARS['XAI_SINKHOLE'], VARS['DEFENSE_ISOLATE']])
    
    # XAI_BLACKHOLE → DEFENSE_BLOCK
    clauses.append([-VARS['XAI_BLACKHOLE'], VARS['DEFENSE_BLOCK']])
    
    # ========== Consistency Constraints ==========
    
    # Cannot be both MALICIOUS and NORMAL
    clauses.append([-VARS['MALICIOUS'], -VARS['NORMAL']])
    
    # Cannot be both MALICIOUS and VICTIM
    clauses.append([-VARS['MALICIOUS'], -VARS['VICTIM']])
    
    # Cannot be both QUARANTINE and NORMAL
    clauses.append([-VARS['QUARANTINE'], -VARS['NORMAL']])
    
    # Cannot have conflicting jamming levels
    clauses.append([-VARS['JAM_HIGH'], -VARS['JAM_NONE']])
    clauses.append([-VARS['JAM_HIGH'], -VARS['JAM_LOW']])
    clauses.append([-VARS['JAM_MEDIUM'], -VARS['JAM_NONE']])
    
    return clauses


def verify_rule_consistency(clauses: List[List[int]]) -> Tuple[bool, str]:
    """Verify that the rule base is consistent (satisfiable)."""
    cnf = CNF(from_clauses=clauses)
    solver = Glucose3()
    solver.append_formula(cnf)
    
    if solver.solve():
        model = solver.get_model()
        return True, "Rule base is CONSISTENT (satisfiable)"
    else:
        return False, "Rule base is INCONSISTENT (unsatisfiable) - CONTRADICTION FOUND!"


def verify_property(clauses: List[List[int]], property_name: str, 
                   assumptions: List[int], expected: List[int]) -> Tuple[bool, str]:
    """
    Verify a specific property using SAT solver.
    
    Args:
        clauses: Base CNF clauses
        property_name: Description of the property
        assumptions: List of assumed true literals
        expected: List of literals that should be derivable
    
    Returns:
        Tuple of (success, message)
    """
    cnf = CNF(from_clauses=clauses)
    solver = Glucose3()
    solver.append_formula(cnf)
    
    # Add assumptions
    for lit in assumptions:
        solver.add_clause([lit])
    
    # Try to derive expected conclusions
    # We check if assumptions ∧ ¬expected is UNSAT (meaning expected must be true)
    for exp_lit in expected:
        solver_check = Glucose3()
        solver_check.append_formula(cnf)
        for lit in assumptions:
            solver_check.add_clause([lit])
        solver_check.add_clause([-exp_lit])  # Negate expected
        
        if solver_check.solve():
            # SAT means the negation is possible, so property doesn't hold
            return False, f"Property '{property_name}' FAILED: {VAR_NAMES.get(exp_lit, exp_lit)} is not guaranteed"
    
    return True, f"Property '{property_name}' VERIFIED ✓"


def run_verification():
    """Run all verification tests."""
    print("=" * 60)
    print("SAT Solver Verification for RPL Expert System")
    print("=" * 60)
    print()
    
    clauses = build_cnf_rules()
    print(f"Total CNF clauses: {len(clauses)}")
    print()
    
    # Test 1: Rule Consistency
    print("Test 1: Rule Consistency Check")
    print("-" * 40)
    success, msg = verify_rule_consistency(clauses)
    print(f"  Result: {msg}")
    print()
    
    # Test 2: Safety Property - Malicious → Block
    print("Test 2: Safety Properties")
    print("-" * 40)
    
    properties = [
        # FLSec-RPL Rules [Ref 9]
        ("FLSec Rule 1: DIO=H,DTI=L,STIA=L → MALICIOUS → BLOCK", 
         [VARS['DIO_High'], VARS['DTI_Low'], VARS['STIA_Low']],
         [VARS['MALICIOUS'], VARS['DEFENSE_BLOCK']]),
        
        ("FLSec Rule 4: DIO=H,DTI=M,STIA=L → MALICIOUS → BLOCK",
         [VARS['DIO_High'], VARS['DTI_Medium'], VARS['STIA_Low']],
         [VARS['MALICIOUS'], VARS['DEFENSE_BLOCK']]),
        
        ("FLSec Rule 10: DIO=M,DTI=L,STIA=L → MALICIOUS → BLOCK",
         [VARS['DIO_Medium'], VARS['DTI_Low'], VARS['STIA_Low']],
         [VARS['MALICIOUS'], VARS['DEFENSE_BLOCK']]),
        
        ("FLSec Rule 2: DIO=H,DTI=L,STIA=M → QUARANTINE → ISOLATE",
         [VARS['DIO_High'], VARS['DTI_Low'], VARS['STIA_Medium']],
         [VARS['QUARANTINE'], VARS['DEFENSE_ISOLATE']]),
        
        ("FLSec Normal Detection",
         [VARS['DIO_Medium'], VARS['DTI_Medium'], VARS['STIA_Medium']],
         [VARS['NORMAL']]),
        
        ("FLSec Rule 19: DIO=L,DTI=L,STIA=L → VICTIM → MONITOR",
         [VARS['DIO_Low'], VARS['DTI_Low'], VARS['STIA_Low']],
         [VARS['VICTIM'], VARS['DEFENSE_MONITOR']]),
        
        # Jamming Rules [Ref 15]
        ("Jamming Rule 9: ETX=H,RET=H → JAM_HIGH → CHANNEL_HOP",
         [VARS['ETX_High'], VARS['RET_High']],
         [VARS['JAM_HIGH'], VARS['DEFENSE_CHANNEL_HOP']]),
        
        ("Jamming Rule 8: ETX=H,RET=M → JAM_MEDIUM → ISOLATE",
         [VARS['ETX_High'], VARS['RET_Medium']],
         [VARS['JAM_MEDIUM'], VARS['DEFENSE_ISOLATE']]),
        
        ("Jamming Rules 1,4: RET=L → JAM_NONE",
         [VARS['ETX_Low'], VARS['RET_Low']],
         [VARS['JAM_NONE']]),
        
        # PRBA/UVM Sinkhole [Ref 3,14]
        ("Sinkhole: RANK_Decrease → SINKHOLE → ISOLATE",
         [VARS['RANK_Decrease']],
         [VARS['SINKHOLE'], VARS['DEFENSE_ISOLATE']]),
        
        # RF Multi-Attack [Ref 11]
        ("RF Rule 2: DPR_H ∧ PFR_H → DOS → RATE_LIMIT",
         [VARS['DPR_High'], VARS['PFR_High']],
         [VARS['DOS'], VARS['DEFENSE_RATE_LIMIT']]),
        
        ("RF Rule 1: DROP_H → SELECTIVE_FWD → REROUTE",
         [VARS['DROP_High']],
         [VARS['SELECTIVE_FWD'], VARS['DEFENSE_REROUTE']]),
        
        ("RF Rule 4: MSG_Flood → HELLO_FLOOD → RATE_LIMIT",
         [VARS['MSG_Flood']],
         [VARS['HELLO_FLOOD'], VARS['DEFENSE_RATE_LIMIT']]),
        
        # XAI Rules [Ref 6]
        ("XAI Rule 1: NPC_L ∧ NC_H ∧ UDP_H → XAI_SINKHOLE → ISOLATE",
         [VARS['NPC_Low'], VARS['NC_High'], VARS['UDP_High']],
         [VARS['XAI_SINKHOLE'], VARS['DEFENSE_ISOLATE']]),
        
        ("XAI Rule 4: NPC_H ∧ NC_L ∧ PF_L → XAI_BLACKHOLE → BLOCK",
         [VARS['NPC_High'], VARS['NC_Low'], VARS['PF_Low']],
         [VARS['XAI_BLACKHOLE'], VARS['DEFENSE_BLOCK']]),
        
        # Hybrid IDS [Ref 13]
        ("Version Number Attack: VN_Forged → VERSION_NUM → VERIFY",
         [VARS['VN_Forged']],
         [VARS['VERSION_NUM'], VARS['DEFENSE_VERIFY_VERSION']]),
        
        # Sybil [Ref 12]
        ("Sybil: SYBIL_Multi → SYBIL_ATTACK → BLOCK",
         [VARS['SYBIL_Multi']],
         [VARS['SYBIL_ATTACK'], VARS['DEFENSE_BLOCK']]),
    ]
    
    all_passed = True
    for prop_name, assumptions, expected in properties:
        success, msg = verify_property(clauses, prop_name, assumptions, expected)
        status = "✓" if success else "✗"
        print(f"  [{status}] {msg}")
        if not success:
            all_passed = False
    
    print()
    
    # Test 3: Non-Contradiction
    print("Test 3: Non-Contradiction Verification")
    print("-" * 40)
    
    contradictions = [
        ("MALICIOUS ∧ NORMAL cannot both be true",
         [VARS['MALICIOUS'], VARS['NORMAL']]),
        
        ("VICTIM ∧ MALICIOUS cannot both be true",
         [VARS['VICTIM'], VARS['MALICIOUS']]),
    ]
    
    for contra_name, literals in contradictions:
        cnf = CNF(from_clauses=clauses)
        solver = Glucose3()
        solver.append_formula(cnf)
        for lit in literals:
            solver.add_clause([lit])
        
        if solver.solve():
            print(f"  [✗] CONTRADICTION: {contra_name}")
            all_passed = False
        else:
            print(f"  [✓] Verified: {contra_name}")
    
    print()
    print("=" * 60)
    if all_passed:
        print("ALL VERIFICATION TESTS PASSED ✓")
    else:
        print("SOME TESTS FAILED - Review rules for inconsistencies")
    print("=" * 60)


def interactive_test():
    """Interactive test mode for custom scenarios."""
    print("\n" + "=" * 60)
    print("Interactive SAT Test Mode")
    print("=" * 60)
    print("\nEnter attack scenario to test (or 'quit' to exit):")
    print("  Example: DIO_High DTI_Low STIA_Low")
    print("  Available inputs:", list(k for k in VARS.keys() if VARS[k] < 100))
    
    clauses = build_cnf_rules()
    
    while True:
        try:
            user_input = input("\n> ").strip()
            if user_input.lower() == 'quit':
                break
            
            inputs = user_input.split()
            assumptions = []
            for inp in inputs:
                if inp in VARS:
                    assumptions.append(VARS[inp])
                else:
                    print(f"  Unknown variable: {inp}")
                    continue
            
            if not assumptions:
                continue
            
            print(f"\nAssumptions: {[VAR_NAMES[a] for a in assumptions]}")
            
            # Find all derivable conclusions
            cnf = CNF(from_clauses=clauses)
            solver = Glucose3()
            solver.append_formula(cnf)
            for lit in assumptions:
                solver.add_clause([lit])
            
            if solver.solve():
                model = solver.get_model()
                conclusions = []
                for lit in model:
                    if lit > 0 and lit >= 100:
                        name = VAR_NAMES.get(lit, f"VAR_{lit}")
                        conclusions.append(name)
                print(f"Conclusions: {conclusions}")
            else:
                print("UNSATISFIABLE - Invalid combination!")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e}")


if __name__ == "__main__":
    run_verification()
    
    # Uncomment for interactive mode:
    # interactive_test()
