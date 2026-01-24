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
# VARIABLE ENCODING (must match rpl_rules_cnf.txt)
# ============================================================

# Input Variables
VARS = {
    # DIO Level
    'DIO_High': 1, 'DIO_Medium': 2, 'DIO_Low': 3,
    # DTI Level  
    'DTI_High': 4, 'DTI_Medium': 5, 'DTI_Low': 6,
    # STIA Level
    'STIA_High': 7, 'STIA_Medium': 8, 'STIA_Low': 9,
    # ETX Level
    'ETX_High': 10, 'ETX_Medium': 11, 'ETX_Low': 12,
    # Retransmission Level
    'RET_High': 13, 'RET_Medium': 14, 'RET_Low': 15,
    # Rank Change
    'RANK_Decrease': 16, 'RANK_Increase': 17, 'RANK_Normal': 18,
    # Drop Rate
    'DROP_High': 19, 'DROP_Medium': 20, 'DROP_Low': 21,
    # DPR (Duplicate Packet Rate)
    'DPR_High': 22, 'DPR_Normal': 23,
    # PFR (Packet Forwarding Rate)
    'PFR_High': 24, 'PFR_Normal': 25,
    # Version Number
    'VN_Forged': 26, 'VN_Normal': 27,
    # Message Flood
    'MSG_Flood': 28, 'MSG_Normal': 29,
    # Sybil
    'SYBIL_Multi': 30, 'SYBIL_Single': 31,
    
    # Output Variables (Conclusions)
    'MALICIOUS': 101, 'QUARANTINE': 102, 'VICTIM': 103, 'NORMAL': 104,
    'JAM_HIGH': 105, 'JAM_MEDIUM': 106, 'JAM_LOW': 107, 'JAM_NONE': 108,
    'SINKHOLE': 109, 'RANK_ATTACK': 110, 'DOS': 111, 'SELECTIVE_FWD': 112,
    'HELLO_FLOOD': 113, 'VERSION_NUM': 114, 'SYBIL_ATTACK': 115,
    
    # Defense Actions
    'DEFENSE_BLOCK': 201, 'DEFENSE_ISOLATE': 202, 'DEFENSE_MONITOR': 203,
}

# Reverse mapping for output
VAR_NAMES = {v: k for k, v in VARS.items()}


def build_cnf_rules() -> List[List[int]]:
    """Build CNF clauses representing the expert system rules."""
    clauses = []
    
    # ========== Mutual Exclusion Constraints ==========
    
    # DIO levels: exactly one must be true
    clauses.append([VARS['DIO_High'], VARS['DIO_Medium'], VARS['DIO_Low']])  # At least one
    clauses.append([-VARS['DIO_High'], -VARS['DIO_Medium']])  # At most one
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
    
    # ========== FLSec-RPL Rules (DIO Suppression) ==========
    
    # R1: DIO=High ∧ DTI=Low ∧ STIA=Low → MALICIOUS
    # CNF: ¬DIO_High ∨ ¬DTI_Low ∨ ¬STIA_Low ∨ MALICIOUS
    clauses.append([-VARS['DIO_High'], -VARS['DTI_Low'], -VARS['STIA_Low'], VARS['MALICIOUS']])
    
    # MALICIOUS → DEFENSE_BLOCK
    clauses.append([-VARS['MALICIOUS'], VARS['DEFENSE_BLOCK']])
    
    # R2: DIO=High ∧ DTI=Low ∧ STIA=Medium → QUARANTINE
    clauses.append([-VARS['DIO_High'], -VARS['DTI_Low'], -VARS['STIA_Medium'], VARS['QUARANTINE']])
    
    # QUARANTINE → DEFENSE_ISOLATE
    clauses.append([-VARS['QUARANTINE'], VARS['DEFENSE_ISOLATE']])
    
    # R3: DIO=Medium ∧ DTI=Medium ∧ STIA=Medium → NORMAL
    clauses.append([-VARS['DIO_Medium'], -VARS['DTI_Medium'], -VARS['STIA_Medium'], VARS['NORMAL']])
    
    # R4: DIO=Low ∧ DTI=Low ∧ STIA=Low → VICTIM
    clauses.append([-VARS['DIO_Low'], -VARS['DTI_Low'], -VARS['STIA_Low'], VARS['VICTIM']])
    
    # VICTIM → DEFENSE_MONITOR
    clauses.append([-VARS['VICTIM'], VARS['DEFENSE_MONITOR']])
    
    # ========== Jamming Rules ==========
    
    # R_Jam_1: ETX=Low ∧ RET=Low → JAM_NONE
    clauses.append([-VARS['ETX_Low'], -VARS['RET_Low'], VARS['JAM_NONE']])
    
    # R_Jam_2: ETX=Low ∧ RET=Medium → JAM_LOW
    clauses.append([-VARS['ETX_Low'], -VARS['RET_Medium'], VARS['JAM_LOW']])
    
    # R_Jam_3: ETX=High ∧ RET=High → JAM_HIGH
    clauses.append([-VARS['ETX_High'], -VARS['RET_High'], VARS['JAM_HIGH']])
    clauses.append([-VARS['JAM_HIGH'], VARS['DEFENSE_BLOCK']])
    
    # R_Jam_4: ETX=Medium ∧ RET=High → JAM_MEDIUM
    clauses.append([-VARS['ETX_Medium'], -VARS['RET_High'], VARS['JAM_MEDIUM']])
    clauses.append([-VARS['JAM_MEDIUM'], VARS['DEFENSE_ISOLATE']])
    
    # ========== Sinkhole Rules ==========
    
    # RANK_Decrease → SINKHOLE
    clauses.append([-VARS['RANK_Decrease'], VARS['SINKHOLE']])
    clauses.append([-VARS['SINKHOLE'], VARS['DEFENSE_BLOCK']])
    
    # ========== DoS Rules ==========
    
    # DPR_High ∧ PFR_High → DOS
    clauses.append([-VARS['DPR_High'], -VARS['PFR_High'], VARS['DOS']])
    clauses.append([-VARS['DOS'], VARS['DEFENSE_BLOCK']])
    
    # ========== Selective Forwarding Rules ==========
    
    # DROP_High → SELECTIVE_FWD
    clauses.append([-VARS['DROP_High'], VARS['SELECTIVE_FWD']])
    clauses.append([-VARS['SELECTIVE_FWD'], VARS['DEFENSE_ISOLATE']])
    
    # ========== Hello Flood Rules ==========
    
    # MSG_Flood → HELLO_FLOOD
    clauses.append([-VARS['MSG_Flood'], VARS['HELLO_FLOOD']])
    clauses.append([-VARS['HELLO_FLOOD'], VARS['DEFENSE_ISOLATE']])
    
    # ========== Version Number Rules ==========
    
    # VN_Forged → VERSION_NUM
    clauses.append([-VARS['VN_Forged'], VARS['VERSION_NUM']])
    clauses.append([-VARS['VERSION_NUM'], VARS['DEFENSE_BLOCK']])
    
    # ========== Sybil Rules ==========
    
    # SYBIL_Multi → SYBIL_ATTACK
    clauses.append([-VARS['SYBIL_Multi'], VARS['SYBIL_ATTACK']])
    clauses.append([-VARS['SYBIL_ATTACK'], VARS['DEFENSE_BLOCK']])
    
    # ========== Consistency Constraints ==========
    
    # Cannot be both MALICIOUS and NORMAL
    clauses.append([-VARS['MALICIOUS'], -VARS['NORMAL']])
    
    # Cannot be both VICTIM and MALICIOUS
    clauses.append([-VARS['VICTIM'], -VARS['MALICIOUS']])
    
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
        ("Malicious Detection → Block", 
         [VARS['DIO_High'], VARS['DTI_Low'], VARS['STIA_Low']],
         [VARS['MALICIOUS'], VARS['DEFENSE_BLOCK']]),
        
        ("Quarantine Detection → Isolate",
         [VARS['DIO_High'], VARS['DTI_Low'], VARS['STIA_Medium']],
         [VARS['QUARANTINE'], VARS['DEFENSE_ISOLATE']]),
        
        ("Normal Detection (No Attack)",
         [VARS['DIO_Medium'], VARS['DTI_Medium'], VARS['STIA_Medium']],
         [VARS['NORMAL']]),
        
        ("Victim Detection → Monitor",
         [VARS['DIO_Low'], VARS['DTI_Low'], VARS['STIA_Low']],
         [VARS['VICTIM'], VARS['DEFENSE_MONITOR']]),
        
        ("High Jamming → Block",
         [VARS['ETX_High'], VARS['RET_High']],
         [VARS['JAM_HIGH'], VARS['DEFENSE_BLOCK']]),
        
        ("Sinkhole → Block",
         [VARS['RANK_Decrease']],
         [VARS['SINKHOLE'], VARS['DEFENSE_BLOCK']]),
        
        ("DoS → Block",
         [VARS['DPR_High'], VARS['PFR_High']],
         [VARS['DOS'], VARS['DEFENSE_BLOCK']]),
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
