#!/usr/bin/env python3
"""
Test script for the COVID-19 Expert System
This script demonstrates the rule-based expert system functionality
"""

from expert_system import ExpertSystem

def test_expert_system():
    """Test the expert system with various symptom combinations"""
    
    print("="*60)
    print("COVID-19 EXPERT SYSTEM TESTING")
    print("="*60)
    
    # Initialize expert system
    es = ExpertSystem()
    
    # Test cases
    test_cases = [
        {
            "name": "High Probability COVID-19",
            "symptoms": ["fever", "cough", "loss of taste or smell"],
            "expected": "Should show high probability COVID-19"
        },
        {
            "name": "Moderate Probability COVID-19", 
            "symptoms": ["fever", "shortness of breath"],
            "expected": "Should show moderate probability COVID-19"
        },
        {
            "name": "Low Probability COVID-19",
            "symptoms": ["cough", "fatigue"],
            "expected": "Should show low probability COVID-19"
        },
        {
            "name": "Common Cold",
            "symptoms": ["sore throat", "cough"],
            "expected": "Should suggest common cold"
        },
        {
            "name": "No Symptoms",
            "symptoms": [],
            "expected": "Should show no significant illness"
        },
        {
            "name": "Mixed Symptoms",
            "symptoms": ["headache", "muscle aches", "fatigue"],
            "expected": "Should provide appropriate diagnosis"
        }
    ]
    
    # Run test cases
    for i, test_case in enumerate(test_cases, 1):
        print(f"\nTest Case {i}: {test_case['name']}")
        print(f"Input Symptoms: {test_case['symptoms']}")
        print(f"Expected: {test_case['expected']}")
        
        try:
            diagnosis = es.diagnose(test_case['symptoms'])
            print(f"Expert System Output: {diagnosis}")
        except Exception as e:
            print(f"Error: {e}")
        
        print("-" * 40)
    
    print("\n" + "="*60)
    print("Testing completed!")
    print("Available symptoms for reference:")
    for symptom in es.get_symptom_mapping():
        print(f"  • {symptom}")
    print("="*60)

if __name__ == "__main__":
    test_expert_system()