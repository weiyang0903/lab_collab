import clips

class ExpertSystem:
    def __init__(self):
        self.environment = clips.Environment()
        self._define_templates()
        self._define_rules()
        
    def _define_templates(self):
        """Define templates for facts"""
        # Define patient template
        self.environment.build("""
            (deftemplate patient
                (slot has-fever (default no))
                (slot has-cough (default no))
                (slot has-fatigue (default no))
                (slot has-breathing-difficulty (default no))
                (slot has-taste-loss (default no))
                (slot has-headache (default no))
                (slot has-muscle-aches (default no))
                (slot has-sore-throat (default no)))
        """)
        
        # Define diagnosis template
        self.environment.build("""
            (deftemplate diagnosis
                (slot disease)
                (slot confidence (default 0)))
        """)
    
    def _define_rules(self):
        """Define COVID-19 diagnosis rules"""
        
        # Rule 1: High probability COVID-19 (multiple key symptoms)
        self.environment.build("""
            (defrule covid-high-probability
                (patient (has-fever yes) (has-cough yes) (has-taste-loss yes))
                =>
                (assert (diagnosis (disease "COVID-19 - High Probability") (confidence 90))))
        """)
        
        # Rule 2: Moderate probability COVID-19 (fever + respiratory symptoms)
        self.environment.build("""
            (defrule covid-moderate-probability
                (patient (has-fever yes) (has-breathing-difficulty yes))
                =>
                (assert (diagnosis (disease "COVID-19 - Moderate Probability") (confidence 75))))
        """)
        
        # Rule 3: Low probability COVID-19 (some symptoms present)
        self.environment.build("""
            (defrule covid-low-probability
                (patient (has-cough yes) (has-fatigue yes))
                (not (patient (has-fever yes)))
                =>
                (assert (diagnosis (disease "COVID-19 - Low Probability") (confidence 40))))
        """)
        
        # Rule 4: Common cold/flu symptoms
        self.environment.build("""
            (defrule common-cold
                (patient (has-sore-throat yes) (has-cough yes))
                (not (patient (has-fever yes)))
                (not (patient (has-taste-loss yes)))
                =>
                (assert (diagnosis (disease "Possible Common Cold") (confidence 60))))
        """)
        
        # Rule 5: Single cough symptom
        self.environment.build("""
            (defrule cough-only
                (patient (has-cough yes) (has-fever no) (has-fatigue no) 
                        (has-breathing-difficulty no) (has-taste-loss no)
                        (has-sore-throat no))
                =>
                (assert (diagnosis (disease "Mild respiratory symptoms - possible minor infection") (confidence 30))))
        """)
        
        # Rule 6: Single fever symptom
        self.environment.build("""
            (defrule fever-only
                (patient (has-fever yes) (has-cough no) (has-fatigue no) 
                        (has-breathing-difficulty no) (has-taste-loss no)
                        (has-sore-throat no))
                =>
                (assert (diagnosis (disease "Fever present - monitor for additional symptoms") (confidence 35))))
        """)
        
        # Rule 7: General single symptom catch-all
        self.environment.build("""
            (defrule single-symptom-general
                (or (patient (has-headache yes))
                    (patient (has-muscle-aches yes)))
                (patient (has-fever no) (has-cough no) (has-breathing-difficulty no) 
                        (has-taste-loss no))
                =>
                (assert (diagnosis (disease "Minor symptoms - likely common illness") (confidence 25))))
        """)

        # Rule 8: No significant symptoms
        self.environment.build("""
            (defrule no-symptoms
                (patient (has-fever no) (has-cough no) (has-fatigue no) 
                        (has-breathing-difficulty no) (has-taste-loss no)
                        (has-headache no) (has-muscle-aches no) (has-sore-throat no))
                =>
                (assert (diagnosis (disease "No significant illness detected") (confidence 95))))
        """)

    def diagnose(self, symptoms):
        """Diagnose based on symptoms list"""
        # Reset environment
        self.environment.reset()
        
        # Convert symptoms to boolean values
        symptom_mapping = {
            'fever': any('fever' in s.lower() for s in symptoms),
            'cough': any('cough' in s.lower() for s in symptoms),
            'fatigue': any('fatigue' in s.lower() or 'tired' in s.lower() for s in symptoms),
            'breathing-difficulty': any('breath' in s.lower() or 'breathing' in s.lower() or 'shortness' in s.lower() for s in symptoms),
            'taste-loss': any('taste' in s.lower() or 'smell' in s.lower() for s in symptoms),
            'headache': any('headache' in s.lower() or 'head' in s.lower() for s in symptoms),
            'muscle-aches': any('muscle' in s.lower() or 'body ache' in s.lower() or 'aches' in s.lower() for s in symptoms),
            'sore-throat': any('sore throat' in s.lower() or 'throat' in s.lower() for s in symptoms)
        }
        
        # Create patient fact string
        fact_string = f"(patient (has-fever {'yes' if symptom_mapping['fever'] else 'no'}) (has-cough {'yes' if symptom_mapping['cough'] else 'no'}) (has-fatigue {'yes' if symptom_mapping['fatigue'] else 'no'}) (has-breathing-difficulty {'yes' if symptom_mapping['breathing-difficulty'] else 'no'}) (has-taste-loss {'yes' if symptom_mapping['taste-loss'] else 'no'}) (has-headache {'yes' if symptom_mapping['headache'] else 'no'}) (has-muscle-aches {'yes' if symptom_mapping['muscle-aches'] else 'no'}) (has-sore-throat {'yes' if symptom_mapping['sore-throat'] else 'no'}))"
        
        # Assert the patient fact
        self.environment.assert_string(fact_string)
        
        # Run the expert system
        self.environment.run()
        
        # Get diagnosis results
        results = []
        for fact in self.environment.facts():
            if fact.template.name == 'diagnosis':
                disease = fact['disease']
                confidence = fact['confidence']
                results.append(f"{disease} (Confidence: {confidence}%)")
        
        return results if results else ["Unable to determine diagnosis - please check symptoms"]
        
    def get_symptom_mapping(self):
        """Return available symptoms for user reference"""
        return [
            "fever", "cough", "fatigue", "shortness of breath", 
            "loss of taste or smell", "headache", "muscle aches", 
            "sore throat", "breathing difficulty"
        ]