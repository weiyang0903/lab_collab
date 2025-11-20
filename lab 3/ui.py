from tkinter import Tk, Label, Entry, Button, StringVar, messagebox, Text, Scrollbar, Frame, Checkbutton, BooleanVar
from tkinter import ttk

class COVIDDiagnosisUI:
    def __init__(self, master, expert_system=None):
        self.master = master
        self.expert_system = expert_system
        master.title("COVID-19 Diagnosis Expert System")
        master.geometry("600x500")
        
        # Create main frame
        main_frame = Frame(master)
        main_frame.pack(padx=10, pady=10, fill='both', expand=True)
        
        # Title
        title_label = Label(main_frame, text="COVID-19 Expert System Diagnosis", 
                           font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Symptoms selection frame
        symptoms_frame = Frame(main_frame)
        symptoms_frame.pack(fill='x', pady=(0, 20))
        
        Label(symptoms_frame, text="Select your symptoms:", font=("Arial", 12)).pack(anchor='w')
        
        # Symptom checkboxes
        self.symptom_vars = {}
        symptoms = [
            "fever", "cough", "fatigue", "shortness of breath",
            "loss of taste or smell", "headache", "muscle aches", "sore throat"
        ]
        
        # Create checkboxes in a grid
        checkbox_frame = Frame(symptoms_frame)
        checkbox_frame.pack(fill='x', pady=(10, 0))
        
        for i, symptom in enumerate(symptoms):
            var = BooleanVar()
            self.symptom_vars[symptom] = var
            cb = Checkbutton(checkbox_frame, text=symptom.title(), variable=var)
            cb.grid(row=i//2, column=i%2, sticky='w', padx=(0, 20), pady=2)
        
        # Additional symptoms entry
        additional_frame = Frame(main_frame)
        additional_frame.pack(fill='x', pady=(0, 20))
        
        Label(additional_frame, text="Additional symptoms (comma-separated):", 
              font=("Arial", 10)).pack(anchor='w')
        
        self.additional_symptoms_var = StringVar()
        self.additional_entry = Entry(additional_frame, textvariable=self.additional_symptoms_var,
                                    width=70)
        self.additional_entry.pack(fill='x', pady=(5, 0))
        
        # Buttons frame
        button_frame = Frame(main_frame)
        button_frame.pack(fill='x', pady=(0, 20))
        
        self.diagnose_button = Button(button_frame, text="Get Diagnosis", 
                                     command=self.get_diagnosis, bg="#4CAF50", fg="white",
                                     font=("Arial", 12, "bold"))
        self.diagnose_button.pack(side='left', padx=(0, 10))
        
        self.clear_button = Button(button_frame, text="Clear All", 
                                  command=self.clear_all, bg="#f44336", fg="white",
                                  font=("Arial", 12))
        self.clear_button.pack(side='left')
        
        # Results frame
        results_frame = Frame(main_frame)
        results_frame.pack(fill='both', expand=True)
        
        Label(results_frame, text="Diagnosis Results:", font=("Arial", 12, "bold")).pack(anchor='w')
        
        # Text area for results with scrollbar
        text_frame = Frame(results_frame)
        text_frame.pack(fill='both', expand=True, pady=(5, 0))
        
        self.result_text = Text(text_frame, wrap='word', font=("Arial", 10),
                               bg="#f0f0f0", height=8)
        scrollbar = Scrollbar(text_frame, orient="vertical", command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        self.result_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Initial message
        self.result_text.insert("1.0", "Welcome to the COVID-19 Expert System!\n\n" +
                                "Please select your symptoms and click 'Get Diagnosis' " +
                                "to receive an assessment based on expert rules.\n\n" +
                                "Note: This is for educational purposes only and should not " +
                                "replace professional medical advice.")
        self.result_text.config(state='disabled')

    def get_diagnosis(self):
        # Collect selected symptoms
        selected_symptoms = []
        for symptom, var in self.symptom_vars.items():
            if var.get():
                selected_symptoms.append(symptom)
        
        # Add additional symptoms
        additional = self.additional_symptoms_var.get().strip()
        if additional:
            additional_list = [s.strip() for s in additional.split(',')]
            selected_symptoms.extend(additional_list)
        
        if not selected_symptoms:
            messagebox.showwarning("No Symptoms", "Please select at least one symptom.")
            return
        
        # Get diagnosis from expert system
        if self.expert_system:
            try:
                diagnosis_results = self.expert_system.diagnose(selected_symptoms)
                self.display_results(selected_symptoms, diagnosis_results)
            except Exception as e:
                messagebox.showerror("Error", f"Error in diagnosis: {str(e)}")
        else:
            messagebox.showerror("Error", "Expert system not initialized.")
    
    def display_results(self, symptoms, diagnosis):
        self.result_text.config(state='normal')
        self.result_text.delete("1.0", "end")
        
        # Display input symptoms
        self.result_text.insert("end", "SYMPTOMS REPORTED:\n", "header")
        for symptom in symptoms:
            self.result_text.insert("end", f"• {symptom.title()}\n")
        
        self.result_text.insert("end", "\n" + "="*50 + "\n\n")
        
        # Display diagnosis
        self.result_text.insert("end", "EXPERT SYSTEM DIAGNOSIS:\n", "header")
        for result in diagnosis:
            self.result_text.insert("end", f"• {result}\n")
        
        self.result_text.insert("end", "\n" + "="*50 + "\n\n")
        self.result_text.insert("end", "IMPORTANT DISCLAIMER:\n", "disclaimer")
        self.result_text.insert("end", "This diagnosis is generated by an educational expert system " +
                                "and should NOT be used as a substitute for professional medical advice. " +
                                "If you are experiencing symptoms, please consult with a healthcare professional.")
        
        # Configure text tags for formatting
        self.result_text.tag_configure("header", font=("Arial", 11, "bold"))
        self.result_text.tag_configure("disclaimer", font=("Arial", 9, "italic"), foreground="red")
        
        self.result_text.config(state='disabled')
    
    def clear_all(self):
        # Clear all checkboxes
        for var in self.symptom_vars.values():
            var.set(False)
        
        # Clear additional symptoms entry
        self.additional_symptoms_var.set("")
        
        # Clear results
        self.result_text.config(state='normal')
        self.result_text.delete("1.0", "end")
        self.result_text.insert("1.0", "All symptoms cleared. Ready for new input.")
        self.result_text.config(state='disabled')

def main():
    from expert_system import ExpertSystem
    root = Tk()
    expert_system = ExpertSystem()
    app = COVIDDiagnosisUI(root, expert_system)
    root.mainloop()

if __name__ == "__main__":
    main()