from tkinter import Tk, Label, Entry, Button, StringVar
import tkinter.messagebox as messagebox

class COVIDDiagnosisUI:
    def __init__(self, master, expert_system=None):
        self.master = master
        self.expert_system = expert_system
        master.title("COVID-19 Diagnosis Expert System")

        self.label = Label(master, text="Enter your symptoms (comma-separated):")
        self.label.pack()

        self.symptoms_var = StringVar()
        self.symptoms_entry = Entry(master, textvariable=self.symptoms_var)
        self.symptoms_entry.pack()

        self.submit_button = Button(master, text="Submit", command=self.submit_symptoms)
        self.submit_button.pack()

        self.result_label = Label(master, text="")
        self.result_label.pack()

    def submit_symptoms(self):
        raw = self.symptoms_var.get()
        if not raw:
            messagebox.showwarning("Input Error", "Please enter at least one symptom.")
            return

        symptoms = [s.strip().lower() for s in raw.split(",") if s.strip()]

        if self.expert_system:
            diagnosis = self.expert_system.diagnose(symptoms)
            message = "\n".join(diagnosis)
            messagebox.showinfo("Diagnosis", message)
            self.result_label.config(text=message)
        else:
            messagebox.showinfo("Symptoms Submitted", f"You entered: {', '.join(symptoms)}")

def main():
    root = Tk()
    app = COVIDDiagnosisUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()