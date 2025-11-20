from tkinter import Tk, Label, Entry, Button, StringVar, messagebox

class COVIDDiagnosisUI:
    def __init__(self, master):
        self.master = master
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
        symptoms = self.symptoms_var.get()
        if symptoms:
            # Here you would typically call the expert system logic to get a diagnosis
            # For now, we will just show a message box with the entered symptoms
            messagebox.showinfo("Symptoms Submitted", f"You entered: {symptoms}")
        else:
            messagebox.showwarning("Input Error", "Please enter at least one symptom.")

def main():
    root = Tk()
    app = COVIDDiagnosisUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()