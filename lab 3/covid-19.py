from tkinter import Tk
from ui import ApplicationUI
from expert_system import ExpertSystem

def main():
    root = Tk()
    root.title("COVID-19 Diagnosis Expert System")
    
    expert_system = ExpertSystem()
    app_ui = ApplicationUI(root, expert_system)
    
    root.mainloop()

if __name__ == "__main__":
    main()