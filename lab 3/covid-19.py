from tkinter import Tk
from ui import COVIDDiagnosisUI
from expert_system import ExpertSystem

def main():
    """
    Main function to run the COVID-19 Expert System Application
    
    This application demonstrates:
    1. Rule-based expert system using clipspy
    2. User interface using tkinter
    3. Multiple diagnostic rules for COVID-19 assessment
    """
    
    # Initialize the main window
    root = Tk()
    root.title("COVID-19 Diagnosis Expert System")
    
    # Initialize the expert system
    try:
        expert_system = ExpertSystem()
        print("Expert System initialized successfully!")
    except Exception as e:
        print(f"Error initializing Expert System: {e}")
        expert_system = None
    
    # Initialize the UI with expert system
    app_ui = COVIDDiagnosisUI(root, expert_system)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    print("Starting COVID-19 Expert System...")
    print("=" * 50)
    print("Features:")
    print("- Rule-based diagnosis using clipspy")
    print("- Interactive GUI with tkinter")
    print("- Multiple diagnostic confidence levels")
    print("- Educational purpose system")
    print("=" * 50)
    main()