import os
import sys
import win32com.client
import subprocess
from pathlib import Path

def add_to_startup():
    """Add search_new\search.py to Windows startup"""
    try:
        # Get the actual directory where the EXE is running
        if getattr(sys, 'frozen', False):
            exe_dir = Path(sys.executable).parent
        else:
            exe_dir = Path(__file__).parent
        
        # Create a batch file that starts the search service
        batch_content = f'''@echo off
cd /d "{exe_dir}"
python search.py
'''
        
        batch_path = exe_dir / "start_search_service.bat"
        with open(batch_path, 'w') as f:
            f.write(batch_content)
        
        # Create shortcut in startup folder
        startup_path = Path(os.environ['APPDATA']) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
        shortcut_path = startup_path / 'FirewallSearchService.lnk'
        
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortcut(str(shortcut_path))
        shortcut.TargetPath = str(batch_path)
        shortcut.WorkingDirectory = str(exe_dir)
        shortcut.Description = "Firewall Guard Search Service"
        shortcut.Save()
        
        print("Autostart enabled for search_new\\search.py")
        print(f"Batch file created: {batch_path}")
        print(f"Shortcut created: {shortcut_path}")
        
    except Exception as e:
        print(f"Error enabling autostart: {e}")

def remove_from_startup():
    """Remove search autostart"""
    try:
        startup_path = Path(os.environ['APPDATA']) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
        shortcut_path = startup_path / 'FirewallSearchService.lnk'
        
        if shortcut_path.exists():
            shortcut_path.unlink()
            print("Autostart disabled")
        else:
            print("Autostart was not enabled")
            
    except Exception as e:
        print(f"Error disabling autostart: {e}")

def launch_search_program():
    """Launch the search.py program"""
    try:
        # Get the actual directory where the EXE is running
        if getattr(sys, 'frozen', False):
            exe_dir = Path(sys.executable).parent
        else:
            exe_dir = Path(__file__).parent
        
        search_script = exe_dir / "search.py"
        if search_script.exists():
            print("Launching search program...")
            subprocess.Popen([sys.executable, str(search_script)], cwd=str(exe_dir))
            print("Search program launched successfully!")
            return True
        else:
            print("search.py not found in current directory")
            return False
            
    except Exception as e:
        print(f"Error launching search program: {e}")
        return False

def main():
    """Main function with user choice"""
    print("UserSearch Backend - Autostart Control")
    print("=" * 40)
    print("1. Enable Autostart")
    print("2. Disable Autostart")
    print("3. Exit")
    
    try:
        choice = input("\nEnter your choice (1-3): ").strip()
        
        if choice == "1":
            add_to_startup()
            # Ask if user wants to launch the program
            launch_choice = input("\nLaunch search program now? (y/n): ").strip().lower()
            if launch_choice in ['y', 'yes']:
                launch_search_program()
        elif choice == "2":
            remove_from_startup()
        elif choice == "3":
            print("Goodbye!")
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")
            
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
