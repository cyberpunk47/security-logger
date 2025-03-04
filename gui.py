import tkinter as tk
from tkinter import scrolledtext
import subprocess
import threading
import sys
import os

class SecurityLoggerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Event Logger")
        self.root.geometry("1000x800")

        # GUI Elements
        self.start_button = tk.Button(root, text="Start Logger", command=self.start_logger)
        self.start_button.pack(pady=10)

        self.log_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=120, height=40)
        self.log_display.pack(pady=10, padx=10)

        self.stop_button = tk.Button(root, text="Stop Logger", command=self.stop_logger, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        # Process and Threads
        self.logger_process = None
        self.logger_thread = None
        self.output_thread = None

    def start_logger(self):
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.log_display.delete(1.0, tk.END)
        self.log_display.insert(tk.END, "Starting security logger...\n")

        # Start the logger in a separate thread
        self.logger_thread = threading.Thread(target=self.run_logger)
        self.logger_thread.start()

    def stop_logger(self):
        """Stop the security logger safely."""
        if self.logger_process:
            try:
                # Try graceful termination first
                self.logger_process.terminate()
                self.logger_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                try:
                    # Force kill if needed
                    self.logger_process.kill()
                    self.logger_process.wait()
                except Exception as e:
                    self.log_display.insert(tk.END, f"Error stopping logger: {str(e)}\n")
            except AttributeError:
                # Process already terminated
                pass
            finally:
                self.logger_process = None
                self.log_display.insert(tk.END, "\nSecurity logger stopped.\n")
                self.start_button.config(state=tk.NORMAL)
                self.stop_button.config(state=tk.DISABLED)

    def run_logger(self):
        """Run the security logger."""
        try:
            # Get absolute paths
            script_dir = os.path.dirname(os.path.abspath(__file__))
            script_path = os.path.join(script_dir, "security_logger.py")
            python_exec = sys.executable

            # Start the process
            self.logger_process = subprocess.Popen(
                ["pkexec", python_exec, "-u", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                env={
                    **os.environ.copy(),
                    "DISPLAY": os.environ.get("DISPLAY", ":0"),
                    "XAUTHORITY": os.environ.get("XAUTHORITY", os.path.expanduser("~/.Xauthority"))
                },
                cwd=script_dir
            )

            # Start output reader thread
            self.output_thread = threading.Thread(target=self.read_output, daemon=True)
            self.output_thread.start()

        except Exception as e:
            self.log_display.insert(tk.END, f"Error: {str(e)}\n")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)

    def read_output(self):
        """Read output from the logger process."""
        try:
            while self.logger_process and self.logger_process.poll() is None:
                # Read stdout
                output = self.logger_process.stdout.readline()
                if output:
                    self.log_display.insert(tk.END, output)
                    self.log_display.yview(tk.END)

                # Read stderr
                error = self.logger_process.stderr.readline()
                if error:
                    self.log_display.insert(tk.END, f"{error}\n")
                    self.log_display.yview(tk.END)
        except ValueError:
            # Handle closed pipe errors
            pass

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityLoggerGUI(root)
    root.mainloop()