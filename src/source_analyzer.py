import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import json
import os
import subprocess

class SourceAnalyzerTab:
    def __init__(self, parent, file_browser):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        self.file_browser = file_browser
        
        self.setup_ui()
    
    def setup_ui(self):
        # Compilation database file selection widgets
        compile_db_frame = tk.Frame(self.frame)
        compile_db_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(compile_db_frame, text="Select compile_commands.json:").pack(side=tk.LEFT)
        self.compile_db_entry = tk.Entry(compile_db_frame, width=50)
        self.compile_db_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(compile_db_frame, text="Browse", command=self.browse_compile_db).pack(side=tk.LEFT)

        # Output directory selection widgets
        output_dir_frame = tk.Frame(self.frame)
        output_dir_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(output_dir_frame, text="Output Directory:").pack(side=tk.LEFT)
        self.output_dir_entry = tk.Entry(output_dir_frame, width=50)
        self.output_dir_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(output_dir_frame, text="Browse", command=self.browse_output_dir).pack(side=tk.LEFT)

        # Analyzer path selection
        analyzer_frame = tk.Frame(self.frame)
        analyzer_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(analyzer_frame, text="Path to MyStaticAnalyzer:").pack(side=tk.LEFT)
        self.analyzer_path_entry = tk.Entry(analyzer_frame, width=50)
        self.analyzer_path_entry.pack(side=tk.LEFT, padx=5)
        self.analyzer_path_entry.insert(0, "./build/MyStaticAnalyzer")  # Default path
        tk.Button(analyzer_frame, text="Browse", command=self.browse_analyzer_path).pack(side=tk.LEFT)

        # Analyze button
        tk.Button(self.frame, text="Analyze Source", command=self.analyze_source).pack(pady=10)

        # Output console
        tk.Label(self.frame, text="Analysis Output:").pack(anchor="w", padx=10)
        self.output_console = scrolledtext.ScrolledText(self.frame, height=15, wrap=tk.WORD)
        self.output_console.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)

        # Output files list
        tk.Label(self.frame, text="Generated Files:").pack(anchor="w", padx=10)
        self.files_listbox = tk.Listbox(self.frame, height=8)
        self.files_listbox.pack(fill=tk.X, padx=10, pady=5)
        self.files_listbox.bind("<Double-1>", self.view_result_file)
    
    def browse_compile_db(self):
        filename = self.file_browser(
            "Select compile_commands.json",
            file_types=[("JSON Files", "compile_commands.json"), ("All JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.compile_db_entry.delete(0, tk.END)
            self.compile_db_entry.insert(0, filename)

    def browse_output_dir(self):
        dirname = self.file_browser(
            "Select Output Directory",
            file_types=[("All Files", "*.*")],
            select_dir=True
        )
        if dirname:
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.insert(0, dirname)

    def browse_analyzer_path(self):
        filename = self.file_browser(
            "Select MyStaticAnalyzer Executable",
            file_types=[("Executable Files", "*"), ("All Files", "*.*")]
        )
        if filename:
            self.analyzer_path_entry.delete(0, tk.END)
            self.analyzer_path_entry.insert(0, filename)
    
    def analyze_source(self):
        compile_db_path = self.compile_db_entry.get().strip()
        if not compile_db_path:
            messagebox.showerror("Error", "Please select a compile_commands.json file.")
            return
        
        analyzer_path = self.analyzer_path_entry.get().strip()
        if not os.path.isfile(analyzer_path):
            messagebox.showerror("Error", f"Analyzer executable not found at: {analyzer_path}")
            return
        
        output_dir = self.output_dir_entry.get().strip()
        if output_dir:
            # Set the OUTPUT_FOLDER environment variable for the analyzer
            os.environ["OUTPUT_FOLDER"] = output_dir
            # Ensure the directory exists
            os.makedirs(output_dir, exist_ok=True)
        
        # Clear previous output
        self.output_console.delete(1.0, tk.END)
        self.files_listbox.delete(0, tk.END)
        
        # Run the analyzer as a subprocess
        try:
            self.output_console.insert(tk.END, f"Running analysis on {compile_db_path}...\n")
            self.parent.update_idletasks()
            
            process = subprocess.Popen(
                [analyzer_path, compile_db_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Process and display the output in real-time
            for line in iter(process.stdout.readline, ''):
                self.output_console.insert(tk.END, line)
                self.output_console.see(tk.END)
                self.parent.update_idletasks()
            
            process.stdout.close()
            return_code = process.wait()
            
            if return_code == 0:
                self.output_console.insert(tk.END, "Analysis completed successfully.\n")
                # List output files if we have an output directory
                if output_dir and os.path.exists(output_dir):
                    self.output_console.insert(tk.END, f"Checking for output files in {output_dir}...\n")
                    files = [f for f in os.listdir(output_dir) if f.startswith("output_") and f.endswith(".json")]
                    if files:
                        self.output_console.insert(tk.END, f"Found {len(files)} result files.\n")
                        for file in sorted(files):
                            self.files_listbox.insert(tk.END, file)
                    else:
                        self.output_console.insert(tk.END, "No output files found.\n")
            else:
                self.output_console.insert(tk.END, f"Analysis failed with return code {return_code}.\n")
                
        except Exception as e:
            self.output_console.insert(tk.END, f"Error running analyzer: {str(e)}\n")
            messagebox.showerror("Error", f"Failed to run analyzer: {str(e)}")

    def view_result_file(self, event):
        selection = self.files_listbox.curselection()
        if not selection:
            return
        
        filename = self.files_listbox.get(selection[0])
        output_dir = self.output_dir_entry.get().strip()
        filepath = os.path.join(output_dir, filename)
        
        if not os.path.exists(filepath):
            messagebox.showerror("Error", f"File not found: {filepath}")
            return
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            # Display the file content in a new window
            result_window = tk.Toplevel(self.parent)
            result_window.title(f"Result: {filename}")
            result_window.geometry("600x500")
            
            # Add a text widget with scrollbar
            result_frame = tk.Frame(result_window)
            result_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
            
            result_text = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD)
            result_text.pack(expand=True, fill=tk.BOTH)
            result_text.insert(tk.END, json.dumps(data, indent=2))
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to open result file: {str(e)}")
    
    def get_settings(self):
        """Return the current settings for saving"""
        return {
            "compile_db_path": self.compile_db_entry.get().strip(),
            "output_dir_path": self.output_dir_entry.get().strip(),
            "analyzer_path": self.analyzer_path_entry.get().strip()
        }
    
    def load_settings(self, settings):
        """Load settings from the provided dictionary"""
        if "compile_db_path" in settings and settings["compile_db_path"]:
            self.compile_db_entry.delete(0, tk.END)
            self.compile_db_entry.insert(0, settings["compile_db_path"])
            
        if "output_dir_path" in settings and settings["output_dir_path"]:
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.insert(0, settings["output_dir_path"])
            
        if "analyzer_path" in settings and settings["analyzer_path"]:
            self.analyzer_path_entry.delete(0, tk.END)
            self.analyzer_path_entry.insert(0, settings["analyzer_path"]) 