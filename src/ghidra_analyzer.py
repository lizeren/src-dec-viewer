import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import json
import os
import subprocess

class GhidraAnalyzerTab:
    def __init__(self, parent, file_browser, notebook, json_viewer_tab):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        self.file_browser = file_browser
        self.notebook = notebook
        self.json_viewer_tab = json_viewer_tab
        
        self.setup_ui()
    
    def setup_ui(self):
        # Frame for Ghidra settings
        ghidra_settings_frame = ttk.LabelFrame(self.frame, text="Ghidra Headless Analyzer Settings")
        ghidra_settings_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Ghidra installation path
        ghidra_path_frame = tk.Frame(ghidra_settings_frame)
        ghidra_path_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(ghidra_path_frame, text="Ghidra Installation Path:").pack(side=tk.LEFT)
        self.ghidra_path_entry = tk.Entry(ghidra_path_frame, width=50)
        self.ghidra_path_entry.pack(side=tk.LEFT, padx=5)
        self.ghidra_path_entry.insert(0, "~/Desktop/ghidra")  # Default path
        tk.Button(ghidra_path_frame, text="Browse", command=self.browse_ghidra_path).pack(side=tk.LEFT)
        
        # Project directory
        project_dir_frame = tk.Frame(ghidra_settings_frame)
        project_dir_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(project_dir_frame, text="Ghidra Project Directory:").pack(side=tk.LEFT)
        self.project_dir_entry = tk.Entry(project_dir_frame, width=50)
        self.project_dir_entry.pack(side=tk.LEFT, padx=5)
        self.project_dir_entry.insert(0, "/home/lizeren/research")  # Default path
        tk.Button(project_dir_frame, text="Browse", command=self.browse_project_dir).pack(side=tk.LEFT)
        
        # Binary file to analyze
        binary_frame = tk.Frame(ghidra_settings_frame)
        binary_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(binary_frame, text="Binary File to Analyze:").pack(side=tk.LEFT)
        self.binary_entry = tk.Entry(binary_frame, width=50)
        self.binary_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(binary_frame, text="Browse", command=self.browse_binary_file).pack(side=tk.LEFT)
        
        # Script path
        script_frame = tk.Frame(ghidra_settings_frame)
        script_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(script_frame, text="Ghidra Script Path:").pack(side=tk.LEFT)
        self.script_entry = tk.Entry(script_frame, width=50)
        self.script_entry.pack(side=tk.LEFT, padx=5)
        self.script_entry.insert(0, "dec_feature_extraction.py")  # Default script name
        tk.Button(script_frame, text="Browse", command=self.browse_script_file).pack(side=tk.LEFT)
        
        # Output file path
        output_frame = tk.Frame(ghidra_settings_frame)
        output_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(output_frame, text="Output JSON Path:").pack(side=tk.LEFT)
        self.ghidra_output_entry = tk.Entry(output_frame, width=50)
        self.ghidra_output_entry.pack(side=tk.LEFT, padx=5)
        self.ghidra_output_entry.insert(0, "/mnt/linuxstorage/vlsi-open-source-tool/src_analyzer/output/dec_function_details.json")  # Default output path
        tk.Button(output_frame, text="Browse", command=self.browse_ghidra_output).pack(side=tk.LEFT)
        
        # Run button
        run_frame = tk.Frame(self.frame)
        run_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(run_frame, text="Run Ghidra Analysis", command=self.run_ghidra_analysis, bg="#4CAF50", fg="white", padx=10).pack(pady=10)
        
        # Output console
        tk.Label(self.frame, text="Analysis Output:").pack(anchor="w", padx=10)
        self.ghidra_console = scrolledtext.ScrolledText(self.frame, height=15, wrap=tk.WORD)
        self.ghidra_console.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        
        # View results button
        view_frame = tk.Frame(self.frame)
        view_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(view_frame, text="View Results", command=self.view_ghidra_results).pack(pady=5)
    
    def browse_ghidra_path(self):
        dirname = self.file_browser(
            "Select Ghidra Installation Directory",
            file_types=[("All Files", "*.*")]
        )
        if dirname and os.path.isdir(dirname):
            self.ghidra_path_entry.delete(0, tk.END)
            self.ghidra_path_entry.insert(0, dirname)
    
    def browse_project_dir(self):
        dirname = self.file_browser(
            "Select Ghidra Project Directory",
            file_types=[("All Files", "*.*")]
        )
        if dirname and os.path.isdir(dirname):
            self.project_dir_entry.delete(0, tk.END)
            self.project_dir_entry.insert(0, dirname)
    
    def browse_binary_file(self):
        filename = self.file_browser(
            "Select Binary File to Analyze", 
            initial_dir="/mnt/linuxstorage/vlsi-open-source-tool",
            file_types=[("All Files", "*.*"), ("ELF Files", "*.elf"), ("Executable Files", "*.exe")]
        )
        if filename:
            self.binary_entry.delete(0, tk.END)
            self.binary_entry.insert(0, filename)
    
    def browse_script_file(self):
        filename = self.file_browser(
            "Select Ghidra Script File",
            file_types=[("Python Files", "*.py"), ("All Files", "*.*")]
        )
        if filename:
            self.script_entry.delete(0, tk.END)
            self.script_entry.insert(0, filename)
    
    def browse_ghidra_output(self):
        filename = self.file_browser(
            "Select Output JSON File",
            file_types=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.ghidra_output_entry.delete(0, tk.END)
            self.ghidra_output_entry.insert(0, filename)
    
    def run_ghidra_analysis(self):
        # Get paths from entries
        ghidra_path = os.path.expanduser(self.ghidra_path_entry.get().strip())
        project_dir = os.path.expanduser(self.project_dir_entry.get().strip())
        binary_file = self.binary_entry.get().strip()
        script_file = self.script_entry.get().strip()
        output_file = self.ghidra_output_entry.get().strip()
        
        # Validate inputs
        if not os.path.exists(ghidra_path):
            messagebox.showerror("Error", f"Ghidra installation path not found: {ghidra_path}")
            return
        
        if not os.path.exists(project_dir):
            messagebox.showerror("Error", f"Project directory not found: {project_dir}")
            return
        
        if not binary_file:
            messagebox.showerror("Error", "Please specify a binary file to analyze.")
            return
        
        # Ensure the output directory exists
        output_dir = os.path.dirname(output_file)
        if output_dir and not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to create output directory: {str(e)}")
                return
        
        # Update the script file with the correct output path if needed
        if script_file.endswith('.py') and os.path.exists(script_file):
            try:
                with open(script_file, 'r') as f:
                    script_content = f.read()
                
                # Check if we need to update the OUTPUT_FILE path
                if "OUTPUT_FILE =" in script_content:
                    script_content = script_content.replace(
                        'OUTPUT_FILE = "/mnt/linuxstorage/vlsi-open-source-tool/src_analyzer/output/dec_function_details.json"',
                        f'OUTPUT_FILE = "{output_file}"'
                    )
                    with open(script_file, 'w') as f:
                        f.write(script_content)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to update script file: {str(e)}")
                return
        
        # Clear previous output
        self.ghidra_console.delete(1.0, tk.END)
        
        # Construct the command
        binary_name = os.path.basename(binary_file)
        headless_script = os.path.join(ghidra_path, "support", "analyzeHeadless")
        
        command = f"{headless_script} {project_dir} research -process {binary_name} -noanalysis -postScript {script_file}"
        
        self.ghidra_console.insert(tk.END, f"Running command: {command}\n\n")
        self.parent.update_idletasks()
        
        # Run the command
        try:
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Process and display the output in real-time
            for line in iter(process.stdout.readline, ''):
                self.ghidra_console.insert(tk.END, line)
                self.ghidra_console.see(tk.END)
                self.parent.update_idletasks()
            
            process.stdout.close()
            return_code = process.wait()
            
            if return_code == 0:
                self.ghidra_console.insert(tk.END, "\nGhidra analysis completed successfully.\n")
                # Update the output file path in the JSON viewer
                self.json_viewer_tab.ghidra_json_entry.delete(0, tk.END)
                self.json_viewer_tab.ghidra_json_entry.insert(0, output_file)
            else:
                self.ghidra_console.insert(tk.END, f"\nGhidra analysis failed with return code {return_code}.\n")
                
        except Exception as e:
            self.ghidra_console.insert(tk.END, f"\nError running Ghidra: {str(e)}\n")
            messagebox.showerror("Error", f"Failed to run Ghidra: {str(e)}")
    
    def view_ghidra_results(self):
        output_file = self.ghidra_output_entry.get().strip()
        if not os.path.exists(output_file):
            messagebox.showerror("Error", f"Output file not found: {output_file}")
            return
        
        # Load the results
        self.json_viewer_tab.ghidra_json_entry.delete(0, tk.END)
        self.json_viewer_tab.ghidra_json_entry.insert(0, output_file)
        self.json_viewer_tab.load_ghidra_json()
        
        # Switch to the JSON Viewer tab
        self.notebook.select(self.json_viewer_tab.frame)
    
    def get_settings(self):
        """Return the current settings for saving"""
        return {
            "ghidra_path": self.ghidra_path_entry.get().strip(),
            "project_dir": self.project_dir_entry.get().strip(),
            "binary_file": self.binary_entry.get().strip(),
            "script_file": self.script_entry.get().strip(),
            "ghidra_output": self.ghidra_output_entry.get().strip()
        }
    
    def load_settings(self, settings):
        """Load settings from the provided dictionary"""
        if "ghidra_path" in settings and settings["ghidra_path"]:
            self.ghidra_path_entry.delete(0, tk.END)
            self.ghidra_path_entry.insert(0, settings["ghidra_path"])
            
        if "project_dir" in settings and settings["project_dir"]:
            self.project_dir_entry.delete(0, tk.END)
            self.project_dir_entry.insert(0, settings["project_dir"])
            
        if "binary_file" in settings and settings["binary_file"]:
            self.binary_entry.delete(0, tk.END)
            self.binary_entry.insert(0, settings["binary_file"])
            
        if "script_file" in settings and settings["script_file"]:
            self.script_entry.delete(0, tk.END)
            self.script_entry.insert(0, settings["script_file"])
            
        if "ghidra_output" in settings and settings["ghidra_output"]:
            self.ghidra_output_entry.delete(0, tk.END)
            self.ghidra_output_entry.insert(0, settings["ghidra_output"]) 