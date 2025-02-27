#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import json
import os
import subprocess
from elftools.elf.elffile import ELFFile
import pickle  # Add this import for saving/loading settings

# Define a settings file path
SETTINGS_FILE = "analyzer_settings.pkl"

def extract_function_addresses(filename):
    """
    Extract function addresses from an ELF file.
    Returns a list of dictionaries with function name, entry point, and size.
    """
    functions_data = []
    try:
        with open(filename, 'rb') as f:
            elffile = ELFFile(f)
            symtab_section = elffile.get_section_by_name('.symtab')
            if symtab_section is None:
                functions_data.append({"error": "No symbol table found in this file."})
            else:
                for symbol in symtab_section.iter_symbols():
                    if symbol['st_info']['type'] == 'STT_FUNC':
                        name = symbol.name
                        addr = symbol['st_value']
                        size = symbol['st_size']
                        if name:
                            functions_data.append({
                                "name": name,
                                "entry_point": hex(addr),
                                "size": hex(size) if size else "Unknown"
                            })
    except Exception as e:
        functions_data.append({"error": str(e)})
    return functions_data

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Code Analyzer")
        self.geometry("800x700")
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        # Create tab for ELF analysis
        self.elf_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.elf_frame, text="ELF Analyzer")
        
        # Create tab for Source Code analysis
        self.source_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.source_frame, text="Source Analyzer")
        
        # Create tab for JSON Upload
        self.json_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.json_frame, text="JSON Viewer")
        
        # Create tab for Ghidra Decompiler Analysis
        self.ghidra_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ghidra_frame, text="Ghidra Analysis")
        
        # Set up ELF analyzer tab
        self.setup_elf_analyzer()
        
        # Set up Source analyzer tab
        self.setup_source_analyzer()
        
        # Set up JSON Upload tab
        self.setup_json_viewer()
        
        # Set up Ghidra Decompiler tab
        self.setup_ghidra_analyzer()
        
        # Keep a copy of the function data for searching/filtering
        self.function_data = []
        
        # Load saved settings
        self.load_settings()
        
        # Bind window close event to save settings
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def setup_elf_analyzer(self):
        # Input file selection widgets
        input_frame = tk.Frame(self.elf_frame)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(input_frame, text="Select ELF file to analyze:").pack(side=tk.LEFT)
        self.input_entry = tk.Entry(input_frame, width=50)
        self.input_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="Browse", command=self.browse_input_file).pack(side=tk.LEFT)

        # Output file selection widgets
        output_frame = tk.Frame(self.elf_frame)
        output_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(output_frame, text="Specify Output File Path:").pack(side=tk.LEFT)
        self.output_entry = tk.Entry(output_frame, width=50)
        self.output_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(output_frame, text="Browse Output", command=self.browse_output_file).pack(side=tk.LEFT)

        # Analyze button
        tk.Button(self.elf_frame, text="Analyze ELF", command=self.analyze_file).pack(pady=10)

        # Search field for filtering results
        search_frame = tk.Frame(self.elf_frame)
        search_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_entry = tk.Entry(search_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind("<KeyRelease>", self.on_search)

        # Treeview for displaying results
        tree_frame = tk.Frame(self.elf_frame)
        tree_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        self.tree = ttk.Treeview(tree_frame)
        self.tree.heading("#0", text="Function Name", anchor="w")
        self.tree.pack(expand=True, fill=tk.BOTH, side=tk.LEFT)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind double-click to toggle expansion of the tree item
        self.tree.bind("<Double-1>", self.toggle_item)

    def setup_source_analyzer(self):
        # Compilation database file selection widgets
        compile_db_frame = tk.Frame(self.source_frame)
        compile_db_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(compile_db_frame, text="Select compile_commands.json:").pack(side=tk.LEFT)
        self.compile_db_entry = tk.Entry(compile_db_frame, width=50)
        self.compile_db_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(compile_db_frame, text="Browse", command=self.browse_compile_db).pack(side=tk.LEFT)

        # Output directory selection widgets
        output_dir_frame = tk.Frame(self.source_frame)
        output_dir_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(output_dir_frame, text="Output Directory:").pack(side=tk.LEFT)
        self.output_dir_entry = tk.Entry(output_dir_frame, width=50)
        self.output_dir_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(output_dir_frame, text="Browse", command=self.browse_output_dir).pack(side=tk.LEFT)

        # Analyzer path selection
        analyzer_frame = tk.Frame(self.source_frame)
        analyzer_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(analyzer_frame, text="Path to MyStaticAnalyzer:").pack(side=tk.LEFT)
        self.analyzer_path_entry = tk.Entry(analyzer_frame, width=50)
        self.analyzer_path_entry.pack(side=tk.LEFT, padx=5)
        self.analyzer_path_entry.insert(0, "./build/MyStaticAnalyzer")  # Default path
        tk.Button(analyzer_frame, text="Browse", command=self.browse_analyzer_path).pack(side=tk.LEFT)

        # Analyze button
        tk.Button(self.source_frame, text="Analyze Source", command=self.analyze_source).pack(pady=10)

        # Output console
        tk.Label(self.source_frame, text="Analysis Output:").pack(anchor="w", padx=10)
        self.output_console = scrolledtext.ScrolledText(self.source_frame, height=15, wrap=tk.WORD)
        self.output_console.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)

        # Output files list
        tk.Label(self.source_frame, text="Generated Files:").pack(anchor="w", padx=10)
        self.files_listbox = tk.Listbox(self.source_frame, height=8)
        self.files_listbox.pack(fill=tk.X, padx=10, pady=5)
        self.files_listbox.bind("<Double-1>", self.view_result_file)

    def setup_json_viewer(self):
        # Frame for upload options
        upload_frame = ttk.LabelFrame(self.json_frame, text="Upload JSON Files")
        upload_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # ELF JSON upload
        elf_frame = tk.Frame(upload_frame)
        elf_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(elf_frame, text="ELF Analysis JSON:").pack(side=tk.LEFT)
        self.elf_json_entry = tk.Entry(elf_frame, width=50)
        self.elf_json_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(elf_frame, text="Browse", command=self.browse_elf_json).pack(side=tk.LEFT)
        tk.Button(elf_frame, text="Load", command=self.load_elf_json).pack(side=tk.LEFT, padx=5)
        
        # Feature extraction folder upload
        feature_frame = tk.Frame(upload_frame)
        feature_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(feature_frame, text="Feature Extraction Folder:").pack(side=tk.LEFT)
        self.feature_json_entry = tk.Entry(feature_frame, width=50)
        self.feature_json_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(feature_frame, text="Browse", command=self.browse_feature_folder).pack(side=tk.LEFT)
        tk.Button(feature_frame, text="Load", command=self.load_feature_jsons).pack(side=tk.LEFT, padx=5)
        
        # Ghidra decompiler JSON upload
        ghidra_frame = tk.Frame(upload_frame)
        ghidra_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(ghidra_frame, text="Ghidra Decompiler JSON:").pack(side=tk.LEFT)
        self.ghidra_json_entry = tk.Entry(ghidra_frame, width=50)
        self.ghidra_json_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(ghidra_frame, text="Browse", command=self.browse_ghidra_json).pack(side=tk.LEFT)
        tk.Button(ghidra_frame, text="Load", command=self.load_ghidra_json).pack(side=tk.LEFT, padx=5)
        
        # Create a frame for the file list and content viewer
        viewer_frame = tk.Frame(self.json_frame)
        viewer_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        
        # Left side: File list
        list_frame = tk.Frame(viewer_frame)
        list_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
        tk.Label(list_frame, text="Loaded Files:").pack(anchor="w")
        
        self.json_files_listbox = tk.Listbox(list_frame, width=30, height=20)
        self.json_files_listbox.pack(expand=True, fill=tk.BOTH)
        self.json_files_listbox.bind("<<ListboxSelect>>", self.on_json_file_select)
        
        # Right side: JSON content viewer
        content_frame = tk.Frame(viewer_frame)
        content_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH)
        tk.Label(content_frame, text="JSON Content:").pack(anchor="w")
        
        self.json_content = scrolledtext.ScrolledText(content_frame, wrap=tk.WORD)
        self.json_content.pack(expand=True, fill=tk.BOTH)
        
        # Dictionary to store loaded JSON data
        self.loaded_jsons = {}

    def setup_ghidra_analyzer(self):
        # Frame for Ghidra settings
        ghidra_settings_frame = ttk.LabelFrame(self.ghidra_frame, text="Ghidra Headless Analyzer Settings")
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
        run_frame = tk.Frame(self.ghidra_frame)
        run_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(run_frame, text="Run Ghidra Analysis", command=self.run_ghidra_analysis, bg="#4CAF50", fg="white", padx=10).pack(pady=10)
        
        # Output console
        tk.Label(self.ghidra_frame, text="Analysis Output:").pack(anchor="w", padx=10)
        self.ghidra_console = scrolledtext.ScrolledText(self.ghidra_frame, height=15, wrap=tk.WORD)
        self.ghidra_console.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        
        # View results button
        view_frame = tk.Frame(self.ghidra_frame)
        view_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Button(view_frame, text="View Results", command=self.view_ghidra_results).pack(pady=5)

    def browse_input_file(self):
        filename = self.custom_file_browser(
            "Select ELF File",
            file_types=[("ELF Files", "*"), ("All Files", "*.*")]
        )
        if filename:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, filename)

    def browse_output_file(self):
        filename = self.custom_file_browser(
            "Select Output File",
            file_types=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, filename)

    def browse_compile_db(self):
        filename = self.custom_file_browser(
            "Select compile_commands.json",
            file_types=[("JSON Files", "compile_commands.json"), ("All JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.compile_db_entry.delete(0, tk.END)
            self.compile_db_entry.insert(0, filename)

    def browse_output_dir(self):
        dirname = self.custom_file_browser(
            "Select Output Directory",
            file_types=[("All Files", "*.*")]
        )
        if dirname and os.path.isdir(dirname):
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.insert(0, dirname)

    def browse_analyzer_path(self):
        filename = self.custom_file_browser(
            "Select MyStaticAnalyzer Executable",
            file_types=[("Executable Files", "*"), ("All Files", "*.*")]
        )
        if filename:
            self.analyzer_path_entry.delete(0, tk.END)
            self.analyzer_path_entry.insert(0, filename)

    def analyze_file(self):
        input_filepath = self.input_entry.get().strip()
        if not input_filepath:
            messagebox.showerror("Error", "Please select an input file.")
            return

        output_filepath = self.output_entry.get().strip()

        # Extract function data from the ELF file
        result = extract_function_addresses(input_filepath)
        
        # If an error occurred, display it
        if len(result) == 1 and "error" in result[0]:
            self.clear_tree()
            self.tree.insert("", "end", text=result[0]["error"])
            messagebox.showerror("Error", result[0]["error"])
            return

        # Sort functions by name
        self.function_data = sorted(result, key=lambda x: x.get("name", ""))
        self.populate_tree(self.function_data)

        # Write to output file if provided
        json_result = json.dumps(result, indent=4)
        if output_filepath:
            try:
                with open(output_filepath, 'w') as out_file:
                    out_file.write(json_result)
                messagebox.showinfo("Success", f"Output written to {output_filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to write output file: {str(e)}")
        else:
            messagebox.showinfo("Info", "No output file path specified. Result displayed only.")

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
            self.update_idletasks()
            
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
                self.update_idletasks()
            
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
            result_window = tk.Toplevel(self)
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

    def clear_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def populate_tree(self, function_list):
        """Populate the tree view with functions and their details as children."""
        self.clear_tree()
        for func in function_list:
            func_name = func.get("name", "Unknown")
            parent_id = self.tree.insert("", "end", text=func_name)
            details = f"Address: {func.get('entry_point', 'N/A')}, Size: {func.get('size', 'N/A')}"
            # Insert a single child node with details
            self.tree.insert(parent_id, "end", text=details)

    def on_search(self, event):
        """Filter the tree view based on the search query."""
        query = self.search_entry.get().strip().lower()
        if query:
            filtered = [f for f in self.function_data if query in f.get("name", "").lower()]
        else:
            filtered = self.function_data
        self.populate_tree(filtered)

    def toggle_item(self, event):
        """Toggle the expansion of a tree item when double-clicked."""
        item = self.tree.identify("item", event.x, event.y)
        if self.tree.get_children(item):
            self.tree.item(item, open=not self.tree.item(item, "open"))

    def browse_elf_json(self):
        filename = self.custom_file_browser(
            "Select ELF Analysis JSON File",
            file_types=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.elf_json_entry.delete(0, tk.END)
            self.elf_json_entry.insert(0, filename)
    
    def browse_feature_folder(self):
        dirname = self.custom_file_browser(
            "Select Feature Extraction JSON Folder",
            file_types=[("All Files", "*.*")]
        )
        if dirname and os.path.isdir(dirname):
            self.feature_json_entry.delete(0, tk.END)
            self.feature_json_entry.insert(0, dirname)
    
    def load_elf_json(self):
        filepath = self.elf_json_entry.get().strip()
        if not filepath:
            messagebox.showerror("Error", "Please select an ELF analysis JSON file.")
            return
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            filename = os.path.basename(filepath)
            self.loaded_jsons[filename] = {
                "type": "elf",
                "data": data,
                "path": filepath
            }
            
            # Add to listbox if not already there
            if filename not in self.json_files_listbox.get(0, tk.END):
                self.json_files_listbox.insert(tk.END, filename)
            
            messagebox.showinfo("Success", f"Loaded ELF analysis JSON: {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load JSON file: {str(e)}")
    
    def load_feature_jsons(self):
        dirpath = self.feature_json_entry.get().strip()
        if not dirpath:
            messagebox.showerror("Error", "Please select a feature extraction JSON folder.")
            return
        
        if not os.path.isdir(dirpath):
            messagebox.showerror("Error", f"Not a valid directory: {dirpath}")
            return
        
        # Find all JSON files in the directory
        json_files = [f for f in os.listdir(dirpath) if f.endswith('.json')]
        
        if not json_files:
            messagebox.showinfo("Info", "No JSON files found in the selected directory.")
            return
        
        loaded_count = 0
        for filename in json_files:
            filepath = os.path.join(dirpath, filename)
            try:
                with open(filepath, 'r') as f:
                    data = json.load(f)
                
                self.loaded_jsons[filename] = {
                    "type": "feature",
                    "data": data,
                    "path": filepath
                }
                
                # Add to listbox if not already there
                if filename not in self.json_files_listbox.get(0, tk.END):
                    self.json_files_listbox.insert(tk.END, filename)
                
                loaded_count += 1
                
            except Exception as e:
                print(f"Failed to load {filename}: {str(e)}")
        
        if loaded_count > 0:
            messagebox.showinfo("Success", f"Loaded {loaded_count} feature extraction JSON files.")
        else:
            messagebox.showerror("Error", "Failed to load any JSON files.")
    
    def on_json_file_select(self, event):
        selection = self.json_files_listbox.curselection()
        if not selection:
            return
        
        filename = self.json_files_listbox.get(selection[0])
        if filename not in self.loaded_jsons:
            self.json_content.delete(1.0, tk.END)
            self.json_content.insert(tk.END, "Error: File data not found.")
            return
        
        # Clear previous content
        self.json_content.delete(1.0, tk.END)
        
        # Format and display the JSON content
        json_data = self.loaded_jsons[filename]["data"]
        formatted_json = json.dumps(json_data, indent=2)
        self.json_content.insert(tk.END, formatted_json)

    def browse_ghidra_json(self):
        filename = self.custom_file_browser(
            "Select Ghidra Decompiler JSON File",
            file_types=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.ghidra_json_entry.delete(0, tk.END)
            self.ghidra_json_entry.insert(0, filename)
    
    def load_ghidra_json(self):
        filepath = self.ghidra_json_entry.get().strip()
        if not filepath:
            messagebox.showerror("Error", "Please select a Ghidra decompiler JSON file.")
            return
        
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            filename = os.path.basename(filepath)
            self.loaded_jsons[filename] = {
                "type": "ghidra",
                "data": data,
                "path": filepath
            }
            
            # Add to listbox if not already there
            if filename not in self.json_files_listbox.get(0, tk.END):
                self.json_files_listbox.insert(tk.END, filename)
            
            messagebox.showinfo("Success", f"Loaded Ghidra decompiler JSON: {filename}")
            
            # Save settings after successful load
            self.save_settings()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load JSON file: {str(e)}")
    
    def browse_ghidra_path(self):
        dirname = self.custom_file_browser(
            "Select Ghidra Installation Directory",
            file_types=[("All Files", "*.*")]
        )
        if dirname and os.path.isdir(dirname):
            self.ghidra_path_entry.delete(0, tk.END)
            self.ghidra_path_entry.insert(0, dirname)
    
    def browse_project_dir(self):
        dirname = self.custom_file_browser(
            "Select Ghidra Project Directory",
            file_types=[("All Files", "*.*")]
        )
        if dirname and os.path.isdir(dirname):
            self.project_dir_entry.delete(0, tk.END)
            self.project_dir_entry.insert(0, dirname)
    
    def browse_binary_file(self):
        filename = self.custom_file_browser("Select Binary File to Analyze", 
                                           initial_dir="/mnt/linuxstorage/vlsi-open-source-tool",
                                           file_types=[("All Files", "*.*"), ("ELF Files", "*.elf"), ("Executable Files", "*.exe")])
        if filename:
            self.binary_entry.delete(0, tk.END)
            self.binary_entry.insert(0, filename)
    
    def custom_file_browser(self, title, initial_dir=None, file_types=None):
        """
        Custom file browser with search capabilities and directory shortcuts
        """
        # Create a new top-level window
        browser = tk.Toplevel(self)
        browser.title(title)
        browser.geometry("800x600")
        browser.transient(self)  # Set to be on top of the main window
        browser.grab_set()  # Modal dialog
        
        # Store the selected file
        selected_file = [None]
        
        # Create frames
        top_frame = tk.Frame(browser)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        shortcuts_frame = tk.Frame(browser)
        shortcuts_frame.pack(fill=tk.X, padx=10, pady=5)
        
        main_frame = tk.Frame(browser)
        main_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        
        bottom_frame = tk.Frame(browser)
        bottom_frame.pack(fill=tk.X, padx=10, pady=10)
        
        # Current directory display and navigation
        tk.Label(top_frame, text="Directory:").pack(side=tk.LEFT)
        current_dir_var = tk.StringVar()
        current_dir_entry = tk.Entry(top_frame, textvariable=current_dir_var, width=60)
        current_dir_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        # Set initial directory
        current_dir = initial_dir if initial_dir and os.path.isdir(initial_dir) else os.getcwd()
        current_dir_var.set(current_dir)
        
        # Go button
        def go_to_dir():
            dir_path = current_dir_var.get()
            if os.path.isdir(dir_path):
                update_file_list(dir_path)
            else:
                messagebox.showerror("Error", f"Invalid directory: {dir_path}")
        
        tk.Button(top_frame, text="Go", command=go_to_dir).pack(side=tk.LEFT)
        
        # Search functionality
        search_frame = tk.Frame(top_frame)
        search_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=search_var, width=20)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        # Directory shortcuts
        common_dirs = [
            ("Home", os.path.expanduser("~")),
            ("Root", "/"),
            ("Current Dir", os.getcwd())
        ]
        
        for label, path in common_dirs:
            if os.path.isdir(path):
                btn = tk.Button(shortcuts_frame, text=label, 
                               command=lambda p=path: (current_dir_var.set(p), update_file_list(p)))
                btn.pack(side=tk.LEFT, padx=5)
        
        # File type filter
        filter_frame = tk.Frame(shortcuts_frame)
        filter_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Label(filter_frame, text="Filter:").pack(side=tk.LEFT)
        filter_var = tk.StringVar()
        
        # Create filter options from file_types
        filter_options = ["All Files"]
        if file_types:
            filter_options.extend([ft[0] for ft in file_types])
        
        filter_menu = tk.OptionMenu(filter_frame, filter_var, *filter_options)
        filter_menu.pack(side=tk.LEFT, padx=5)
        filter_var.set("All Files")  # Default value
        
        # File listbox with scrollbar
        file_frame = tk.Frame(main_frame)
        file_frame.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        
        file_listbox = tk.Listbox(file_frame, width=40, height=20, font=("Courier", 10))
        file_listbox.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
        
        scrollbar = tk.Scrollbar(file_frame, orient="vertical", command=file_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        file_listbox.config(yscrollcommand=scrollbar.set)
        
        # Preview frame
        preview_frame = tk.Frame(main_frame)
        preview_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=10)
        
        tk.Label(preview_frame, text="File Info:").pack(anchor="w")
        file_info = tk.Text(preview_frame, height=10, width=40, wrap=tk.WORD)
        file_info.pack(expand=True, fill=tk.BOTH)
        
        # Buttons
        tk.Button(bottom_frame, text="Select", command=lambda: select_file()).pack(side=tk.RIGHT, padx=5)
        tk.Button(bottom_frame, text="Cancel", command=browser.destroy).pack(side=tk.RIGHT, padx=5)
        
        # Double-click to select or navigate
        def on_double_click(event):
            selection = file_listbox.curselection()
            if not selection:
                return
            
            item = file_listbox.get(selection[0])
            path = os.path.join(current_dir_var.get(), item)
            
            if os.path.isdir(path):
                current_dir_var.set(path)
                update_file_list(path)
            else:
                select_file(path)
        
        file_listbox.bind("<Double-1>", on_double_click)
        
        # Select file and close dialog
        def select_file(path=None):
            if path is None:
                selection = file_listbox.curselection()
                if not selection:
                    return
                
                item = file_listbox.get(selection[0])
                path = os.path.join(current_dir_var.get(), item)
                
                if os.path.isdir(path):
                    current_dir_var.set(path)
                    update_file_list(path)
                    return
            
            selected_file[0] = path
            browser.destroy()
        
        # Update file info when a file is selected
        def on_select(event):
            selection = file_listbox.curselection()
            if not selection:
                return
            
            item = file_listbox.get(selection[0])
            path = os.path.join(current_dir_var.get(), item)
            
            file_info.delete(1.0, tk.END)
            
            if os.path.isdir(path):
                file_info.insert(tk.END, f"Directory: {item}\n")
                try:
                    num_items = len(os.listdir(path))
                    file_info.insert(tk.END, f"Contains {num_items} items")
                except:
                    file_info.insert(tk.END, "Unable to read directory contents")
            else:
                file_info.insert(tk.END, f"File: {item}\n")
                try:
                    size = os.path.getsize(path)
                    file_info.insert(tk.END, f"Size: {size} bytes\n")
                    
                    # Check if it's an ELF file
                    if os.path.exists(path) and os.access(path, os.R_OK):
                        with open(path, 'rb') as f:
                            header = f.read(4)
                            if header.startswith(b'\x7fELF'):
                                file_info.insert(tk.END, "Type: ELF Binary\n")
                                
                                # Try to get more ELF info
                                try:
                                    import subprocess
                                    result = subprocess.run(['file', path], capture_output=True, text=True)
                                    file_info.insert(tk.END, f"Details: {result.stdout}")
                                except:
                                    pass
                except:
                    file_info.insert(tk.END, "Unable to read file information")
        
        file_listbox.bind("<<ListboxSelect>>", on_select)
        
        # Filter files based on search and file type
        def filter_files(files, search_text, filter_type):
            if not search_text and filter_type == "All Files":
                return files
            
            filtered = []
            for f in files:
                # Apply search filter
                if search_text and search_text.lower() not in f.lower():
                    continue
                
                # Apply type filter
                if filter_type != "All Files":
                    if filter_type == "ELF Files" and not f.endswith('.elf'):
                        # Special case for ELF files - check content if no extension
                        if not os.path.isdir(os.path.join(current_dir_var.get(), f)):
                            try:
                                with open(os.path.join(current_dir_var.get(), f), 'rb') as file:
                                    header = file.read(4)
                                    if not header.startswith(b'\x7fELF'):
                                        continue
                            except:
                                continue
                    elif filter_type == "Executable Files":
                        # Check if file is executable
                        full_path = os.path.join(current_dir_var.get(), f)
                        if not (os.path.isfile(full_path) and os.access(full_path, os.X_OK)):
                            continue
                    elif any(filter_type.startswith(ft[0]) for ft in file_types):
                        # Get the file extension pattern
                        for ft in file_types:
                            if filter_type == ft[0]:
                                ext_pattern = ft[1]
                                # Convert glob pattern to simple extension check
                                if ext_pattern.startswith("*."):
                                    ext = ext_pattern[1:]
                                    if not f.endswith(ext):
                                        continue
                
                filtered.append(f)
            
            return filtered
        
        # Update file list when directory changes
        def update_file_list(directory):
            try:
                file_listbox.delete(0, tk.END)
                
                # Add parent directory entry
                file_listbox.insert(tk.END, "..")
                
                # Get directory contents
                contents = os.listdir(directory)
                
                # Separate directories and files
                dirs = [d for d in contents if os.path.isdir(os.path.join(directory, d))]
                files = [f for f in contents if os.path.isfile(os.path.join(directory, f))]
                
                # Sort alphabetically
                dirs.sort()
                files.sort()
                
                # Filter files based on search and type
                search_text = search_var.get()
                filter_type = filter_var.get()
                
                # Always show directories, filter only files
                filtered_files = filter_files(files, search_text, filter_type)
                
                # Add directories first (with trailing slash)
                for d in dirs:
                    file_listbox.insert(tk.END, d + "/")
                
                # Then add files
                for f in filtered_files:
                    file_listbox.insert(tk.END, f)
                
                current_dir_var.set(directory)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read directory: {str(e)}")
        
        # Update when search or filter changes
        def on_search_change(*args):
            update_file_list(current_dir_var.get())
        
        search_var.trace("w", on_search_change)
        filter_var.trace("w", on_search_change)
        
        # Initial file list update
        update_file_list(current_dir)
        
        # Handle Enter key in directory entry
        current_dir_entry.bind("<Return>", lambda event: go_to_dir())
        
        # Wait for the dialog to be closed
        browser.wait_window()
        
        return selected_file[0]
    
    def browse_script_file(self):
        filename = self.custom_file_browser(
            "Select Ghidra Script File",
            file_types=[("Python Files", "*.py"), ("All Files", "*.*")]
        )
        if filename:
            self.script_entry.delete(0, tk.END)
            self.script_entry.insert(0, filename)
    
    def browse_ghidra_output(self):
        filename = self.custom_file_browser(
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
        self.update_idletasks()
        
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
                self.update_idletasks()
            
            process.stdout.close()
            return_code = process.wait()
            
            if return_code == 0:
                self.ghidra_console.insert(tk.END, "\nGhidra analysis completed successfully.\n")
                # Update the output file path in the JSON viewer
                self.ghidra_json_entry.delete(0, tk.END)
                self.ghidra_json_entry.insert(0, output_file)
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
        self.ghidra_json_entry.delete(0, tk.END)
        self.ghidra_json_entry.insert(0, output_file)
        self.load_ghidra_json()
        
        # Switch to the JSON Viewer tab
        self.notebook.select(self.json_frame)

    def save_settings(self):
        """Save current file paths and settings to a file"""
        settings = {
            "elf_input_path": self.input_entry.get().strip(),
            "elf_output_path": self.output_entry.get().strip(),
            "compile_db_path": self.compile_db_entry.get().strip(),
            "output_dir_path": self.output_dir_entry.get().strip(),
            "analyzer_path": self.analyzer_path_entry.get().strip(),
            "elf_json_path": self.elf_json_entry.get().strip(),
            "feature_json_dir": self.feature_json_entry.get().strip(),
            "ghidra_json_path": self.ghidra_json_entry.get().strip(),
            "ghidra_path": self.ghidra_path_entry.get().strip(),
            "project_dir": self.project_dir_entry.get().strip(),
            "binary_file": self.binary_entry.get().strip(),
            "script_file": self.script_entry.get().strip(),
            "ghidra_output": self.ghidra_output_entry.get().strip(),
            "loaded_jsons": {k: v["path"] for k, v in self.loaded_jsons.items()}
        }
        
        try:
            with open(SETTINGS_FILE, 'wb') as f:
                pickle.dump(settings, f)
        except Exception as e:
            print(f"Failed to save settings: {str(e)}")
    
    def load_settings(self):
        """Load saved settings if they exist"""
        if not os.path.exists(SETTINGS_FILE):
            return
        
        try:
            with open(SETTINGS_FILE, 'rb') as f:
                settings = pickle.load(f)
            
            # Restore file paths
            if "elf_input_path" in settings and settings["elf_input_path"]:
                self.input_entry.delete(0, tk.END)
                self.input_entry.insert(0, settings["elf_input_path"])
                
            if "elf_output_path" in settings and settings["elf_output_path"]:
                self.output_entry.delete(0, tk.END)
                self.output_entry.insert(0, settings["elf_output_path"])
                
            if "compile_db_path" in settings and settings["compile_db_path"]:
                self.compile_db_entry.delete(0, tk.END)
                self.compile_db_entry.insert(0, settings["compile_db_path"])
                
            if "output_dir_path" in settings and settings["output_dir_path"]:
                self.output_dir_entry.delete(0, tk.END)
                self.output_dir_entry.insert(0, settings["output_dir_path"])
                
            if "analyzer_path" in settings and settings["analyzer_path"]:
                self.analyzer_path_entry.delete(0, tk.END)
                self.analyzer_path_entry.insert(0, settings["analyzer_path"])
                
            if "elf_json_path" in settings and settings["elf_json_path"]:
                self.elf_json_entry.delete(0, tk.END)
                self.elf_json_entry.insert(0, settings["elf_json_path"])
                
            if "feature_json_dir" in settings and settings["feature_json_dir"]:
                self.feature_json_entry.delete(0, tk.END)
                self.feature_json_entry.insert(0, settings["feature_json_dir"])
                
            if "ghidra_json_path" in settings and settings["ghidra_json_path"]:
                self.ghidra_json_entry.delete(0, tk.END)
                self.ghidra_json_entry.insert(0, settings["ghidra_json_path"])
                
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
            
            # Reload previously loaded JSON files
            if "loaded_jsons" in settings:
                for filename, filepath in settings["loaded_jsons"].items():
                    if os.path.exists(filepath):
                        try:
                            with open(filepath, 'r') as f:
                                data = json.load(f)
                            
                            # Determine file type
                            file_type = "elf"
                            if "ghidra_json_path" in settings and filepath == settings["ghidra_json_path"]:
                                file_type = "ghidra"
                            elif "elf_json_path" in settings and filepath == settings["elf_json_path"]:
                                file_type = "elf"
                            else:
                                file_type = "feature"
                                
                            self.loaded_jsons[filename] = {
                                "type": file_type,
                                "data": data,
                                "path": filepath
                            }
                            
                            # Add to listbox if not already there
                            if filename not in self.json_files_listbox.get(0, tk.END):
                                self.json_files_listbox.insert(tk.END, filename)
                        except Exception as e:
                            print(f"Failed to reload {filename}: {str(e)}")
                
        except Exception as e:
            print(f"Failed to load settings: {str(e)}")
    
    def on_closing(self):
        """Save settings when the application is closed"""
        self.save_settings()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()
