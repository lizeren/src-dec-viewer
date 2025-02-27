#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox, ttk, scrolledtext
import json
import os
import subprocess
from elftools.elf.elffile import ELFFile

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
        
        # Set up ELF analyzer tab
        self.setup_elf_analyzer()
        
        # Set up Source analyzer tab
        self.setup_source_analyzer()
        
        # Set up JSON Upload tab
        self.setup_json_viewer()
        
        # Keep a copy of the function data for searching/filtering
        self.function_data = []

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

    def browse_input_file(self):
        filename = filedialog.askopenfilename(
            title="Select ELF File",
            filetypes=[("ELF Files", "*"), ("All Files", "*.*")]
        )
        if filename:
            self.input_entry.delete(0, tk.END)
            self.input_entry.insert(0, filename)

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(
            title="Select Output File",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.output_entry.delete(0, tk.END)
            self.output_entry.insert(0, filename)

    def browse_compile_db(self):
        filename = filedialog.askopenfilename(
            title="Select compile_commands.json",
            filetypes=[("JSON Files", "compile_commands.json"), ("All JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.compile_db_entry.delete(0, tk.END)
            self.compile_db_entry.insert(0, filename)

    def browse_output_dir(self):
        dirname = filedialog.askdirectory(
            title="Select Output Directory"
        )
        if dirname:
            self.output_dir_entry.delete(0, tk.END)
            self.output_dir_entry.insert(0, dirname)

    def browse_analyzer_path(self):
        filename = filedialog.askopenfilename(
            title="Select MyStaticAnalyzer Executable",
            filetypes=[("Executable Files", "*"), ("All Files", "*.*")]
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
        filename = filedialog.askopenfilename(
            title="Select ELF Analysis JSON File",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.elf_json_entry.delete(0, tk.END)
            self.elf_json_entry.insert(0, filename)
    
    def browse_feature_folder(self):
        dirname = filedialog.askdirectory(
            title="Select Feature Extraction JSON Folder"
        )
        if dirname:
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

if __name__ == "__main__":
    app = App()
    app.mainloop()
