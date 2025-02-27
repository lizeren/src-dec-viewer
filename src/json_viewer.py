import tkinter as tk
from tkinter import messagebox, ttk, scrolledtext
import json
import os

class JsonViewerTab:
    def __init__(self, parent, file_browser):
        self.parent = parent
        self.frame = ttk.Frame(parent)
        self.file_browser = file_browser
        
        # Dictionary to store loaded JSON data
        self.loaded_jsons = {}
        
        self.setup_ui()
    
    def setup_ui(self):
        # Frame for upload options
        upload_frame = ttk.LabelFrame(self.frame, text="Upload JSON Files")
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
        viewer_frame = tk.Frame(self.frame)
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
    
    def browse_elf_json(self):
        filename = self.file_browser(
            "Select ELF Analysis JSON File",
            file_types=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.elf_json_entry.delete(0, tk.END)
            self.elf_json_entry.insert(0, filename)
    
    def browse_feature_folder(self):
        dirname = self.file_browser(
            "Select Feature Extraction JSON Folder",
            file_types=[("All Files", "*.*")]
        )
        if dirname and os.path.isdir(dirname):
            self.feature_json_entry.delete(0, tk.END)
            self.feature_json_entry.insert(0, dirname)
    
    def browse_ghidra_json(self):
        filename = self.file_browser(
            "Select Ghidra Decompiler JSON File",
            file_types=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filename:
            self.ghidra_json_entry.delete(0, tk.END)
            self.ghidra_json_entry.insert(0, filename)
    
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
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load JSON file: {str(e)}")
    
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
    
    def get_settings(self):
        """Return the current settings for saving"""
        return {
            "elf_json_path": self.elf_json_entry.get().strip(),
            "feature_json_dir": self.feature_json_entry.get().strip(),
            "ghidra_json_path": self.ghidra_json_entry.get().strip(),
            "loaded_jsons": {k: v["path"] for k, v in self.loaded_jsons.items()}
        }
    
    def load_settings(self, settings):
        """Load settings from the provided dictionary"""
        if "elf_json_path" in settings and settings["elf_json_path"]:
            self.elf_json_entry.delete(0, tk.END)
            self.elf_json_entry.insert(0, settings["elf_json_path"])
            
        if "feature_json_dir" in settings and settings["feature_json_dir"]:
            self.feature_json_entry.delete(0, tk.END)
            self.feature_json_entry.insert(0, settings["feature_json_dir"])
            
        if "ghidra_json_path" in settings and settings["ghidra_json_path"]:
            self.ghidra_json_entry.delete(0, tk.END)
            self.ghidra_json_entry.insert(0, settings["ghidra_json_path"])
        
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