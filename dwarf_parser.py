#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import json
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
        self.title("ELF Analyzer")
        self.geometry("700x600")

        # Input file selection widgets
        input_frame = tk.Frame(self)
        input_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(input_frame, text="Select ELF file to analyze:").pack(side=tk.LEFT)
        self.input_entry = tk.Entry(input_frame, width=50)
        self.input_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(input_frame, text="Browse", command=self.browse_input_file).pack(side=tk.LEFT)

        # Output file selection widgets
        output_frame = tk.Frame(self)
        output_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(output_frame, text="Specify Output File Path:").pack(side=tk.LEFT)
        self.output_entry = tk.Entry(output_frame, width=50)
        self.output_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(output_frame, text="Browse Output", command=self.browse_output_file).pack(side=tk.LEFT)

        # Analyze button
        tk.Button(self, text="Analyze", command=self.analyze_file).pack(pady=10)

        # Search field for filtering results
        search_frame = tk.Frame(self)
        search_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_entry = tk.Entry(search_frame, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=5)
        self.search_entry.bind("<KeyRelease>", self.on_search)

        # Treeview for displaying results
        tree_frame = tk.Frame(self)
        tree_frame.pack(expand=True, fill=tk.BOTH, padx=10, pady=5)
        self.tree = ttk.Treeview(tree_frame)
        self.tree.heading("#0", text="Function Name", anchor="w")
        self.tree.pack(expand=True, fill=tk.BOTH, side=tk.LEFT)
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Bind double-click to toggle expansion of the tree item
        self.tree.bind("<Double-1>", self.toggle_item)

        # Keep a copy of the function data for searching/filtering
        self.function_data = []

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

if __name__ == "__main__":
    app = App()
    app.mainloop()
