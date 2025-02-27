#!/usr/bin/env python3
import tkinter as tk
from tkinter import filedialog, messagebox
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
        self.geometry("600x500")

        # Input file selection widgets
        self.input_label = tk.Label(self, text="Select ELF file to analyze:")
        self.input_label.pack(pady=5)
        
        self.input_entry = tk.Entry(self, width=50)
        self.input_entry.pack(pady=5)

        self.input_browse_button = tk.Button(self, text="Browse", command=self.browse_input_file)
        self.input_browse_button.pack(pady=5)

        # Output file selection widgets
        self.output_label = tk.Label(self, text="Specify Output File Path:")
        self.output_label.pack(pady=5)

        self.output_entry = tk.Entry(self, width=50)
        self.output_entry.pack(pady=5)

        self.output_browse_button = tk.Button(self, text="Browse Output", command=self.browse_output_file)
        self.output_browse_button.pack(pady=5)

        # Analyze button
        self.analyze_button = tk.Button(self, text="Analyze", command=self.analyze_file)
        self.analyze_button.pack(pady=10)

        # Text widget to display analysis result
        self.text_area = tk.Text(self, wrap=tk.NONE)
        self.text_area.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

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

        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, "Analyzing file...\n")
        self.update()

        result = extract_function_addresses(input_filepath)
        json_result = json.dumps(result, indent=4)
        self.text_area.delete(1.0, tk.END)
        self.text_area.insert(tk.END, json_result)

        # If an output file path is provided, write the result to that file
        if output_filepath:
            try:
                with open(output_filepath, 'w') as out_file:
                    out_file.write(json_result)
                messagebox.showinfo("Success", f"Output written to {output_filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to write output file: {str(e)}")
        else:
            messagebox.showinfo("Info", "No output file path specified. Result displayed only.")

if __name__ == "__main__":
    app = App()
    app.mainloop()
