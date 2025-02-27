#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, font

from elf_analyzer import ElfAnalyzerTab
from source_analyzer import SourceAnalyzerTab
from json_viewer import JsonViewerTab
from ghidra_analyzer import GhidraAnalyzerTab
from file_browser import custom_file_browser
from settings_manager import SettingsManager

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Code Analyzer")
        
        # Increase window size from 800x700 to 1024x800
        self.geometry("1024x800")
        
        # Configure default font size
        default_font = font.nametofont("TkDefaultFont")
        default_font.configure(size=11)  # Increase from default (usually 9 or 10)
        
        text_font = font.nametofont("TkTextFont")
        text_font.configure(size=11)
        
        fixed_font = font.nametofont("TkFixedFont")
        fixed_font.configure(size=11)
        
        # Apply the font configuration
        self.option_add("*Font", default_font)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)
        
        # Initialize tabs
        self.json_viewer_tab = JsonViewerTab(self.notebook, self.file_browser)
        self.notebook.add(self.json_viewer_tab.frame, text="JSON Viewer")
        
        self.elf_analyzer_tab = ElfAnalyzerTab(self.notebook, self.file_browser)
        self.notebook.add(self.elf_analyzer_tab.frame, text="ELF Analyzer")
        
        self.source_analyzer_tab = SourceAnalyzerTab(self.notebook, self.file_browser)
        self.notebook.add(self.source_analyzer_tab.frame, text="Source Analyzer")
        
        self.ghidra_analyzer_tab = GhidraAnalyzerTab(self.notebook, self.file_browser, self.notebook, self.json_viewer_tab)
        self.notebook.add(self.ghidra_analyzer_tab.frame, text="Ghidra Analysis")
        
        # Load saved settings
        self.load_settings()
        
        # Bind window close event to save settings
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def file_browser(self, title, file_types=None, initial_dir=None, select_dir=False):
        """Wrapper for the custom file browser"""
        return custom_file_browser(self, title, initial_dir, file_types, select_dir)
    
    def save_settings(self):
        """Save current settings from all tabs"""
        settings = {}
        
        # Collect settings from each tab
        settings.update(self.elf_analyzer_tab.get_settings())
        settings.update(self.source_analyzer_tab.get_settings())
        settings.update(self.json_viewer_tab.get_settings())
        settings.update(self.ghidra_analyzer_tab.get_settings())
        
        # Save settings
        SettingsManager.save_settings(settings)
    
    def load_settings(self):
        """Load settings and apply to all tabs"""
        settings = SettingsManager.load_settings()
        if not settings:
            return
        
        # Apply settings to each tab
        self.elf_analyzer_tab.load_settings(settings)
        self.source_analyzer_tab.load_settings(settings)
        self.json_viewer_tab.load_settings(settings)
        self.ghidra_analyzer_tab.load_settings(settings)
    
    def on_closing(self):
        """Save settings when the application is closed"""
        self.save_settings()
        self.destroy()

if __name__ == "__main__":
    app = App()
    app.mainloop()