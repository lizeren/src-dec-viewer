import tkinter as tk
from tkinter import messagebox
import os
import subprocess

def custom_file_browser(parent, title, initial_dir=None, file_types=None, select_dir=False):
    """
    Custom file browser with search capabilities and directory shortcuts
    
    Args:
        parent: The parent window
        title: Title for the browser window
        initial_dir: Initial directory to display
        file_types: List of tuples with file type descriptions and patterns
        select_dir: If True, allows selecting directories instead of files
        
    Returns:
        Selected file/directory path or None if canceled
    """
    # Create a new top-level window
    browser = tk.Toplevel(parent)
    browser.title(title)
    # Increase window size from 800x600 to 1024x700
    browser.geometry("1024x700")
    browser.transient(parent)  # Set to be on top of the main window
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
    current_dir_entry = tk.Entry(top_frame, textvariable=current_dir_var, width=60, font=("TkDefaultFont", 11))
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
    search_entry = tk.Entry(search_frame, textvariable=search_var, width=20, font=("TkDefaultFont", 11))
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
    
    # Increase font size from 10 to 12
    file_listbox = tk.Listbox(file_frame, width=40, height=20, font=("Courier", 12))
    file_listbox.pack(side=tk.LEFT, expand=True, fill=tk.BOTH)
    
    scrollbar = tk.Scrollbar(file_frame, orient="vertical", command=file_listbox.yview)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    file_listbox.config(yscrollcommand=scrollbar.set)
    
    # Preview frame
    preview_frame = tk.Frame(main_frame)
    preview_frame.pack(side=tk.RIGHT, expand=True, fill=tk.BOTH, padx=10)
    
    tk.Label(preview_frame, text="File Info:").pack(anchor="w")
    # Increase font size
    file_info = tk.Text(preview_frame, height=10, width=40, wrap=tk.WORD, font=("TkDefaultFont", 11))
    file_info.pack(expand=True, fill=tk.BOTH)
    
    # Buttons
    select_button_text = "Select Directory" if select_dir else "Select"
    tk.Button(bottom_frame, text=select_button_text, command=lambda: select_file()).pack(side=tk.RIGHT, padx=5)
    tk.Button(bottom_frame, text="Cancel", command=browser.destroy).pack(side=tk.RIGHT, padx=5)
    
    # If selecting directories, add a button to select the current directory
    if select_dir:
        tk.Button(bottom_frame, text="Select Current Directory", 
                 command=lambda: select_current_dir()).pack(side=tk.RIGHT, padx=5)
    
    # Function to select the current directory
    def select_current_dir():
        selected_file[0] = current_dir_var.get()
        browser.destroy()
    
    # Double-click to select or navigate
    def on_double_click(event):
        selection = file_listbox.curselection()
        if not selection:
            return
        
        item = file_listbox.get(selection[0])
        
        # Fix for parent directory navigation
        if item == "..":
            path = os.path.dirname(os.path.normpath(current_dir_var.get()))
        else:
            path = os.path.join(current_dir_var.get(), item.rstrip('/'))
        
        if os.path.isdir(path):
            # If selecting directories and double-clicking, select the directory
            if select_dir and item != "..":
                selected_file[0] = path
                browser.destroy()
            else:
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
            
            # Fix for parent directory navigation
            if item == "..":
                path = os.path.dirname(os.path.normpath(current_dir_var.get()))
            else:
                path = os.path.join(current_dir_var.get(), item.rstrip('/'))
            
            if os.path.isdir(path):
                if select_dir:
                    # If we're selecting directories, select this directory
                    selected_file[0] = path
                    browser.destroy()
                else:
                    # Otherwise navigate into it
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
        
        # Fix for parent directory navigation
        if item == "..":
            path = os.path.dirname(os.path.normpath(current_dir_var.get()))
        else:
            path = os.path.join(current_dir_var.get(), item.rstrip('/'))
        
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
            # Normalize the directory path to resolve any ".." or "." components
            directory = os.path.normpath(directory)
            
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