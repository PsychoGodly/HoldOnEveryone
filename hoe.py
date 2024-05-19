import os
import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import win32security
import ntsecuritycon as con

# Create the main application window
root = tk.Tk()
root.title("HOE Actions")
root.geometry("600x400")
root.configure(bg='#f0f0f0')

# Create a notebook for tabs
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both')

# Create frames for each tab
main_frame = ttk.Frame(notebook)
history_frame = ttk.Frame(notebook)
notebook.add(main_frame, text='Main')
notebook.add(history_frame, text='History')

# Variables to keep track of selected path and permission state
selected_path = tk.StringVar()
history = []

# Function to log actions
def log_action(path):
    global history
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"{timestamp}: {path}"
    history.append(log_entry)
    
    # Append to the log file
    log_dir = "HOE Actions"
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    log_file = os.path.join(log_dir, "logs.txt")
    with open(log_file, "a") as file:
        file.write(log_entry + "\n")

# Function to grant permissions
def grant_permissions():
    path = selected_path.get()
    if not path:
        messagebox.showwarning("Warning", "Please select a file or folder first.")
        return

    try:
        # Get the security descriptor for the file or folder
        sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
        
        # Get the DACL
        dacl = sd.GetSecurityDescriptorDacl()
        
        # Create a new DACL if none exists
        if dacl is None:
            dacl = win32security.ACL()

        # Get the SID for 'Everyone'
        everyone, domain, type = win32security.LookupAccountName("", "Everyone")

        # Determine flags based on whether the path is a directory or a file
        flags = con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE if os.path.isdir(path) else 0

        # Add an ACE to the DACL that allows full control to 'Everyone'
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, flags, con.FILE_ALL_ACCESS, everyone)
        
        # Set the new DACL for the file or folder
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)
        
        log_action(path)
        messagebox.showinfo("Success", "Now you have access")
        messagebox.showinfo("Note", "You can only revert changes manually")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to grant permissions: {e}")

# Function to select a file or folder
def select_path():
    path = filedialog.askopenfilename()  # Ask for a file
    if not path:  # If no file selected, ask for a folder
        path = filedialog.askdirectory()
    selected_path.set(path)

# Function to populate history listbox
def populate_history():
    for entry in history:
        history_listbox.insert(tk.END, entry)

# Function to open the selected item in the history
def open_selected(event):
    selected_index = history_listbox.curselection()
    if selected_index:
        log_entry = history[selected_index[0]]
        path = log_entry.split(": ")[1]
        if os.path.exists(path):
            os.startfile(path)
        else:
            messagebox.showerror("Error", "Path does not exist")

# Create UI elements for the main tab
select_button = tk.Button(main_frame, text="Select File or Folder", command=select_path, bg='#6200ea', fg='#ffffff')
select_button.pack(pady=10)
path_entry = tk.Entry(main_frame, textvariable=selected_path, width=80, state='readonly')
path_entry.pack(pady=10)
grant_button = tk.Button(main_frame, text="Get Access", command=grant_permissions, bg='#6200ea', fg='#ffffff')
grant_button.pack(pady=20)

# Create UI elements for the history tab
history_label = tk.Label(history_frame, text="History of Permissions Changes", bg='#f0f0f0')
history_label.pack(pady=10)
history_listbox = tk.Listbox(history_frame, width=80, height=15)
history_listbox.pack(pady=10)
history_listbox.bind('<Double-1>', open_selected)
populate_history()

# Start the application
root.mainloop()
