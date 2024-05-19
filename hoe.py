import os
import keyboard
import win32security
import ntsecuritycon as con
import tkinter as tk
from tkinter import filedialog

# Function to grant permissions
def grant_permissions(path):
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
        
        print(f"Granted full control to 'Everyone' for {path}")
    except Exception as e:
        print(f"Failed to grant permissions: {e}")

# Function to revoke permissions
def revoke_permissions(path):
    try:
        # Get the security descriptor for the file or folder
        sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
        
        # Get the DACL
        dacl = sd.GetSecurityDescriptorDacl()

        # Create a new DACL
        new_dacl = win32security.ACL()

        # Get the SID for 'Everyone'
        everyone, domain, type = win32security.LookupAccountName("", "Everyone")

        # Copy all ACEs except those for 'Everyone' to the new DACL
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            ace_sid = ace[2]
            if ace_sid != everyone:
                new_dacl.AddAceEx(ace[0], ace[1], ace[2], ace[3])

        # Set the new DACL for the file or folder
        sd.SetSecurityDescriptorDacl(1, new_dacl, 0)
        win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)
        
        print(f"Revoked permissions for 'Everyone' from {path}")
    except Exception as e:
        print(f"Failed to revoke permissions: {e}")

# Function to select a file or folder
def select_path():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    path = filedialog.askopenfilename()  # Ask for a file
    if not path:  # If no file selected, ask for a folder
        path = filedialog.askdirectory()
    return path

# Variable to keep track of the permission state
permissions_granted = False

def toggle_permissions():
    global permissions_granted, selected_path
    if selected_path:
        if permissions_granted:
            revoke_permissions(selected_path)
        else:
            grant_permissions(selected_path)
        permissions_granted = not permissions_granted
    else:
        print("No path selected.")

# Initial file or folder selection
selected_path = select_path()

# Set the hotkey to toggle permissions
keyboard.add_hotkey('ctrl+shift+e', toggle_permissions)

print("Press Ctrl+Shift+E to toggle permissions for the selected file or folder.")
keyboard.wait('esc')  # Keep the script running
