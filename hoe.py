import os
import keyboard
import win32security
import ntsecuritycon as con
import tkinter as tk
from tkinter import filedialog

# Function to grant permissions
def grant_permissions(folder_path):
    try:
        # Get the security descriptor for the folder
        sd = win32security.GetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION)
        
        # Get the DACL
        dacl = sd.GetSecurityDescriptorDacl()
        
        # Create a new DACL if none exists
        if dacl is None:
            dacl = win32security.ACL()

        # Get the SID for 'Everyone'
        everyone, domain, type = win32security.LookupAccountName("", "Everyone")

        # Add an ACE to the DACL that allows full control to 'Everyone'
        dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE, con.FILE_ALL_ACCESS, everyone)
        
        # Set the new DACL for the folder
        sd.SetSecurityDescriptorDacl(1, dacl, 0)
        win32security.SetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION, sd)
        
        print(f"Granted full control to 'Everyone' for {folder_path}")
    except Exception as e:
        print(f"Failed to grant permissions: {e}")

# Function to revoke permissions
def revoke_permissions(folder_path):
    try:
        # Get the security descriptor for the folder
        sd = win32security.GetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION)
        
        # Get the DACL
        dacl = sd.GetSecurityDescriptorDacl()

        # Create a new DACL
        new_dacl = win32security.ACL()

        # Get the SID for 'Everyone'
        everyone, domain, type = win32security.LookupAccountName("", "Everyone")

        # Copy all ACEs except those for 'Everyone' to the new DACL
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            if ace[2] != everyone:
                new_dacl.AddAccessAllowedAceEx(ace[0], ace[1], ace[2], ace[3])

        # Set the new DACL for the folder
        sd.SetSecurityDescriptorDacl(1, new_dacl, 0)
        win32security.SetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION, sd)
        
        print(f"Revoked permissions for 'Everyone' from {folder_path}")
    except Exception as e:
        print(f"Failed to revoke permissions: {e}")

# Function to select a folder
def select_folder():
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    folder_path = filedialog.askdirectory()
    return folder_path

# Variable to keep track of the permission state
permissions_granted = False

def toggle_permissions():
    global permissions_granted, selected_folder
    if selected_folder:
        if permissions_granted:
            revoke_permissions(selected_folder)
        else:
            grant_permissions(selected_folder)
        permissions_granted = not permissions_granted
    else:
        print("No folder selected.")

# Initial folder selection
selected_folder = select_folder()

# Set the hotkey to toggle permissions
keyboard.add_hotkey('ctrl+shift+e', toggle_permissions)

print("Press Ctrl+Shift+E to toggle permissions for the selected folder.")
keyboard.wait('esc')  # Keep the script running
