import os
import keyboard
import win32security
import win32api
import ntsecuritycon as con
import win32con

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
        dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, everyone)
        
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

        # Create a new DACL to replace the old one
        new_dacl = win32security.ACL()

        # Get the SID for 'Everyone'
        everyone, domain, type = win32security.LookupAccountName("", "Everyone")

        # Copy all ACEs except those for 'Everyone' to the new DACL
        for i in range(dacl.GetAceCount()):
            ace = dacl.GetAce(i)
            if ace[2] != everyone:
                new_dacl.AddAce(ace[0], ace[1], ace[2])
        
        # Set the new DACL for the folder
        sd.SetSecurityDescriptorDacl(1, new_dacl, 0)
        win32security.SetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION, sd)
        
        print(f"Revoked permissions for 'Everyone' from {folder_path}")
    except Exception as e:
        print(f"Failed to revoke permissions: {e}")

# Define the folder path here
folder_path = r'C:\path\to\your\folder'

# Variable to keep track of the permission state
permissions_granted = False

def toggle_permissions():
    global permissions_granted
    if permissions_granted:
        revoke_permissions(folder_path)
    else:
        grant_permissions(folder_path)
    permissions_granted = not permissions_granted

# Set the hotkey to toggle permissions
keyboard.add_hotkey('ctrl+shift+e', toggle_permissions)

print("Press Ctrl+Shift+E to toggle permissions.")
keyboard.wait('esc')  # Keep the script running
