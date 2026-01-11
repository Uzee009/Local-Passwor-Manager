#!/usr/bin/env python
import base64
from getpass import getpass
import questionary
import os
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError

import json
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


ph = PasswordHasher()
master_path = Path("master.json")
store_path = Path("store.json")


# -------- Supporting function for creating vault key --------
def derive_key(password : str, salt : bytes, iterations : int = 200_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm = hashes.SHA256(),
        length = 32,
        salt = salt,
        iterations = iterations
    )
    raw = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(raw)


# First run -- create new pass & Initiate vault.
def user_reg(pw):
    scram = ph.hash(pw)
    salt = os.urandom(16)
    
    # The actual key for encrypting passwords in store.json
    vault_key = Fernet.generate_key() 
    
    # A separate recovery key, also a Fernet key
    recovery_key = Fernet.generate_key() 

    # Encrypt the vault_key with a key derived from the master password
    derived_master_key = derive_key(pw, salt)
    encrypted_vault_key_A = Fernet(derived_master_key).encrypt(vault_key)
    
    # Encrypt the same vault_key with the recovery key
    encrypted_vault_key_B = Fernet(recovery_key).encrypt(vault_key)

    data = {
        "master_hash": scram,
        "salt": base64.b64encode(salt).decode(),
        "vk_a": base64.b64encode(encrypted_vault_key_A).decode(), # Encrypted with master
        "vk_b": base64.b64encode(encrypted_vault_key_B).decode()  # Encrypted with recovery
    }
    
    with open(master_path, "w") as f:
        json.dump(data, f, indent=4)
    
    # Display the one-time recovery key
    print("\n" + "="*60)
    print("IMPORTANT: Your Vault has been created.")
    print("If you forget your master password, you will need this recovery key.")
    print("Please MANUALLY save this key in a new text file somewhere safe.")
    print("The application WILL NOT save this for you.\n")
    print(f"Your one-time recovery key is:\n{recovery_key.decode()}") # decode to make it a plain string
    print("="*60 + "\n")


# Authenticate user and Open vault.
def user_Auth(master_path,authPass):
    if not Path(master_path).is_file():
        return None

    with open(master_path,"r") as f:
        mp = json.load(f)
    
    master_hash = mp['master_hash']
    salt = base64.b64decode(mp['salt'])
    vk_a = base64.b64decode(mp['vk_a'])

    try:
        ph.verify(master_hash,authPass)
    except (VerifyMismatchError, VerificationError):
        # We don't print here to avoid revealing if a user exists
        return None

    derived = derive_key(authPass,salt)
    f = Fernet(derived)

    try:
        dec_vault_key = f.decrypt(vk_a)
        return Fernet(dec_vault_key)
    except InvalidToken:
        # This can happen if master file is corrupt or a different salt was used
        print("Critical error: Could not decrypt vault key even with correct password.")
        return None


def load_file(fpath):
    if fpath.is_file():
        with fpath.open("r") as f:
            try :
                store = json.load(f)
                return store
            except json.JSONDecodeError:
                store = {}
                return store
    else:
        store = {}
        return store


def add_entry(cat,uname,pw,vFernet):
    store = load_file(store_path)
    if cat not in store or not isinstance(store[cat], list):
        store[cat] = []
    
    encrypt_pw = vFernet.encrypt(pw.encode()).decode()
    data = {"uname" : uname, "pw": encrypt_pw}
    store[cat].append(data)
    
    with open(store_path,"w+") as f:
        json.dump(store,f,indent=4)
    print(f"{cat}, Entry added Successfully")

def add_entry_interactive(vFernet):
    """Interactively prompts the user to add a new password entry."""
    store = load_file(store_path)
    existing_categories = list(store.keys())

    print("\n--- Add New Password ---")
    print(f"Existing Categories : \n{existing_categories}")
    cat = questionary.autocomplete(
        'Enter category (or select an existing one):',
        choices=existing_categories,
        validate=lambda text: True if len(text) > 0 else "Category cannot be empty."
    ).ask()

    if cat is None: return

    uname = questionary.text(
        'Enter username:',
        validate=lambda text: True if len(text) > 0 else "Username cannot be empty."
    ).ask()
    if uname is None: return

    pw = questionary.password(
        'Enter password:',
        validate=lambda text: True if len(text) > 0 else "Password cannot be empty."
    ).ask()
    if pw is None: return

    add_entry(cat, uname, pw, vFernet)


def _select_entry(data):
    """
    Helper function to interactively select a category and username.
    Returns (category, entry_dict) or (None, None) if cancelled or no data.
    """
    while True:
        if not data:
            print("No categories found in the vault.")
            questionary.press_any_key_to_continue().ask()
            return None, None

        cat_list = sorted(list(data.keys()))
        category_choices = cat_list + [questionary.Separator(), "Go Back to Main Menu"]

        choice = questionary.select(
            "What category would you like to choose?",
            choices=category_choices,
            show_selected=True
        ).ask()

        if choice is None or choice == "Go Back to Main Menu":
            return None, None

        while True:
            unames_in_category = [entry['uname'] for entry in data[choice]]
            if not unames_in_category:
                print(f"No passwords found in the '{choice}' category.")
                questionary.press_any_key_to_continue("Press any key to return to categories...").ask()
                break

            username_choices = sorted(unames_in_category) + [questionary.Separator(), "Go Back to Categories"]

            ch_uname = questionary.select(
                f"Select a username from '{choice}' (or go back):",
                choices=username_choices,
                pointer=">",
                show_selected=True
            ).ask()

            if ch_uname is None:
                return None, None
            elif ch_uname == "Go Back to Categories":
                break
            
            for entry in data[choice]:
                if entry['uname'] == ch_uname:
                    return choice, entry
            
            print("Error: Selected username not found. Please try again.")
            questionary.press_any_key_to_continue().ask()


def view_pass(vFernet):
    """
    Interactively guides the user to select and view a password.
    """
    data = load_file(store_path)
    category, entry = _select_entry(data)

    if category is None:
        return

    try:
        encrypted_pw_str = entry['pw']
        decrypted_pw_bytes = vFernet.decrypt(encrypted_pw_str.encode())
        decrypted_pw = decrypted_pw_bytes.decode()
        
        print("\n--- Credentials ---")
        print(f"Category: {category}")
        print(f"Username: {entry['uname']}")
        print(f"Password: {decrypted_pw}")
        print("---------------------")
        
    except InvalidToken:
        print("\nError: Could not decrypt password. Data may be corrupt or key is invalid.")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}")
    
    questionary.press_any_key_to_continue("Press any key to continue...").ask()


def edit_entry(vFernet):
    """
    Interactively guides the user to select an entry and then edit it.
    """
    data = load_file(store_path)
    if not data:
        print("No categories found in the vault to edit.")
        questionary.press_any_key_to_continue().ask()
        return

    category, entry_to_edit_original = _select_entry(data)

    if category is None:
        return

    print("\n--- Master Password Re-authentication ---")
    master_pass_check = getpass("Please enter your master password to edit this entry: ")
    
    with open(master_path, "r") as f:
        master_data = json.load(f)
    
    try:
        ph.verify(master_data['master_hash'], master_pass_check)
        print("✅ Master Password Verified.")
    except (VerifyMismatchError, VerificationError):
        print("Incorrect Master Password. Edit operation cancelled.")
        questionary.press_any_key_to_continue().ask()
        return

    print(f"\n--- Editing Entry in Category: {category} ---")
    print(f"Current Username: {entry_to_edit_original['uname']}")
    
    new_uname = questionary.text(
        'Enter new username (or press Enter to keep current):',
        default=entry_to_edit_original['uname']
    ).ask()
    if new_uname is None: return

    new_pw = questionary.password(
        'Enter new password (or press Enter to keep current):'
    ).ask()
    if new_pw is None: return

    # Find the specific entry in the data list
    entry_index = -1
    for i, entry in enumerate(data[category]):
        if entry['uname'] == entry_to_edit_original['uname'] and entry['pw'] == entry_to_edit_original['pw']:
            entry_index = i
            break
    
    if entry_index == -1:
        print("Error: Could not find the original entry to update.")
        return

    # Update username if a new one was provided
    if new_uname:
        data[category][entry_index]['uname'] = new_uname
    
    # Update password if a new one was provided
    if new_pw:
        data[category][entry_index]['pw'] = vFernet.encrypt(new_pw.encode()).decode()

    with open(store_path, "w") as f:
        json.dump(data, f, indent=4)
    
    print("\nEntry updated successfully!")
    questionary.press_any_key_to_continue().ask()

def recover_account():
    """Handles the account recovery process using a recovery key file."""
    print("\n--- Account Recovery ---")
    if not master_path.is_file():
        print("Error: No master data file found. Cannot recover account.")
        return

    recovery_file_path_str = questionary.path(
        "Please enter the full path to your recovery key file:"
    ).ask()

    if not recovery_file_path_str:
        print("Recovery cancelled.")
        return

    recovery_file_path = Path(recovery_file_path_str.strip())
    
    if not recovery_file_path.is_file():
        print("Error: The specified file path does not exist.")
        return

    try:
        with open(recovery_file_path, "r") as f:
            recovery_key_from_file = f.read().strip()
    except Exception as e:
        print(f"Error reading the recovery file: {e}")
        return

    with open(master_path, "r") as f:
        master_data = json.load(f)

    vk_b = base64.b64decode(master_data['vk_b'])
    
    try:
        recovery_key_bytes = recovery_key_from_file.encode()
        vault_key = Fernet(recovery_key_bytes).decrypt(vk_b)
        print("✅ Recovery Key Verified.")
    except InvalidToken:
        print("Invalid Recovery Key. Recovery failed.")
        return
    except Exception:
        print("Invalid Recovery Key format. Recovery failed.")
        return

    print("You can now set a new master password.")
    new_master_pw = getpass("Enter your new master password: ")
    new_master_pw_confirm = getpass("Confirm your new master password: ")

    if not new_master_pw or new_master_pw != new_master_pw_confirm:
        print("Passwords do not match or are empty. Recovery failed.")
        return

    new_master_hash = ph.hash(new_master_pw)
    salt = base64.b64decode(master_data['salt'])
    new_derived_key = derive_key(new_master_pw, salt)
    new_vk_a = Fernet(new_derived_key).encrypt(vault_key)

    master_data['master_hash'] = new_master_hash
    master_data['vk_a'] = base64.b64encode(new_vk_a).decode()

    with open(master_path, "w") as f:
        json.dump(master_data, f, indent=4)
        
    print("\nPassword has been reset successfully.")
    print("Please restart the script and log in with your new password.")
    exit()


def main_menu(vault_fernet):
    """Displays the main menu and returns True to continue, False to exit."""
    choice = questionary.select(
        "What would you like to do?",
        choices=[
            "View Passwords",
            "Add New Password",
            "Edit an Entry",
            questionary.Separator(),
            "Exit"
        ],
        use_indicator=True,
        qmark= ">"
    ).ask()

    if choice == "View Passwords":
        view_pass(vault_fernet)
    elif choice == "Add New Password":
        add_entry_interactive(vault_fernet)
    elif choice == "Edit an Entry":
        edit_entry(vault_fernet)
    elif choice == "Exit" or choice is None:
        return False
    return True


# ------ Main Flow ------- 
if not master_path.is_file():
    pw = getpass("Create master Password: ")
    user_reg(pw)
    print("Vault generated, please restart the script.")
    exit()

# --- Authentication Loop ---
if master_path.is_file():
    auth_choice = questionary.select(
        "Welcome back! Please choose an option:",
        choices=["Log In", "Forgot Master Password"]
    ).ask()
    
    if auth_choice == "Forgot Master Password":
        recover_account()

attempt = 3
vault_fernet = None
while attempt > 0:
    authPass = getpass("Please enter your master password: ")
    vault_fernet = user_Auth(master_path, authPass)
    if vault_fernet:
        break
    
    attempt -= 1
    if attempt > 0:
        print(f'Authentication failed. Attempts left: {attempt}')
    else:
        print("Too many failed attempts, terminating script.")
        exit()

# --- Main Application Loop ---
print("\nVault Unlocked - Welcome!")
while True:
    should_continue = main_menu(vault_fernet)
    if not should_continue:
        break

print("Exiting. Goodbye!")
