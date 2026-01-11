#!/usr/bin/env python
import base64
from getpass import getpass
import questionary
import os
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
    
    # Create masterPass.
    scram = ph.hash(pw)

    # Genrate vault key
    vault_key = Fernet.generate_key()

    # Deriving key for vault_key encryption.
    salt = os.urandom(16)
    derived = derive_key(pw,salt)

    # Encrypting vault_key
    enc = Fernet(derived).encrypt(vault_key)
    
    #store meta data into json.
    data = {
        "master" : scram,
        "salt" : base64.b64encode(salt).decode(),
        "vault_key" : base64.b64encode(enc).decode()
    }

    with open(master_path,"w") as f:
        json.dump(data,f,indent=4)


# Authenticate user and Open vault.
def user_Auth(master_path,authPass):

    if Path(master_path).is_file():
        with open(master_path,"r") as f:
            mp = json.load(f)
        
        master = mp['master']
        salt = base64.b64decode(mp['salt'])
        vault_key = base64.b64decode(mp['vault_key'])

        try:
            ph.verify(master,authPass)
        except VerifyMismatchError:
            print(f"Incorrect Password,Try again please")
            return None
        except VerificationError:
            print(f"Passwrd could not be varified, Please try again.")
            return None

        derived = derive_key(authPass,salt)
        f = Fernet(derived)

        try:
            dec_vault_key = f.decrypt(vault_key)
            return Fernet(dec_vault_key)
        except InvalidToken:
            print("Unable to decrypt vault key. This might indicate data corruption or an incorrect master password.")
            return None
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

    if cat is None: return  # User cancelled

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
    while True: # Loop for category selection
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

        while True: # Loop for username selection within a category
            unames_in_category = [entry['uname'] for entry in data[choice]]
            if not unames_in_category:
                print(f"No passwords found in the '{choice}' category.")
                questionary.press_any_key_to_continue("Press any key to return to categories...").ask()
                break # Break inner loop, go back to category selection

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
                break # Break inner loop, go back to category selection
            
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

    if category is None: # User cancelled or no data
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
    Interactively guides the user to select an entry and then edit its username or password.
    Requires master password re-authentication.
    """
    data = load_file(store_path)
    if not data:
        print("No categories found in the vault to edit.")
        questionary.press_any_key_to_continue().ask()
        return

    category, entry_to_edit = _select_entry(data)

    if category is None: # User cancelled selection
        return

    print("\n--- Master Password Re-authentication ---")
    master_pass_check = getpass("Please enter your master password to edit this entry: ")
    
    if not master_path.is_file():
        print("Master data file not found. Cannot re-authenticate.")
        questionary.press_any_key_to_continue().ask()
        return

    with open(master_path, "r") as f:
        master_data = json.load(f)
    
    try:
        ph.verify(master_data['master'], master_pass_check)
        print("✅ Master Password Verified.")
    except (VerifyMismatchError, VerificationError):
        print("Incorrect Master Password. Edit operation cancelled.")
        questionary.press_any_key_to_continue().ask()
        return

    print(f"\n--- Editing Entry in Category: {category} ---")
    print(f"Current Username: {entry_to_edit['uname']}")
    
    new_uname = questionary.text(
        'Enter new username (leave blank to keep current):',
        default=entry_to_edit['uname']
    ).ask()
    if new_uname is None: return

    new_pw = questionary.password(
        'Enter new password (leave blank to keep current, input will be hidden):',
        validate=lambda text: True if len(text) > 0 else True # Allow blank if not changing
    ).ask()
    if new_pw is None: return

    # If new_uname or new_pw are empty strings, use the existing values
    final_uname = new_uname if new_uname else entry_to_edit['uname']
    final_pw = new_pw if new_pw else vFernet.decrypt(entry_to_edit['pw'].encode()).decode() # Decrypt to get current raw password

    # Encrypt the final password
    encrypted_final_pw = vFernet.encrypt(final_pw.encode()).decode()

    # Update the entry in the data structure
    # We need to find and update the actual entry object within the list
    for i, entry in enumerate(data[category]):
        if entry['uname'] == entry_to_edit['uname']: # Find by original username
            data[category][i]['uname'] = final_uname
            data[category][i]['pw'] = encrypted_final_pw
            break
    
    with open(store_path, "w") as f:
        json.dump(data, f, indent=4)
    
    print("\nEntry updated successfully!")
    questionary.press_any_key_to_continue("Press any key to return to the menu...").ask()


def main_menu(vault_fernet):
    """Displays the main menu and returns True to continue, False to exit."""
    choice = questionary.select(
        "What would you like to do?",
        choices=[
            "View Passwords",
            "Add New Password",
            "Edit an Entry", # New option
            questionary.Separator(),
            "Exit"
        ],
        use_indicator=True,
        qmark= "->"
    ).ask()

    if choice == "View Passwords":
        view_pass(vault_fernet)
    elif choice == "Add New Password":
        add_entry_interactive(vault_fernet)
    elif choice == "Edit an Entry":
        edit_entry(vault_fernet)
    elif choice == "Exit" or choice is None:
        return False  # Signal to exit the loop
    return True  # Signal to continue


# ------ Main Flow ------- 
if not master_path.is_file():
    pw = getpass("Create master Password: ")
    user_reg(pw)
    print("Vault generated, please restart the script.")
    exit()

# --- Authentication Loop ---
attempt = 3
vault_fernet = None
while attempt > 0:
    authPass = getpass("Please enter your master password: ")
    try:
        vault_fernet = user_Auth(master_path, authPass)
        if vault_fernet:
            break  # Success
    except (ValueError, VerifyMismatchError, VerificationError) as e:
        # Catching specific errors from auth logic
        pass # The user_Auth function already prints errors

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