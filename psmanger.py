#!/usr/bin/env python
import base64
from getpass import getpass
import questionary
from questionary import Style
import os
import functools
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, VerifyMismatchError
import sys

import json
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken


custom_style = Style([
    ('question', 'fg:orange'),
    ('highlighted', 'fg:green bold'),
    ('selected', 'fg:green'),
    ('pointer', 'fg:green bold'),
    ('answer', 'fg:green'),
])

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
    
    vault_key = Fernet.generate_key() 
    recovery_key = Fernet.generate_key() 

    derived_master_key = derive_key(pw, salt)
    encrypted_vault_key_A = Fernet(derived_master_key).encrypt(vault_key)
    encrypted_vault_key_B = Fernet(recovery_key).encrypt(vault_key)

    data = {
        "master_hash": scram,
        "salt": base64.b64encode(salt).decode(),
        "vk_a": base64.b64encode(encrypted_vault_key_A).decode(),
        "vk_b": base64.b64encode(encrypted_vault_key_B).decode()
    }
    
    with open(master_path, "w") as f:
        json.dump(data, f, indent=4)
    
    print("\n" + "="*60)
    print("IMPORTANT: Your Vault has been created.")
    print("If you forget your master password, you will need this recovery key.")
    print("Please MANUALLY save this key in a new text file somewhere safe.")
    print("The application WILL NOT save this for you.\n")
    print(f"Your one-time recovery key is:\n{recovery_key.decode()}")
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
        return None

    derived = derive_key(authPass,salt)
    f = Fernet(derived)

    try:
        dec_vault_key = f.decrypt(vk_a)
        return Fernet(dec_vault_key)
    except InvalidToken:
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
    if existing_categories is None:
        cat = questionary.text(
            'Enter category (or select an existing one):',
            validate=lambda text: True if len(text) > 0 else "Category cannot be empty.",
            style=custom_style,
            qmark='→'
        ).ask()
    else: 
        cat = questionary.autocomplete(
            'Enter category (or select an existing one):',
            choices=existing_categories,
            validate=lambda text: True if len(text) > 0 else "Category cannot be empty.",
            style=custom_style,
            qmark='→'
        ).ask()
        
    if cat is None: return

    uname = questionary.text(
        'Enter username:',
        validate=lambda text: True if len(text) > 0 else "Username cannot be empty.",
        style=custom_style,
        qmark='→'
    ).ask()
    if uname is None: return

    pw = questionary.password(
        'Enter password:',
        validate=lambda text: True if len(text) > 0 else "Password cannot be empty.",
        style=custom_style,
        qmark='→'
    ).ask()
    if pw is None: return

    add_entry(cat, uname, pw, vFernet)


# ----- Action Callbacks for Navigator ----- 

def _perform_view_action(vFernet, category, entry):
    """The actual logic for viewing a single entry."""
    try:
        encrypted_pw_str = entry['pw']
        decrypted_pw_bytes = vFernet.decrypt(encrypted_pw_str.encode())
        decrypted_pw = decrypted_pw_bytes.decode()
        
        print("\n" + "-"*25)
        print(f"Category: {category}")
        print(f"Username: {entry['uname']}")
        print(f"Password: {decrypted_pw}")
        print("-"*(25) + "\n")
        
    except InvalidToken:
        print("\nError: Could not decrypt password. Data may be corrupt.\n")
    except Exception as e:
        print(f"\nAn unexpected error occurred: {e}\n")
    
    questionary.press_any_key_to_continue("Press enter to return to the username list...", style=custom_style).ask()
    return False # Data was not changed

def _perform_edit_action(vFernet, master_hash, data, category, original_entry):
    """The actual logic for editing a single entry. Returns True if data changed."""
    print("\n--- Password Re-authentication for Edit ---")
    master_pass_check = getpass("Please enter your master password to confirm: ")
    
    try:
        ph.verify(master_hash, master_pass_check)
    except (VerifyMismatchError, VerificationError):
        print("\nIncorrect Master Password. Edit operation cancelled.")
        questionary.press_any_key_to_continue(style=custom_style).ask()
        return False

    print("✅ Master Password Verified.\n")
    print(f"--- Editing '{original_entry['uname']}' in Category: {category} ---")
    
    new_uname = questionary.text(
        'Enter new username (or press Enter to keep current):',
        default=original_entry['uname'],
        style=custom_style,
        qmark='→'
    ).ask()
    if new_uname is None: return False

    new_pw = questionary.password(
        'Enter new password (or press Enter to keep current):',
        style=custom_style,
        qmark='→'
    ).ask()
    if new_pw is None: return False
    
    if new_uname == original_entry['uname'] and not new_pw:
        print("\nNo changes made.")
        questionary.press_any_key_to_continue(style=custom_style).ask()
        return False

    entry_index = -1
    for i, entry in enumerate(data[category]):
        if entry['uname'] == original_entry['uname'] and entry['pw'] == original_entry['pw']:
            entry_index = i
            break
    
    if entry_index == -1:
        print("\nError: Could not find the original entry to update. It may have been changed.")
        return False

    if new_uname:
        data[category][entry_index]['uname'] = new_uname
    if new_pw:
        data[category][entry_index]['pw'] = vFernet.encrypt(new_pw.encode()).decode()

    with open(store_path, "w") as f:
        json.dump(data, f, indent=4)
    
    print("\n✅ Entry updated successfully!")
    questionary.press_any_key_to_continue(style=custom_style).ask()
    return True

# --- Main Navigator --- 

def entry_navigator(action_callback):
    """Main navigation engine. Takes a callback to perform an action on a selected entry."""
    data = load_file(store_path)
    
    while True: # Category selection loop
        if not data:
            print("No categories found in the vault.")
            questionary.press_any_key_to_continue(style=custom_style).ask()
            return

        cat_list = sorted(list(data.keys()))
        category_choices = cat_list + [questionary.Separator(), "Go Back to Main Menu"]

        category_choice = questionary.select(
            "Select a Category:",
            choices=category_choices,
            show_selected=True,
            style=custom_style,
            qmark='→',
            pointer='▶'
        ).ask()

        if category_choice is None or category_choice == "Go Back to Main Menu":
            return

        while True: # Username selection loop
            unames_in_category = [entry['uname'] for entry in data[category_choice]]
            if not unames_in_category:
                print(f"\nNo passwords found in the '{category_choice}' category.")
                questionary.press_any_key_to_continue("Press enter to return to categories...", style=custom_style).ask()
                break

            username_choices = sorted(unames_in_category) + [
                questionary.Separator(), 
                "Go Back to Categories",
                "Go Back to Main Menu"
            ]

            username_choice = questionary.select(
                f"Select an entry in '{category_choice}':",
                choices=username_choices,
                pointer="▶",
                show_selected=True,
                style=custom_style,
                qmark='→'
            ).ask()

            if username_choice is None or username_choice == "Go Back to Main Menu":
                return
            elif username_choice == "Go Back to Categories":
                break

            selected_entry = None
            for entry in data[category_choice]:
                if entry['uname'] == username_choice:
                    selected_entry = entry.copy()
                    break
            
            if selected_entry:
                data_was_changed = action_callback(category=category_choice, original_entry=selected_entry, data=data)
                if data_was_changed:
                    data = load_file(store_path)


# --- Top-Level Functions --- 

def view_pass(vFernet):
    """Wrapper for navigator to view passwords."""
    print("\n--- View Passwords ---")
    view_action = functools.partial(_perform_view_action, vFernet)
    navigator_callback = lambda category, original_entry, data: view_action(category=category, entry=original_entry)
    entry_navigator(navigator_callback)

def edit_entry(vFernet, master_hash):
    """Wrapper for navigator to edit passwords."""
    print("\n--- Edit Passwords ---")
    edit_action = functools.partial(_perform_edit_action, vFernet, master_hash)
    entry_navigator(edit_action)

def recover_account():
    """Handles the account recovery process using a recovery key file."""
    print("\n--- Account Recovery ---")
    if not master_path.is_file():
        print("Error: No master data file found. Cannot recover account.")
        return

    recovery_file_path_str = questionary.path(
        "Please select your recovery key file:",
        style=custom_style,
        qmark='→'
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
    new_master_pw = questionary.password("Create a new master Password").ask()
    new_master_pw_confirm = questionary.password("Confirm new master Password").ask()

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
    input("Press any Key to restart script...")
    sys.exit()


def main_menu(vault_fernet, master_data):
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
        style=custom_style,
        qmark="→",
        pointer="▶"
    ).ask()

    if choice == "View Passwords":
        view_pass(vault_fernet)
    elif choice == "Add New Password":
        add_entry_interactive(vault_fernet)
    elif choice == "Edit an Entry":
        edit_entry(vault_fernet, master_data['master_hash'])
    elif choice == "Exit" or choice is None:
        return False
    return True


# ------ Main Flow ------- 
if not master_path.is_file():
    print("----- Welcome to CMD Password manager ----- \n")
    pw = getpass("Create master Password: ")
    user_reg(pw)
    print("Vault generated, please restart the script.")
    input("Press any key to Exit...")
    sys.exit()

# --- Authentication Loop ---
master_data_main = None
if master_path.is_file():
    with open(master_path, "r") as f:
        master_data_main = json.load(f)

    auth_choice = questionary.select(
        "Welcome back! Please choose an option:",
        choices=["Log In", "Forgot Master Password"],
        style=custom_style,
        qmark='→',
        pointer='▶'
    ).ask()
    
    if auth_choice is None:
        sys.exit()
    elif auth_choice == "Forgot Master Password":
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
        sys.exit()

# --- Main Application Loop ---
print("\nVault Unlocked - Welcome!")
while True:
    should_continue = main_menu(vault_fernet, master_data_main)
    if not should_continue:
        break

print("Exiting. Goodbye!")