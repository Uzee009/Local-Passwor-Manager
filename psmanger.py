#!/usr/bin/env python
import base64
from getpass import getpass
import questionary
import os
from argon2 import PasswordHasher 
from argon2.exceptions import VerificationError,VerifyMismatchError 

import json
from pathlib import Path
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet,InvalidToken


ph = PasswordHasher()
master_path = Path("master.json")
store_path = Path("store.json")
# MasterPass -> just to get into the system 
# VaultKey -> get an access of the stored password for encryption and decryption
#  -> Why not store vault key right away? Its randomly generated anyways? 
#       Becasuse if we do that vault key is wide open and if get compormised then 
#       it can decrypt any password store in vault 
#       So in order to prevent it we are encrypting vault key with "authPass" and storing it. 
#       So this way each time whenever we need a password to be decrypted we have to run the code 
#       in order to decrypt the key and keep that in memory while its running 


# -------- Supporting funtion for creating valut key --------
# --- Args : user password, Salt
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
# Args : user password.
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
    # Why not store slat and vault key rightaway? Why put them in base64?
    # Json cannot store bytes right away thats why base64 decode() is needed.
    # Without it traceback is being thrown.
    data = {
        "master" : scram,
        "salt" : base64.b64encode(salt).decode(),
        "vault_key" : base64.b64encode(enc).decode()
    }

    # Storing in master Pass and Vaultkey in Json
    # masterPass = {"master":scram}

    with open(master_path,"w") as f:
        json.dump(data,f,indent=4)



# Authenticate user and Open vault.
# json location, user Password. 
def user_Auth(master_path,authPass):

    if Path(master_path).is_file():
        with open(master_path,"r") as f:
            mp = json.load(f)
        
        # initial setup for decryption
        master = mp['master']
        salt = base64.b64decode(mp['salt'])
        vault_key = base64.b64decode(mp['vault_key'])

        try:
            # Varify master password...
            # print("Varifying Master key...")
            ph.verify(master,authPass)
            # print("✅ Master Varified")
            
        except VerifyMismatchError: 
            print(f"Incorrect Password,Try again please")
        
        except VerificationError:
            print(f"Passwrd could not be varified, Please try again.")

        # Derive key based on user Password and prepare for decryption.
        derived = derive_key(authPass,salt)
        f = Fernet(derived)

        try: 
            # Decrypting vault based on given Fernet object.
            # print("Unlocking vault...")
            dec_vault_key = f.decrypt(vault_key)
            # print("✅ Vault Unlocked")
            return Fernet(dec_vault_key)
        except InvalidToken:
            raise ValueError("Unable to decrypt vault key")
            


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


# ----- Add new Entry -------
# Args : category, username, password.
def add_entry(cat,uname,pw,vFernet):
    
    # if store_path.is_file():
    #     with store_path.open("r") as f:
    #         try :
    #             store = json.load(f)
    #         except json.JSONDecodeError:
    #             store = {}
    # else:
    #     store = {}

    store = load_file(store_path)
    
    #isinstace function here checks if "cat" exists in the dict or not 
    if cat not in store or not isinstance(store[cat], list):
        store[cat] = []
    
    encrypt_pw = vFernet.encrypt(pw.encode()).decode()
    data = {"uname" : uname, "pw": encrypt_pw}
    store[cat].append(data)
    
    with open(store_path,"w+") as f:
        json.dump(store,f,indent=4)
    print(f"{cat}, Entry added Successfully")

# def add_entry_interactive(vFernet):
#     """Interactively prompts the user to add a new password entry."""
#     store = load_file(store_path)
#     existing_categories = list(store.keys())

#     print("\n--- Add New Password ---")
#     cat = questionary.autocomplete(
#         'Enter category (or select an existing one):',
#         choices=existing_categories,
#         validate=lambda text: True if len(text) > 0 else "Category cannot be empty."
#     ).ask()

#     if cat is None: return  # User cancelled

#     uname = questionary.text(
#         'Enter username:',
#         validate=lambda text: True if len(text) > 0 else "Username cannot be empty."
#     ).ask()
#     if uname is None: return

#     pw = questionary.password(
#         'Enter password:',
#         validate=lambda text: True if len(text) > 0 else "Password cannot be empty."
#     ).ask()
#     if pw is None: return

#     # Call the original logic function to add the entry
#     add_entry(cat, uname, pw, vFernet)


def view_pass(vFernet):
    """
    Interactively guides the user to select and view a password, with go-back functionality.
    """
    while True: # Loop for category selection
        data = load_file(store_path)
        if not data:
            print("No categories found in the vault.")
            questionary.press_any_key_to_continue().ask()
            return

        cat_list = sorted(list(data.keys()))
        category_choices = cat_list + [questionary.Separator(), "Go Back to Main Menu"]

        choice = questionary.select(
            "What category would you like to choose?",
            choices=category_choices,
            show_selected=True
        ).ask()

        # Bug fix 1: Handle 'Go Back' BEFORE accessing data[choice]
        if choice is None or choice == "Go Back to Main Menu":
            return # Exit view_pass function

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
                return # Exit view_pass function
            elif ch_uname == "Go Back to Categories":
                break # Break inner loop, go back to category selection
            
            # If a username is selected, proceed to decrypt and display
            for entry in data[choice]:
                if entry['uname'] == ch_uname:
                    try:
                        encrypted_pw_str = entry['pw']
                        decrypted_pw_bytes = vFernet.decrypt(encrypted_pw_str.encode())
                        decrypted_pw = decrypted_pw_bytes.decode()
                        
                        print("\n--- Credentials ---")
                        print(f"Category: {choice}")
                        print(f"Username: {ch_uname}")
                        print(f"Password: {decrypted_pw}")
                        print("---------------------")
                        
                    except InvalidToken:
                        print("\nError: Could not decrypt password. Data may be corrupt or key is invalid.")
                    except Exception as e:
                        print(f"\nAn unexpected error occurred: {e}")
                    
                    questionary.press_any_key_to_continue("Press any key to continue...").ask()
                    break # Break out of the for loop after finding the entry
            
            # Bug fix 2: Break from the inner while loop to return to category selection
            if ch_uname and ch_uname != "Go Back to Categories":
                break



def main_menu(vault_fernet):
    """Displays the main menu and returns True to continue, False to exit."""
    choice = questionary.select(
        "What would you like to do?",
        choices=[
            "View Passwords",
            "Add New Password",
            questionary.Separator(),
            "Exit"
        ],
        use_indicator=True
    ).ask()

    if choice == "View Passwords":
        view_pass(vault_fernet)
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
