#!/usr/bin/env python
import base64
from getpass import getpass
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

def get_user_choice(options,item_type="item", display_key = None):
    
    if not options:
        print(f"No {item_type}s to choose from")
        return None
    
    display_options = []
    if display_key:
        for option in options: 
            display_options.append(option.get(display_key,"UnNamed entry"))
    else:
        display_options = options
    
    for i,option_name in enumerate(display_options):
        print(f"{i+1}.{str(option_name).capitalize()}")

    
    while True:
        choice = input(f"Choose a {item_type} by name or Number: ").strip()
        try: 
            choice_idx = int(choice) - 1
            if 0<= choice_idx < len(options):
                return choice_idx
            else: 
                print("Invalid Number please try again.")
        except ValueError:
            lower_choice = choice.lower()
            lower_options = [opt.lower() for opt in display_options]
            
            if lower_options.count(lower_choice) > 1:
                print(f"'{choice}' is ambiguous. Please choose by number instead.")
            else:
                try: 
                    choice_idx = lower_options.index(lower_choice)
                    return choice_idx
                except ValueError:
                    print(f"Invalid {item_type} name. Please try again.")

    

# ------ View Entries -------
def view_pass(cat=""):
    store = load_file(store_path)
    pass



# ------ Main Flow -------
if not master_path.is_file():
    
    pw = getpass("Create master Password : ")
    user_reg(pw)
    print("Vault genrated, restart the script" )

attempt = 3
vault_fernet = None
while attempt > 0:
    if vault_fernet is None: 
        try:
            authPass = getpass("Please enter the passowrd: ")
            vault_fernet = user_Auth(master_path,authPass)
            
        except ValueError as e:
            attempt -= 1
            print(f'{e}. Attempts left : {attempt}')
            if attempt == 0:
                print("Too many attempts, Terminating script...")
                exit()
            continue
    else:
        store = load_file(store_path)
        
        print("Vault Unlcoked - welcome")
        

        # ---- list the stored categories ----
        print("Added categories")
        print("--------------------------")
        
        # Iterate through all the keys / categories 
        # And return selected category index.
        key_list = [key for key in store]
        category_index = get_user_choice(key_list, "category")

        if category_index is not None:
            # Storing only selected category data.
            selected_category = key_list[category_index]
            print(f"Your choice: {selected_category}")


            # itm_lst containts list of dicts with uname and pw.
            itm_list = store[selected_category]
            entry_index = get_user_choice(itm_list, item_type="entry", display_key="uname")
            
            # print(entry_index)

            if entry_index is not None:
                selected_entry = itm_list[entry_index]
                uname = selected_entry['uname']
                encrypted_pw = selected_entry['pw']
                
                decrypted_pw = vault_fernet.decrypt(encrypted_pw.encode()).decode()
                
                print(f"\nUsername: {uname}")
                print(f"Password: {decrypted_pw}")

        

        # add_entry("mail","uzeee","mypassword2",vault_fernet)
        # add_entry("mail","chirag","mypassword23",vault_fernet)
        # add_entry("mail","Nikku","mypassword55",vault_fernet)
        # add_entry("Valorant","Nikku","uzee69",vault_fernet)
        
        # print(f"decoded password of {store['Valorant'][0]['uname']}")
        # print(f"decoded password of {store['Valorant'][1]['pw']}")
        
        # realPass = vault_fernet.decrypt(store['Valorant'][0]['pw'].encode()).decode()
        # print(realPass)

        # view_pass("Valorant")

        
        break
