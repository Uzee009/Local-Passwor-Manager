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
            


# ----- Add new Entry -------
# Args : category, username, password.
def add_entry(cat,uname,pw,vFernet):
    
    if store_path.is_file():
        with store_path.open("r") as f:
            try :
                store = json.load(f)
            except json.JSONDecodeError:
                store = {}
    else:
        store = {}
    
    #isinstace function here checks if "cat" exists in the dict or not 
    if cat not in store or not isinstance(store[cat], list):
        store[cat] = []
    
    encrypt_pw = vFernet.encrypt(pw.encode()).decode()
    data = {"uname" : uname, "pw": encrypt_pw}
    store[cat].append(data)
    
    with open(store_path,"w+") as f:
        json.dump(store,f,indent=4)
    print(f"{cat}, Entry added Successfully")




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
        if store_path.is_file():
            with store_path.open("r") as f:
                try :
                    store = json.load(f)
                except json.JSONDecodeError:
                    store = {}
        else:
            store = {}
        
        print("Vault Unlcoked - welcome")
        pt = "thisIsVerySensitivePassword"
        add_entry("mail","uzeee","mypassword2",vault_fernet)
        add_entry("mail","chirag","mypassword23",vault_fernet)
        add_entry("mail","Nikku","mypassword55",vault_fernet)
        add_entry("Valorant","Nikku","uzee69",vault_fernet)
        
        print(f"decoded password of {store['Valorant'][0]['uname']}")
        # print(f"decoded password of {store['Valorant'][1]['pw']}")
        
        realPass = vault_fernet.decrypt(store['Valorant'][0]['pw'].encode()).decode()
        print(realPass)
        
        break
