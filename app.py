import streamlit as st
from cryptography.fernet import Fernet
import hashlib

if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
fernet = Fernet(st.session_state.fernet_key)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "is_logged_in" not in st.session_state:
    st.session_state.is_logged_in = True  
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return fernet.encrypt(text.encode()).decode()

def decrypt_data(ciphertext):
    return fernet.decrypt(ciphertext.encode()).decode()

def login_page():
    st.title("🔐 Reauthorization Required")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        if username == "admin" and password == "admin123":
            st.session_state.is_logged_in = True
            st.session_state.failed_attempts = 0
            st.success("Reauthorized successfully!")
            st.experimental_rerun()
        else:
            st.error("Incorrect credentials.")

def home_page():
    st.title("🛡️ Secure Data Encryption System")
    st.write("Choose an action:")
    if st.button("📥 Store Data"):
        st.session_state.page = "store"
    if st.button("🔓 Retrieve Data"):
        st.session_state.page = "retrieve"

def store_data_page():
    st.title("📥 Store New Data")
    user_key = st.text_input("Enter Unique Key")
    user_text = st.text_area("Enter Text to Encrypt")
    passkey = st.text_input("Enter a Passkey", type="password")

    if st.button("Store Securely"):
        if user_key and user_text and passkey:
            hashed_key = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_text)
            st.session_state.stored_data[user_key] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_key
            }
            st.success("Data stored securely.")
        else:
            st.warning("All fields are required.")

    if st.button("🔙 Back to Home"):
        st.session_state.page = "home"

def retrieve_data_page():
    st.title("🔓 Retrieve Stored Data")
    user_key = st.text_input("Enter Unique Key")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if user_key in st.session_state.stored_data:
            stored_entry = st.session_state.stored_data[user_key]
            hashed_input = hash_passkey(passkey)

            if hashed_input == stored_entry["passkey"]:
                decrypted_text = decrypt_data(stored_entry["encrypted_text"])
                st.success("Data decrypted successfully:")
                st.code(decrypted_text)
                st.session_state.failed_attempts = 0  # reset on success
            else:
                st.session_state.failed_attempts += 1
                st.error(f"Incorrect passkey. Attempts: {st.session_state.failed_attempts}/3")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.is_logged_in = False
                    st.warning("Too many failed attempts. Redirecting to login...")
                    st.experimental_rerun()
        else:
            st.error("No data found for that key.")

    if st.button("🔙 Back to Home"):
        st.session_state.page = "home"

if "page" not in st.session_state:
    st.session_state.page = "home"

if not st.session_state.is_logged_in:
    login_page()
else:
    if st.session_state.page == "home":
        home_page()
    elif st.session_state.page == "store":
        store_data_page()
    elif st.session_state.page == "retrieve":
        retrieve_data_page()
