import streamlit as st
import hashlib
import sqlite3  # currently unused, kept for future extension
import os
import json
from cryptography.fernet import Fernet

# --- File Configurations ---
KEY_FILE = "secret.key"
DATA_FILE = "data.json"

# --- Key Management ---
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return key

cipher = Fernet(load_key())

# --- Data Storage ---
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

stored_data = load_data()

# --- Session State Initialization ---
st.session_state.setdefault("failed_attempts", 0)
st.session_state.setdefault("is_logged_in", True)

# --- Helper Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- UI ---
st.set_page_config(page_title="Secure Data Vault", page_icon="🔐")
st.title("🔐 Secure Data Vault")

tabs = st.tabs(["🏠 Home", "📥 Store Data", "🔓 Retrieve Data", "🔐 Login"])

# --- Home Tab ---
with tabs[0]:
    st.markdown("### Welcome!")
    st.info("This app lets you **securely encrypt and store sensitive text**, and retrieve it using a passkey.")

# --- Store Data Tab ---
with tabs[1]:
    st.markdown("### Store Encrypted Data")
    label = st.text_input("Enter a Label (e.g., 'Note1'):")
    plain_text = st.text_area("Enter the Text to Encrypt:")
    passkey = st.text_input("Set a Passkey for this data:", type="password")

    if st.button("🔐 Encrypt and Save"):
        if label and plain_text and passkey:
            encrypted = encrypt_data(plain_text)
            hashed_pass = hash_passkey(passkey)
            stored_data[label] = {"encrypted_text": encrypted, "passkey": hashed_pass}
            save_data(stored_data)
            st.success(f"✅ Data saved securely under label: `{label}`")
        else:
            st.warning("⚠️ Please fill in all fields.")

# --- Retrieve Data Tab ---
with tabs[2]:
    st.markdown("### Retrieve Your Data")

    if not st.session_state.is_logged_in:
        st.warning("🔒 Session locked due to too many failed attempts. Please reauthorize in the **Login** tab.")
    else:
        label = st.text_input("Enter Label of Data to Retrieve:")
        passkey = st.text_input("Enter the Passkey:", type="password")

        if st.button("🔓 Decrypt Data"):
            if label in stored_data:
                correct_hash = stored_data[label]["passkey"]
                encrypted_text = stored_data[label]["encrypted_text"]

                if hash_passkey(passkey) == correct_hash:
                    result = decrypt_data(encrypted_text)
                    st.success("✅ Decryption Successful!")
                    st.code(result, language="text")
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = 3 - st.session_state.failed_attempts
                    st.error(f"❌ Incorrect passkey. Attempts left: {attempts_left}")

                    if st.session_state.failed_attempts >= 3:
                        st.session_state.is_logged_in = False
                        st.warning("🚫 Too many failed attempts. Please reauthorize.")
            else:
                st.error("⚠️ No data found for the entered label.")

# --- Login Tab ---
with tabs[3]:
    st.markdown("### Admin Login")
    master_pass = st.text_input("Enter Master Password (hint: admin123)", type="password")

    if st.button("🔑 Reauthorize"):
        if master_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.session_state.is_logged_in = True
            st.success("✅ Session reauthorized. You may now access the Retrieve tab.")
        else:
            st.error("❌ Incorrect master password.")
