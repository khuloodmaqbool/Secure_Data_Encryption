import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.fernet import Fernet

# Key file
KEY_FILE = "simple_secret.key"

# Load or generate encryption key
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

# Initialize database
def init_db():
    conn = sqlite3.connect("simple_data.db")
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS vault (
            label TEXT PRIMARY KEY,
            encrypted_text TEXT,
            passkey TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

# Hashing password
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encrypt and decrypt
def encrypt(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# -------------------- UI Styling --------------------
st.set_page_config(page_title="Secure Vault", page_icon="🔐", layout="centered")

st.markdown("""
    <style>
        .main {
            background-color: #f9f9f9;
        }
        .stButton>button {
            background-color: #4CAF50;
            color: white;
            font-weight: bold;
            padding: 10px 20px;
            border-radius: 10px;
            border: none;
        }
        .stTextInput>div>input {
            border-radius: 10px;
        }
        .stTextArea textarea {
            border-radius: 10px;
        }
        .stSelectbox>div {
            border-radius: 10px;
        }
    </style>
""", unsafe_allow_html=True)

st.title("🔐 Secure Data Vault")

menu = ["Store Secret", "Retrieve Secret"]
choice = st.sidebar.selectbox("🔸 Choose Option", menu)

if choice == "Store Secret":
    st.subheader("✨ Store a New Secret")

    label = st.text_input("🆔 Label (unique id):")
    secret = st.text_area("📝 Your Secret:")
    passkey = st.text_input("🔑 Passkey (to protect it):", type="password")

    if st.button("🔒 Encrypt & Save"):
        if label and secret and passkey:
            conn = sqlite3.connect("simple_data.db")
            c = conn.cursor()
            encrypted = encrypt(secret)
            hashed_key = hash_passkey(passkey)

            try:
                c.execute("INSERT INTO vault (label, encrypted_text, passkey) VALUES (?, ?, ?)",
                          (label, encrypted, hashed_key))
                conn.commit()
                st.success("✅ Secret saved successfully!")
            except sqlite3.IntegrityError:
                st.error("⚠️ Label already exists.")
            finally:
                conn.close()
        else:
            st.warning("⚠️ Please fill all fields.")

elif choice == "Retrieve Secret":
    st.subheader("🔎 Retrieve Your Secret")

    label = st.text_input("🆔 Enter Label:")
    passkey = st.text_input("🔑 Enter Passkey:", type="password")

    if st.button("🔓 Decrypt"):
        conn = sqlite3.connect("simple_data.db")
        c = conn.cursor()
        c.execute("SELECT encrypted_text, passkey FROM vault WHERE label=?", (label,))
        result = c.fetchone()
        conn.close()

        if result:
            encrypted_text, stored_hash = result
            if hash_passkey(passkey) == stored_hash:
                decrypted = decrypt(encrypted_text)
                st.success("🎉 Your Secret:")
                st.code(decrypted, language='text')
            else:
                st.error("❌ Incorrect passkey.")
        else:
            st.error("❌ No secret found with that label.")
