import streamlit as st
import time
import base64
from encryption_utils import *

st.set_page_config(page_title="Secure Vault", layout="centered")
st.sidebar.title("🔐 Navigation")
page = st.sidebar.radio("Go to", ["Home", "Store Data", "Retrieve Data", "View Stored", "Login"])

vault = load_vault()
users = load_users()

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if "just_saved_data" not in st.session_state:
    st.session_state.just_saved_data = False

st.markdown("<style>button {margin-top: 10px !important}</style>", unsafe_allow_html=True)

# Home Page
if page == "Home":
    st.title("🔐 Secured Data Encryption System")
    st.write("Welcome to the ultimate secure vault.")
    st.markdown("""
    ### ✨ Key Features:
    - End-to-End Data Encryption
    - Expiry Based Storage System
    - Secure Retrieval with Passkey
    - Auto Lockout after 3 Failed Attempts
    """)
    st.markdown("<br><br><center><i>Developed by Duaa Pirzada</i></center>", unsafe_allow_html=True)

# Store Data Page
elif page == "Store Data":
    st.header("📦 Store Your Secret Data")

    secret = st.text_area("Enter the secret data you want to encrypt")
    passkey = st.text_input("🔑 Create a Passkey", type="password")
    expiry = st.slider("⏳ Set data expiry (in minutes)", 1, 60, 10)

    if st.button("Encrypt & Store"):
        if secret and passkey:
            encrypted_data = encrypt_data(secret)
            encrypted_passkey = hash_password(passkey)
            expiry_time = time.time() + (expiry * 60)

            vault.append({
                "data": encrypted_data,
                "passkey": encrypted_passkey,
                "expiry": expiry_time,
                "timestamp": time.strftime('%Y-%m-%d %H:%M:%S')
            })
            save_vault(vault)
            st.success("✅ Your data is securely saved!")

            st.session_state.just_saved_data = True

            if st.session_state.just_saved_data:
                st.markdown("#### View Encrypted Text")
                st.code(encrypted_data)

                b64 = base64.b64encode(encrypted_data.encode()).decode()
                href = f'<a href="data:file/txt;base64,{b64}" download="encrypted_data.txt">📥 Download Encrypted Text</a>'
                st.markdown(href, unsafe_allow_html=True)
        else:
            st.warning("⚠️ Please fill in all fields.")
    else:
        st.session_state.just_saved_data = False

# Retrieve Data Page
elif page == "Retrieve Data":
    st.header("🔍 Retrieve Data")
    enc_input = st.text_area("Paste your encrypted data")
    passkey = st.text_input("Enter your Passkey", type="password")

    if st.button("Decrypt"):
        found = False
        for entry in vault:
            if entry["data"] == enc_input:
                found = True
                if time.time() > entry["expiry"]:
                    st.error("⏳ This data has expired.")
                elif verify_password(passkey, entry["passkey"]):
                    decrypted = decrypt_data(enc_input)
                    st.success("✅ Successfully Decrypted!")
                    st.code(decrypted)
                else:
                    st.error("❌ Incorrect Passkey.")
        if not found:
            st.warning("⚠️ Data not found in stored vault.")


elif page == "View Stored":
    st.header("📁 View Stored Data")

    if len(vault) == 0:
        st.info("No entries found.")
    else:
        for i, entry in enumerate(vault):
            if st.button(f"📄 Entry {i+1}"):
                st.markdown(f"**Encrypted:** `{entry['data'][:30]}...`")
                left = max(0, int((entry['expiry'] - time.time()) / 60))
                st.markdown(f"⏱ Time left: **{left} mins**")
                st.markdown(f"🕒 Stored At: {entry['timestamp']}")
                st.markdown("---")
elif page == "Login":
    st.header("🔐 Login")

    uname = st.text_input("Username")
    pwd = st.text_input("Password", type="password")

    if st.session_state.failed_attempts >= 3:
        st.error("🚫 Too many failed attempts. Please contact admin.")
    else:
        if st.button("Login"):
            if uname in users and verify_password(pwd, users[uname]["password"]):
                st.session_state.logged_in = True
                st.session_state.failed_attempts = 0
                st.success("✅ Login Successful")
            else:
                st.session_state.failed_attempts += 1
                st.error("❌ Invalid username or password")

    if st.button("Register"):
        if uname in users:
            st.warning("User already exists")
        else:
            users[uname] = {"password": hash_password(pwd)}
            save_users(users)
            st.success("✅ Registered successfully!")






