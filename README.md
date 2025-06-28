# 🔐 FileKey

FileKey is an offline web app that lets you quickly encrypt and share files using passkeys. No accounts, no tracking, no backend servers. Just local, offline security powered by passkeys.

> 🛡️ **FileKey is open source and privacy-first.**

---

### 🚀 Features

- ✅ **Free & Open Source** – Licensed under GPLv3.
- ✅ **Accountless by Design** – No logins, no tracking.
- ✅ **Passkey-Based Encryption** – Integrates with your existing security key or password manager.
- ✅ **End-to-End Encrypted** – Only you can see your data.
- ✅ **Secure Sharing** – Share files securely with “Share Keys”
- ✅ **Offline** – Runs 100% offline in your browser. Can be installed locally as a PWA.

---

### 👨‍💻 How to Use FileKey

1. **Create your FileKey**  
   Generate a secure passkey stored in your password manager or security key (like iCloud Keychain or Yubikey).

2. **Encrypt files**  
   Drag and drop any file into FileKey — it's immediately encrypted with AES-256.

3. **Decrypt files**  
   Drop the encrypted file back in. Your passkey unlocks it quickly, locally and securely.

4. **Share privately**  
   Encrypt a file for someone else using their Share Key. Only they can open it.

---

### 💾 Supported Systems

In order to use FileKey, you need a compatible password manager (Apple Passwords, Google Passwords, Windows Hello, etc) or a hardware security key that supports FIDO2 and PRF (like the YubiKey 5 and Bio Series). For hardware security keys, your browser and operating system both need to support WebAuthn and the PRF extension. Below is a non-exhaustive compatiblity table:

| Platform      | Supported Passkey Providers        | Notes               |
|--------------|-------------------------------------|------------------------------------|
| macOS     | Apple Passwords, Yubikey         | Safari ≥ 17 or Chrome ≥ 112. Yubikeys will not work in Safari. |
| Windows       | Windows Hello, YubiKey  | Edge ≥ 112 or Chrome ≥ 112. Requires Windows 11. |
| Linux         | YubiKey (via browser)              | Latest version of Chrome or Chromium-based browsers.  |
| iOS       | Apple Passwords | Safari ≥ 17 or Chrome ≥ 112 |
| Android       | Google Passwords, Yubikey | Chrome ≥ 112 |

<br>

> ⚠️ **Notes:**  
> - The 1Password browser extension appears to work with FileKey, but more verification is needed.
> - Proton Pass and BitWarden won't work until they properly support PRF.  
> - Samsung Pass has been reported to work, despite not officially supporting PRF. 
> - Windows 10 and below does not support PRF, and thus won't work.
> - Filekey will likely work with Chromium based browsers (e.g. Brave, Vivaldi, Opera)

---

### 🛠️ How the Encryption Works

FileKey first requires the generation of a passkey, that will be stored on either your password manager or security key device, using the app’s domain as the relying party. Once a passkey has been created, it can then pass a static message through WebAuthn which interacts with a PRF in order to generate a deterministic random value.

Using this deterministic random value, an HKDF with 256 bits of entropy is generated. The HKDF and a random salt is then used to derive a key to be used with AES-GCM. The derived key is then used to encrypt and decrypt the file. A new derived key is used for each additional file.

All low-level cryptographic functions performed within this process are using the web’s built-in SubtleCrypto interface of the Web Crypto API. All encrypted files use a unique randomly generated salt, composed of a 16 byte hash.

> 🛡️ **To understand more details of the encryption process, [see here](how-encryption-works.md).**

---

### 🔁 Sharing

Every FileKey user has a unique **Share Key** — a long string that acts like a public address. You can find it in the menu under **"Your Share Key."**

#### 📤 Sharing a File

1. Click the **"Share"** button next to any file.
2. Enter the recipient’s Share Key (they’ll need to provide this to you).
3. FileKey creates a special encrypted version only that recipient can unlock. Save and send the file (ending in `.shared_filekey`) via any method — email, messaging, file transfer, etc.

#### 📥 Receiving a Shared File

1. Open FileKey and authenticate.
2. Drag and drop the shared file into FileKey.
3. FileKey detects that it’s a shared file and decrypts it using your key.

#### 🔐 Security Details for Sharing

- Your private keys **never** leave your device.
- Shared files are locked to a specific recipient.
- All encryption and decryption happen **entirely on your device** — no servers involved.
- Files are secured with **AES-256** encryption.
- Your Share Key does not need to be kept secret, it can be shared openly.

> 🛡️ Share with confidence, knowing only your intended recipient can access the file.

---

### 🔗 Links

> **🔒 [filekey.app](https://filekey.app)**  
> *(Best in the latest versions of Chrome, Safari, or Edge)*

> **📜 [Substack](https://filekey.substack.com/)**  
> *(Our official blog)*

> **💬 [Signal Group](https://signal.group/#CjQKIDpdakX0nr1V00ciNv3dsWCFZgUwm_NylulFJz4VOUJ_EhBtY-bq759RNExzcCWMUGIB)**  
> *(Chat with us directly)*
