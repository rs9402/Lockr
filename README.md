```
██╗      ██████╗  ██████╗██╗  ██╗██████╗ 
██║     ██╔═══██╗██╔════╝██║ ██╔╝██╔══██╗
██║     ██║   ██║██║     █████╔╝ ██████╔╝
██║     ██║   ██║██║     ██╔═██╗ ██╔══██╗
███████╗╚██████╔╝╚██████╗██║  ██╗██║  ██║
╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
```                                      
Lockr is a lightweight, secure, and offline cryptography utility made for power users who want full control over their credentials. No fluff, just cryptography that works.
Built with a minimalist dark interface, it provides essential cryptography tools without unnecessary complexity.

---

## Features
- Generate strong random passwords with customizable length and character sets
- Create secure passphrases coupled with a random number using wordlists (Default is EFF Long Wordlist with 7776 words, or use your own)
- Hash text using SHA-256 with optional salt and BASE64 encoding
- Encrypt and decrypt data with multiple input/output format options using the AES256 GCM algorithm
- KDF through PBKD2 and Argon2
- Copy results to clipboard instantly with a single click
- Slick, clean UI

## System Requirements
- Windows 7/8/10/11
- No installation required - Portable executable. Unzip and run.

---

## How to Use

1. Password Generation
- Launch Lockr.exe
- Hit the GENERATE PASSWORD tab
- Set your length and character types
- Generate and copy

2. Passphrase Creation
- Switch to GENERATE PASSPHRASE tab
- Pick your word count (slider)
- Set your separator
- Generate and copy

3. Hashing
- Go to the HASH tab
- Enter your passphrase
- Add site-specific salt if needed
- Hash it and copy

4. Encryption
- Select the ENCRYPT tab
- Enter your encryption key
- Choose operation and formats
- Process your data

5. KDF
- Select the KDF tab
- Enter your passphrase to derive
- Choose your desired algorithm
- Optionally, change the amount of iterations or final key length
- Derive key

---

## Security Notes

- LOCKR operates completely offline
- No data is sent to any server. Nothing cached. No trace gets left behind after you close the exe. Everything is done in system memory with nothing stored.
- The wordlist contains 7776 words by default (EFF long wordlist)
- All cryptographic operations use industry-standard algorithms
- Passphrases can be more memorable and equally secure as complex passwords

---

## License
This project is licensed under the MIT License.  

---

## Final Words
Stay secure, stay in control. LOCKR is designed by a security enthusiast, for security enthusiasts.
Because security shouldn't be complicated, and your data should remain yours.

Made by someone who gets it.
- RS9402 (aka SS)
