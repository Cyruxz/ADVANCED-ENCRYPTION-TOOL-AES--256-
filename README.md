# ADVANCED-ENCRYPTION-TOOL-AES--256-

COMPANY: CODETECH IT SOLUTION

NAME: YOKESH R

INTERN ID: CT04DH39

DOMAIN: CYBER SECURITY AND ETHICAL HACKING

DURATION: 4 WEEKS

MENTOR: NEELA SANTOSH

Project Description: Advanced Encryption Tool (AES-256)
This project is a robust file encryption and decryption application designed to protect sensitive data using the AES-256 (Advanced Encryption Standard) algorithm. AES-256 is a military-grade encryption method widely used for secure data storage and transmission. The tool features a user-friendly graphical interface built with Python’s tkinter library, allowing users to easily encrypt and decrypt files without needing advanced technical knowledge.

The application supports two core functions:

Encrypt File – Converts any selected file into a secure, unreadable .enc format using a password provided by the user. The encryption process uses AES in CBC (Cipher Block Chaining) mode with 256-bit keys, derived from the password via SHA-256 hashing.

Decrypt File – Restores the encrypted file back to its original form (.dec) using the correct password. If the wrong password is used, the tool shows an error to prevent unauthorized access.

The interface allows users to:

Browse and select files

Input a password

Perform encryption and decryption with just a click

Behind the scenes, the tool:

Pads the file data to fit AES block size

Uses a random 16-byte IV (Initialization Vector) for added security

Combines the IV and encrypted data into one file for easy handling

This encryption tool is suitable for personal use, secure file sharing, or academic projects. It ensures confidentiality of files and is lightweight, portable, and can be extended further (e.g., add drag-and-drop, file overwrite prompts, or key storage options).

OUTPUT:
