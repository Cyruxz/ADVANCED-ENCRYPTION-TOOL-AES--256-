import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os

def get_key(password):
    return hashlib.sha256(password.encode()).digest()

def pad(data):
    pad_len = 16 - len(data) % 16
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    return data[:-data[-1]]

def encrypt_file(filepath, password):
    key = get_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    with open(filepath, 'rb') as f:
        plaintext = f.read()

    ciphertext = cipher.encrypt(pad(plaintext))
    encrypted_data = iv + ciphertext

    encrypted_path = filepath + '.enc'
    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)

    return encrypted_path

def decrypt_file(filepath, password):
    key = get_key(password)

    with open(filepath, 'rb') as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    decrypted_path = filepath.replace('.enc', '.dec')
    with open(decrypted_path, 'wb') as f:
        f.write(plaintext)

    return decrypted_path

# GUI
root = tk.Tk()
root.title("AES-256 File Encryption Tool")
root.geometry("400x250")

filename = tk.StringVar()
password = tk.StringVar()

def select_file():
    filename.set(filedialog.askopenfilename())

def encrypt_action():
    file = filename.get()
    pw = password.get()
    if file and pw:
        out = encrypt_file(file, pw)
        messagebox.showinfo("Success", f"Encrypted:\n{out}")
    else:
        messagebox.showerror("Error", "File and password required!")

def decrypt_action():
    file = filename.get()
    pw = password.get()
    if file and pw:
        try:
            out = decrypt_file(file, pw)
            messagebox.showinfo("Success", f"Decrypted:\n{out}")
        except:
            messagebox.showerror("Error", "Decryption failed!")
    else:
        messagebox.showerror("Error", "File and password required!")

tk.Label(root, text="File Path:").pack(pady=5)
tk.Entry(root, textvariable=filename, width=40).pack()
tk.Button(root, text="Browse", command=select_file).pack(pady=5)

tk.Label(root, text="Password:").pack(pady=5)
tk.Entry(root, textvariable=password, show='*', width=30).pack()

tk.Button(root, text="Encrypt File", command=encrypt_action, bg='green', fg='white').pack(pady=10)
tk.Button(root, text="Decrypt File", command=decrypt_action, bg='blue', fg='white').pack(pady=5)

root.mainloop()
