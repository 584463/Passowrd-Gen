import random
import tkinter as tk
from tkinter import ttk
import hashlib

characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()_+"

def generate():
    password = ""
    for i in range(int(length.get())):
        password += random.choice(characters)
    passwordEntry.delete(0, tk.END)
    passwordEntry.insert(0, password)
    update_strength_bar(password)
    update_hash(password)

def copy():
    window.clipboard_clear()
    window.clipboard_append(passwordEntry.get())

def update_strength_bar(password):
    strength = calculate_strength(password)
    strengthBar['value'] = strength
    update_crack_time(strength)

def calculate_strength(password):
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()_+" for c in password)
    
    strength = 0
    if length >= 8:
        strength += 25
    if has_lower:
        strength += 25
    if has_upper:
        strength += 25
    if has_digit:
        strength += 12.5
    if has_special:
        strength += 12.5
    
    return strength

def update_hash(password):
    hash_object = hashlib.sha256(password.encode())
    password_hash = hash_object.hexdigest()
    hashEntry.delete(0, tk.END)
    hashEntry.insert(0, password_hash)

def update_crack_time(strength):
    # Simple heuristic for time to crack based on strength
    if strength < 25:
        time_to_crack = "Seconds"
    elif strength < 50:
        time_to_crack = "Minutes"
    elif strength < 75:
        time_to_crack = "Hours"
    else:
        time_to_crack = "Years"
    
    crackTimeLabel.config(text=f"Estimated Time to Crack: {time_to_crack}")

window = tk.Tk()
window.title("mstr3sl's Password Generator")
window.geometry("600x400")  # Set the initial size of the window
window.configure(bg="#020024")

style = ttk.Style()
style.configure("TLabel", background="#020024", foreground="#00d4ff", font=("Helvetica", 12))
style.configure("TButton", background="#000000", foreground="#00d4ff", font=("Helvetica", 12))  # Changed background to black
style.configure("TEntry", font=("Helvetica", 12))
style.configure("TProgressbar", troughcolor="#34495e", background="#1abc9c")

lengthLabel = ttk.Label(window, text="Password Length:")
lengthLabel.pack(pady=10)

length = ttk.Entry(window)
length.pack(pady=5)

generateButton = ttk.Button(window, text="Generate Password", command=generate)
generateButton.pack(pady=10)

passwordEntry = ttk.Entry(window)
passwordEntry.pack(pady=5)

copyButton = ttk.Button(window, text="Copy to Clipboard", command=copy)
copyButton.pack(pady=10)

strengthLabel = ttk.Label(window, text="Password Strength:")
strengthLabel.pack(pady=10)

strengthBar = ttk.Progressbar(window, length=200, mode='determinate', maximum=100)
strengthBar.pack(pady=5)

hashLabel = ttk.Label(window, text="Password Hash (SHA-256):")
hashLabel.pack(pady=10)

hashEntry = ttk.Entry(window)
hashEntry.pack(pady=5)

crackTimeLabel = ttk.Label(window, text="Estimated Time to Crack: N/A")
crackTimeLabel.pack(pady=10)

window.mainloop()
