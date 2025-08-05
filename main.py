import tkinter as tk
from tkinter import messagebox
import json, os

FILE = "users.json"

# Load users
def load_users():
    if os.path.exists(FILE):
        with open(FILE, "r") as f:
            return json.load(f)
    return []

# Save users
def save_users():
    with open(FILE, "w") as f:
        json.dump(users, f)

# Register user
def register():
    uname = username_var.get().strip()
    pwd = password_var.get().strip()

    if uname and pwd:
        if any(u["username"] == uname for u in users):
            messagebox.showwarning("Exists", "User already exists.")
        else:
            users.append({"username": uname, "password": pwd})
            save_users()
            messagebox.showinfo("Success", "Registered successfully!")
            username_var.set("")
            password_var.set("")
    else:
        messagebox.showwarning("Empty", "Fill all fields.")

# Login user
def login():
    uname = username_var.get().strip()
    pwd = password_var.get().strip()

    for u in users:
        if u["username"] == uname and u["password"] == pwd:
            messagebox.showinfo("Success", f"Welcome {uname}!")
            return
    messagebox.showerror("Failed", "Invalid credentials.")

# GUI
root = tk.Tk()
root.title("Login/Register System")
root.geometry("300x300")
root.resizable(False, False)

username_var = tk.StringVar()
password_var = tk.StringVar()

tk.Label(root, text="Username:").pack(pady=5)
tk.Entry(root, textvariable=username_var).pack()

tk.Label(root, text="Password:").pack(pady=5)
tk.Entry(root, textvariable=password_var, show="*").pack()

tk.Button(root, text="Login", width=20, command=login).pack(pady=10)
tk.Button(root, text="Register", width=20, command=register).pack()

# Load user data
users = load_users()

root.mainloop()
