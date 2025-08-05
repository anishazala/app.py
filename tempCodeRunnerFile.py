import tkinter as tk
from tkinter import messagebox
import json, os, hashlib

FILE = "users.json"

# Hash the password using SHA-256
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

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

# Delete account
def delete_account(username, dashboard):
    confirm = messagebox.askyesno("Delete", "Are you sure you want to delete your account?")
    if confirm:
        global users
        users = [u for u in users if u["username"] != username]
        save_users()
        dashboard.destroy()
        messagebox.showinfo("Deleted", "Your account has been deleted.")

# Open dashboard after login
def open_dashboard(username):
    dash = tk.Toplevel(root)
    dash.title("Dashboard")
    dash.geometry("300x200")

    tk.Label(dash, text=f"Welcome, {username}!", font=("Arial", 14)).pack(pady=20)
    tk.Button(dash, text="Logout", command=dash.destroy).pack(pady=10)
    tk.Button(dash, text="Delete Account", fg="red", command=lambda: delete_account(username, dash)).pack(pady=5)

# Register user
def register():
    uname = username_var.get().strip()
    pwd = password_var.get().strip()

    if uname and pwd:
        if any(u["username"] == uname for u in users):
            messagebox.showwarning("Exists", "User already exists.")
        else:
            hashed_pwd = hash_password(pwd)
            users.append({"username": uname, "password": hashed_pwd})
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
    hashed_pwd = hash_password(pwd)

    for u in users:
        if u["username"] == uname and u["password"] == hashed_pwd:
            username_var.set("")
            password_var.set("")
            open_dashboard(uname)
            return
    messagebox.showerror("Failed", "Invalid credentials.")

# GUI setup
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
