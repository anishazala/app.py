import tkinter as tk
from tkinter import messagebox
import json, os, hashlib

FILE = "users.json"
MAX_ATTEMPTS = 3
attempts_left = MAX_ATTEMPTS

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
    dash.configure(bg="#f0f4f7")

    tk.Label(dash, text=f"Welcome, {username}!", font=("Helvetica", 14, "bold"), bg="#f0f4f7").pack(pady=20)
    tk.Button(dash, text="Logout", font=("Helvetica", 10), bg="#d0e1f9", command=dash.destroy).pack(pady=10)
    tk.Button(dash, text="Delete Account", font=("Helvetica", 10), bg="#f08080", fg="white",
              command=lambda: delete_account(username, dash)).pack(pady=5)

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

# Login user with attempt limit
def login():
    global attempts_left
    uname = username_var.get().strip()
    pwd = password_var.get().strip()
    hashed_pwd = hash_password(pwd)

    for u in users:
        if u["username"] == uname and u["password"] == hashed_pwd:
            username_var.set("")
            password_var.set("")
            attempts_left = MAX_ATTEMPTS  # reset on success
            login_button.config(state="normal")
            open_dashboard(uname)
            return

    attempts_left -= 1
    if attempts_left <= 0:
        login_button.config(state="disabled")
        messagebox.showerror("Blocked", "Too many failed attempts. Login disabled.")
    else:
        messagebox.showerror("Failed", f"Invalid credentials.\nAttempts left: {attempts_left}")

# Toggle password visibility
def toggle_password():
    if show_password_var.get():
        password_entry.config(show="")
    else:
        password_entry.config(show="*")

# GUI setup with theme
root = tk.Tk()
root.title("Login/Register System")
root.geometry("320x360")
root.resizable(False, False)
root.configure(bg="#e6f0f8")  # Light blue-gray background

username_var = tk.StringVar()
password_var = tk.StringVar()
show_password_var = tk.BooleanVar(value=False)

# Title
tk.Label(root, text="User Login Panel", font=("Helvetica", 16, "bold"), bg="#e6f0f8", fg="#333").pack(pady=15)

# Username field
tk.Label(root, text="Username:", font=("Helvetica", 10), bg="#e6f0f8").pack(pady=5)
tk.Entry(root, textvariable=username_var, font=("Helvetica", 10), width=28).pack()

# Password field
tk.Label(root, text="Password:", font=("Helvetica", 10), bg="#e6f0f8").pack(pady=5)
password_entry = tk.Entry(root, textvariable=password_var, show="*", font=("Helvetica", 10), width=28)
password_entry.pack()

# Show password checkbox
tk.Checkbutton(root, text="Show Password", variable=show_password_var, bg="#e6f0f8", font=("Helvetica", 9),
               command=toggle_password).pack(pady=5)

# Buttons
login_button = tk.Button(root, text="Login", font=("Helvetica", 10), width=22, bg="#a4c8f0", command=login)
login_button.pack(pady=10)

tk.Button(root, text="Register", font=("Helvetica", 10), width=22, bg="#b6e2d3", command=register).pack(pady=5)

# Load users
users = load_users()

root.mainloop()
