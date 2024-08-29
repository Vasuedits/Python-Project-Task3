import random
import string
import sqlite3
from tkinter import *
from tkinter import messagebox

# Initialize SQLite database
def init_db():
    with sqlite3.connect("users.db") as db:
        cursor = db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                Username TEXT NOT NULL UNIQUE,
                GeneratedPassword TEXT NOT NULL
            )
        """)
        db.commit()

# Generate a random password
def generate_password(length):
    if length < 6:
        raise ValueError("Password must be at least 6 characters long.")
    
    all_characters = string.ascii_letters + string.digits + string.punctuation
    password = random.choices(all_characters, k=length)
    random.shuffle(password)
    return ''.join(password)

class PasswordGeneratorApp:
    def __init__(self, master):
        self.master = master
        master.title("Password Generator")
        master.geometry("700x400")
        master.config(bg="#FF8000")
        master.resizable(False, False)

        self.username_var = StringVar()
        self.password_length_var = IntVar()
        self.generated_password_var = StringVar()

        self.create_widgets()

    def create_widgets(self):
        Label(self.master, text="Password Generator", font=("Arial", 20, "bold"), bg="#FF8000", fg="darkblue").pack(pady=10)

        # Username Input
        Label(self.master, text="Enter Username:", font=("Times New Roman", 15), bg="#FF8000", fg="darkblue").pack(pady=(10, 0))
        Entry(self.master, textvariable=self.username_var, font=("Times New Roman", 15), bd=5).pack(pady=5)

        # Password Length Input
        Label(self.master, text="Enter Password Length:", font=("Times New Roman", 15), bg="#FF8000", fg="darkblue").pack(pady=(10, 0))
        Entry(self.master, textvariable=self.password_length_var, font=("Times New Roman", 15), bd=5).pack(pady=5)

        # Generated Password Output
        Label(self.master, text="Generated Password:", font=("Times New Roman", 15), bg="#FF8000", fg="darkblue").pack(pady=(10, 0))
        Entry(self.master, textvariable=self.generated_password_var, font=("Times New Roman", 15), bd=5, fg="darkred").pack(pady=5)

        # Buttons
        Button(self.master, text="Generate Password", font=("Verdana", 15), bg="#BCEE68", command=self.generate_password).pack(pady=10)
        Button(self.master, text="Accept", font=("Helvetica", 15, "bold"), bg="#FFFAF0", command=self.accept_password).pack(side=LEFT, padx=20)
        Button(self.master, text="Reset", font=("Helvetica", 15, "bold"), bg="#FFFAF0", command=self.reset_fields).pack(side=RIGHT, padx=20)

    def generate_password(self):
        try:
            length = self.password_length_var.get()
            if length < 6:
                raise ValueError("Password length must be at least 6.")
            password = generate_password(length)
            self.generated_password_var.set(password)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def accept_password(self):
        username = self.username_var.get()
        generated_password = self.generated_password_var.get()

        if not username:
            messagebox.showerror("Error", "Username cannot be empty.")
            return

        if not generated_password:
            messagebox.showerror("Error", "No password generated.")
            return

        with sqlite3.connect("users.db") as db:
            cursor = db.cursor()
            cursor.execute("SELECT * FROM users WHERE Username = ?", (username,))
            if cursor.fetchone():
                messagebox.showerror("Error", "Username already exists. Please choose another one.")
                return

            cursor.execute("INSERT INTO users (Username, GeneratedPassword) VALUES (?, ?)", (username, generated_password))
            db.commit()
            messagebox.showinfo("Success", "Password saved successfully.")

    def reset_fields(self):
        self.username_var.set("")
        self.password_length_var.set("")
        self.generated_password_var.set("")

if __name__ == '__main__':
    init_db()
    root = Tk()
    app = PasswordGeneratorApp(root)
    root.mainloop()
