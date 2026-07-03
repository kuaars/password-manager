import os
import sys
import pickle
import random
import string
import hashlib
import sqlite3
import base64
import tkinter as tk
from tkinter import messagebox

import customtkinter as ctk
import pyperclip
import rsa
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256


ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


def check_first_run() -> bool:
    return not os.path.exists('keys.enc')


def derive_key(password: str, salt: bytes, iterations: int = 200_000) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)


def encrypt_data(data: bytes, password: str) -> str:
    salt = get_random_bytes(16)
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()


def decrypt_data(encrypted_data: str, password: str) -> bytes:
    raw = base64.b64decode(encrypted_data)
    salt, nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:48], raw[48:]
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def save_keys(public_key: 'rsa.PublicKey', private_key: 'rsa.PrivateKey', password: str) -> None:
    keys_data = {
        'public': public_key.save_pkcs1(),
        'private': private_key.save_pkcs1(),
    }
    encrypted = encrypt_data(pickle.dumps(keys_data), password)
    with open('keys.enc', 'w') as f:
        f.write(encrypted)


def load_keys(password: str):
    with open('keys.enc', 'r') as f:
        encrypted = f.read()
    keys_data = pickle.loads(decrypt_data(encrypted, password))
    public_key = rsa.PublicKey.load_pkcs1(keys_data['public'])
    private_key = rsa.PrivateKey.load_pkcs1(keys_data['private'])
    return public_key, private_key


def encrypt_password(password: str, public_key: 'rsa.PublicKey') -> bytes:
    rsa_key = RSA.import_key(public_key.save_pkcs1())
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    encrypted = cipher.encrypt(password.encode())
    return base64.b64encode(encrypted)


def decrypt_password(encrypted_password: bytes, private_key: 'rsa.PrivateKey') -> str:
    raw = base64.b64decode(encrypted_password)
    rsa_key = RSA.import_key(private_key.save_pkcs1())
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    return cipher.decrypt(raw).decode()


connection: sqlite3.Connection | None = None
cursor: sqlite3.Cursor | None = None
public_key = None
private_key = None


def init_database() -> None:
    global connection, cursor
    connection = sqlite3.connect('passwords.db')
    cursor = connection.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL UNIQUE,
            login TEXT NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    connection.commit()


def center_window(window: ctk.CTkToplevel | ctk.CTk, width: int, height: int) -> None:
    window.update_idletasks()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')


def show_auth_window() -> None:
    root.withdraw()

    auth = ctk.CTkToplevel(root)
    auth.title("Аутентификация")
    auth.resizable(False, False)
    auth.transient(root)
    auth.grab_set()
    center_window(auth, 450, 300)

    def on_auth():
        global public_key, private_key
        password = entry_pass.get()

        if len(password) < 6:
            messagebox.showerror("Ошибка", "Пароль слишком короткий\nМинимальная длина: 6 символов")
            return

        if not password:
            messagebox.showerror("Ошибка", "Введите пароль!")
            return

        try:
            if check_first_run():
                label_status.configure(text="Генерация ключей...")
                auth.update()

                pub_key, priv_key = rsa.newkeys(2048)
                save_keys(pub_key, priv_key, password)
                public_key, private_key = pub_key, priv_key

                auth.destroy()
                messagebox.showinfo(
                    "Первый запуск",
                    "Ключи сгенерированы и сохранены!\nЗапомните ваш пароль - он нужен для доступа к данным."
                )
                root.deiconify()
                load_passwords()
            else:
                public_key, private_key = load_keys(password)
                auth.destroy()
                root.deiconify()
                load_passwords()

        except Exception as e:
            messagebox.showerror("Ошибка", f"Неверный пароль или повреждены ключи!\n{e}")

    def reset():
        confirmed = messagebox.askyesnocancel(
            "Внимание!",
            "При сбросе мастер-пароля, все сохраненные пароли удалятся.\nПродолжить? "
        )
        if confirmed:
            os.system("del keys.enc")
            os.execl(sys.executable, sys.executable, *sys.argv)

    def on_enter(_event):
        on_auth()

    def on_auth_closing():
        root.destroy()

    ctk.CTkLabel(auth, text="Менеджер паролей",
                 font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)

    frame = ctk.CTkFrame(auth)
    frame.pack(pady=20, padx=40, fill="both", expand=True)

    ctk.CTkLabel(frame, text="Введите мастер-пароль:",
                 font=ctk.CTkFont(size=14)).pack(pady=15)

    reset_button = ctk.CTkButton(frame, text="Сбросить пароль", command=reset,
                                  height=10, width=60, font=ctk.CTkFont(size=14))

    entry_pass = ctk.CTkEntry(frame, width=250, height=40,
                               font=ctk.CTkFont(size=14), show="●",
                               placeholder_text="Мастер-пароль")
    entry_pass.pack(pady=10)
    entry_pass.focus()
    entry_pass.bind('<Return>', on_enter)

    if not check_first_run():
        reset_button.pack(pady=15)

    label_status = ctk.CTkLabel(frame, text="", font=ctk.CTkFont(size=12))
    label_status.pack(pady=5)

    if check_first_run():
        label_status.configure(text="Первый запуск: будут созданы новые ключи",
                                text_color="orange")

    ctk.CTkButton(frame, text="Войти", command=on_auth,
                  height=40, width=150, font=ctk.CTkFont(size=14)).pack(pady=15)

    auth.protocol("WM_DELETE_WINDOW", on_auth_closing)


root = ctk.CTk()
root.title("Менеджер паролей")
center_window(root, 1100, 800)
root.withdraw()

init_database()


def addwin() -> None:
    add = ctk.CTkToplevel(root)
    add.title("Добавить пароль")
    add.transient(root)
    add.grab_set()
    center_window(add, 600, 550)

    def show_pass():
        if entrypass.cget('show') == '●':
            entrypass.configure(show='')
            showpass.configure(text="Скрыть")
        else:
            entrypass.configure(show='●')
            showpass.configure(text="Показать")

    def pastpass():
        current = entrypass.get()
        clipboard = pyperclip.paste()
        if current != clipboard:
            entrypass.delete(0, tk.END)
            entrypass.insert(0, clipboard)

    def gen_pass():
        entrypass.delete(0, tk.END)
        alphabet = string.ascii_letters + string.digits + string.punctuation
        generated = ''.join(random.choice(alphabet) for _ in range(12))
        entrypass.insert(0, generated)

    def addpass():
        service = entryservice.get()
        login = entrylogin.get()
        password = entrypass.get()

        if not (service and password and login):
            messagebox.showerror("Ошибка!", "Все поля должны быть заполнены!")
            return

        try:
            encrypted_password = encrypt_password(password, public_key)
            cursor.execute(
                'INSERT INTO passwords (service, login, password) VALUES (?, ?, ?)',
                (service, login, encrypted_password)
            )
            connection.commit()
            add.destroy()
            messagebox.showinfo("Успех", "Пароль успешно добавлен!")
            load_passwords()
        except sqlite3.IntegrityError:
            messagebox.showerror("Ошибка!", "Такой сервис уже существует!")

    ctk.CTkLabel(add, text="Добавление нового пароля",
                 font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)

    main_frame = ctk.CTkFrame(add)
    main_frame.pack(pady=10, padx=30, fill="both", expand=True)

    ctk.CTkLabel(main_frame, text="Сервис:", font=ctk.CTkFont(size=14)) \
        .grid(row=0, column=0, padx=10, pady=10, sticky="w")
    entryservice = ctk.CTkEntry(main_frame, width=300, height=35,
                                 font=ctk.CTkFont(size=13),
                                 placeholder_text="Например: Google")
    entryservice.grid(row=0, column=1, padx=10, pady=10, columnspan=2)

    ctk.CTkLabel(main_frame, text="Логин:", font=ctk.CTkFont(size=14)) \
        .grid(row=1, column=0, padx=10, pady=10, sticky="w")
    entrylogin = ctk.CTkEntry(main_frame, width=300, height=35,
                               font=ctk.CTkFont(size=13),
                               placeholder_text="Ваш логин или email")
    entrylogin.grid(row=1, column=1, padx=10, pady=10, columnspan=2)

    ctk.CTkLabel(main_frame, text="Пароль:", font=ctk.CTkFont(size=14)) \
        .grid(row=2, column=0, padx=10, pady=10, sticky="w")
    entrypass = ctk.CTkEntry(main_frame, width=300, height=35,
                              font=ctk.CTkFont(size=13), show='●')
    entrypass.grid(row=2, column=1, padx=10, pady=10)

    showpass = ctk.CTkButton(main_frame, text="Показать", width=80, height=35,
                              command=show_pass)
    showpass.grid(row=2, column=2, padx=5, pady=10)

    button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
    button_frame.grid(row=3, column=0, columnspan=3, pady=20)

    ctk.CTkButton(button_frame, text="Вставить", command=pastpass,
                  width=120, height=35).grid(row=0, column=0, padx=5)
    ctk.CTkButton(button_frame, text="Сгенерировать", command=gen_pass,
                  width=150, height=35).grid(row=0, column=1, padx=5)
    ctk.CTkButton(button_frame, text="Сохранить", command=addpass,
                  width=120, height=35, fg_color="green",
                  hover_color="darkgreen").grid(row=0, column=2, padx=5)


def view_password() -> None:
    try:
        selected = Listbox.curselection()[0]
    except Exception:
        return

    service = Listbox.get(selected)

    cursor.execute("SELECT login, password FROM passwords WHERE service = ?", (service,))
    result = cursor.fetchone()
    if not result:
        return

    login, encrypted_password = result

    viewpas = ctk.CTkToplevel(root)
    viewpas.title(f'Пароль для {service}')
    viewpas.transient(root)
    viewpas.grab_set()
    center_window(viewpas, 500, 400)

    try:
        password = decrypt_password(encrypted_password, private_key)
    except Exception as e:
        messagebox.showerror("Ошибка", f"Не удалось расшифровать пароль: {str(e)}")
        viewpas.destroy()
        return

    ctk.CTkLabel(viewpas, text=f"{service}",
                 font=ctk.CTkFont(size=24, weight="bold")).pack(pady=30)

    info_frame = ctk.CTkFrame(viewpas)
    info_frame.pack(pady=20, padx=40, fill="both", expand=True)

    ctk.CTkLabel(info_frame, text=f"Сервис: {service}",
                 font=ctk.CTkFont(size=16)).pack(pady=15)
    ctk.CTkLabel(info_frame, text=f"Логин: {login}",
                 font=ctk.CTkFont(size=16)).pack(pady=10)

    pass_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
    pass_frame.pack(pady=15)

    ctk.CTkLabel(pass_frame, text=f"Пароль: {password}",
                 font=ctk.CTkFont(size=14)).pack(side="left", padx=5)

    def copy_pass():
        pyperclip.copy(password)
        messagebox.showinfo("Успех!", "Пароль скопирован в буфер обмена!")

    ctk.CTkButton(pass_frame, text="Копировать", command=copy_pass,
                  width=100, height=30).pack(side="left", padx=10)


def load_passwords() -> None:
    Listbox.delete(0, tk.END)
    cursor.execute("SELECT service FROM passwords ORDER BY service")
    for (service,) in cursor.fetchall():
        Listbox.insert(tk.END, service)


def del_pass() -> None:
    selected_index = Listbox.curselection()
    if not selected_index:
        return

    service = Listbox.get(selected_index[0])
    confirmed = messagebox.askyesno(
        "Подтверждение удаления",
        f"Вы уверены, что хотите удалить пароль для {service}?"
    )
    if not confirmed:
        return

    try:
        cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
        connection.commit()
        load_passwords()
        messagebox.showinfo("Успех", "Пароль успешно удален!")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")


ctk.CTkLabel(root, text="Менеджер паролей",
             font=ctk.CTkFont(size=30, weight="bold")).pack(pady=20)

button_container = ctk.CTkFrame(root, fg_color="transparent")
button_container.pack(pady=10)

ctk.CTkButton(button_container, text='Добавить пароль', command=addwin,
              width=150, height=40, font=ctk.CTkFont(size=14)).grid(row=0, column=0, padx=10)
ctk.CTkButton(button_container, text='Посмотреть', command=view_password,
              width=150, height=40, font=ctk.CTkFont(size=14)).grid(row=0, column=1, padx=10)
ctk.CTkButton(button_container, text='Удалить', command=del_pass,
              width=150, height=40, font=ctk.CTkFont(size=14),
              fg_color="red", hover_color="darkred").grid(row=0, column=2, padx=10)

ctk.CTkLabel(root, text="Сохраненные сервисы:",
             font=ctk.CTkFont(size=16)).pack(pady=(20, 5))

list_frame = ctk.CTkFrame(root)
list_frame.pack(pady=10, padx=30, fill="both", expand=True)

scrollbar = ctk.CTkScrollbar(list_frame)
scrollbar.pack(side="right", fill="y")

Listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set,
                      width=60, height=25, font=("Arial", 12),
                      bg="#2b2b2b", fg="white",
                      selectbackground="#1f538d",
                      selectforeground="white",
                      borderwidth=0, highlightthickness=0)
Listbox.pack(side="left", fill="both", expand=True)
scrollbar.configure(command=Listbox.yview)


def on_closing() -> None:
    if connection:
        connection.close()
    root.destroy()


root.protocol("WM_DELETE_WINDOW", on_closing)

show_auth_window()
root.mainloop()
