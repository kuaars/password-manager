import customtkinter as ctk
from tkinter import messagebox
import tkinter as tk
import random
import string
import sqlite3
import pyperclip
import hashlib
import base64
import os
import pickle
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import rsa
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
import sys

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

def check_first_run():
    return not os.path.exists('keys.enc')

def derive_key(password, salt, iterations=200000):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)

def encrypt_data(data, password):
    salt = get_random_bytes(16)
    iterations = 200000
    key = derive_key(password, salt, iterations)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(salt + cipher.nonce + tag + ciphertext).decode()

def decrypt_data(encrypted_data, password):
    encrypted_data = base64.b64decode(encrypted_data)
    salt = encrypted_data[:16]
    nonce = encrypted_data[16:32]
    tag = encrypted_data[32:48]
    ciphertext = encrypted_data[48:]
    iterations = 200000
    key = derive_key(password, salt, iterations)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    return decrypted

def save_keys(public_key, private_key, password):
    public_pem = public_key.save_pkcs1()
    private_pem = private_key.save_pkcs1()
    keys_data = {
        'public': public_pem,
        'private': private_pem
    }
    encrypted = encrypt_data(pickle.dumps(keys_data), password)
    with open('keys.enc', 'w') as f:
        f.write(encrypted)

def load_keys(password):
    with open('keys.enc', 'r') as f:
        encrypted = f.read()
    decrypted = decrypt_data(encrypted, password)
    keys_data = pickle.loads(decrypted)
    public_key = rsa.PublicKey.load_pkcs1(keys_data['public'])
    private_key = rsa.PrivateKey.load_pkcs1(keys_data['private'])
    return public_key, private_key

def encrypt_password(password, public_key):
    rsa_key = RSA.import_key(public_key.save_pkcs1())
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    encrypted = cipher.encrypt(password.encode())
    return base64.b64encode(encrypted)

def decrypt_password(encrypted_password, private_key):
    encrypted = base64.b64decode(encrypted_password)
    rsa_key = RSA.import_key(private_key.save_pkcs1())
    cipher = PKCS1_OAEP.new(rsa_key, hashAlgo=SHA256)
    decrypted = cipher.decrypt(encrypted)
    return decrypted.decode()

connection = None
cursor = None
public_key = None
private_key = None

def init_database():
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

def show_auth_window():
    root.withdraw()

    auth = ctk.CTkToplevel(root)
    auth.title("Аутентификация")
    auth.geometry("450x300")
    auth.resizable(False, False)
    auth.transient(root)
    auth.grab_set()

    auth.update_idletasks()
    x = (auth.winfo_screenwidth() // 2) - (450 // 2)
    y = (auth.winfo_screenheight() // 2) - (300 // 2)
    auth.geometry(f'450x300+{x}+{y}')

    def on_auth():
        global public_key, private_key
        password = entry_pass.get()
        if len(password) >= 6:
            if not password:
                messagebox.showerror("Ошибка", "Введите пароль!")
                return

            try:
                if check_first_run():
                    label_status.configure(text="Генерация ключей...")
                    auth.update()

                    (pub_key, priv_key) = rsa.newkeys(2048)
                    save_keys(pub_key, priv_key, password)

                    public_key, private_key = pub_key, priv_key

                    auth.destroy()
                    messagebox.showinfo("Первый запуск",
                                      "Ключи сгенерированы и сохранены!\nЗапомните ваш пароль - он нужен для доступа к данным.")
                    root.deiconify()
                    load_passwords()
                else:
                    public_key, private_key = load_keys(password)
                    auth.destroy()
                    root.deiconify()
                    load_passwords()

            except Exception as e:
                messagebox.showerror("Ошибка", f"Неверный пароль или повреждены ключи!\n{e}")
        else:
            messagebox.showerror("Ошибка", "Пароль слишком короткий\nМинимальная длина: 6 символов")

    title_label = ctk.CTkLabel(auth, text="Менеджер паролей",
                                font=ctk.CTkFont(size=24, weight="bold"))
    title_label.pack(pady=30)

    frame = ctk.CTkFrame(auth)
    frame.pack(pady=20, padx=40, fill="both", expand=True)

    label = ctk.CTkLabel(frame, text="Введите мастер-пароль:",
                          font=ctk.CTkFont(size=14))
    label.pack(pady=15)
    def reset():
        a = messagebox.askyesnocancel("Внимание!","При сбросе мастер-пароля, все сохраненные пароли удалятся.\nПродолжить? ")
        if a:
            os.system("del keys.enc")
            os.execl(sys.executable, sys.executable, *sys.argv)

    res = ctk.CTkButton(frame, text="Сбросить пароль", command=reset,height=10, width=60, font=ctk.CTkFont(size=14))

    entry_pass = ctk.CTkEntry(frame, width=250, height=40,
                               font=ctk.CTkFont(size=14), show="●",
                               placeholder_text="Мастер-пароль")
    entry_pass.pack(pady=10)
    entry_pass.focus()
    if not check_first_run():
        res.pack(pady=15)
    label_status = ctk.CTkLabel(frame, text="", font=ctk.CTkFont(size=12))
    label_status.pack(pady=5)

    if check_first_run():
        label_status.configure(text="Первый запуск: будут созданы новые ключи",
                               text_color="orange")

    btn_auth = ctk.CTkButton(frame, text="Войти", command=on_auth,
                              height=40, width=150, font=ctk.CTkFont(size=14))
    btn_auth.pack(pady=15)

    def on_enter(event):
        on_auth()

    entry_pass.bind('<Return>', on_enter)

    def on_auth_closing():
        root.destroy()

    auth.protocol("WM_DELETE_WINDOW", on_auth_closing)



root = ctk.CTk()
root.title("Менеджер паролей")
root.geometry('1100x800')

root.update_idletasks()
x = (root.winfo_screenwidth() // 2) - (1100 // 2)
y = (root.winfo_screenheight() // 2) - (800 // 2)
root.geometry(f'1100x800+{x}+{y}')

root.withdraw()

init_database()

generator = ''
shpas = '*'

def addwin():
    add = ctk.CTkToplevel(root)
    add.title("Добавить пароль")
    add.geometry("600x550")
    add.transient(root)
    add.grab_set()

    add.update_idletasks()
    x = (add.winfo_screenwidth() // 2) - (600 // 2)
    y = (add.winfo_screenheight() // 2) - (550 // 2)
    add.geometry(f'600x550+{x}+{y}')

    def show_pass():
        if entrypass.cget('show') == '●':
            entrypass.configure(show='')
            showpass.configure(text="Скрыть")
        else:
            entrypass.configure(show='●')
            showpass.configure(text="Показать")

    title_label = ctk.CTkLabel(add, text="Добавление нового пароля",
                                font=ctk.CTkFont(size=20, weight="bold"))
    title_label.pack(pady=20)

    main_frame = ctk.CTkFrame(add)
    main_frame.pack(pady=10, padx=30, fill="both", expand=True)

    service_label = ctk.CTkLabel(main_frame, text="Сервис:",
                                   font=ctk.CTkFont(size=14))
    service_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

    entryservice = ctk.CTkEntry(main_frame, width=300, height=35,
                                  font=ctk.CTkFont(size=13),
                                  placeholder_text="Например: Google")
    entryservice.grid(row=0, column=1, padx=10, pady=10, columnspan=2)

    login_label = ctk.CTkLabel(main_frame, text="Логин:",
                                 font=ctk.CTkFont(size=14))
    login_label.grid(row=1, column=0, padx=10, pady=10, sticky="w")

    entrylogin = ctk.CTkEntry(main_frame, width=300, height=35,
                                font=ctk.CTkFont(size=13),
                                placeholder_text="Ваш логин или email")
    entrylogin.grid(row=1, column=1, padx=10, pady=10, columnspan=2)

    password_label = ctk.CTkLabel(main_frame, text="Пароль:",
                                    font=ctk.CTkFont(size=14))
    password_label.grid(row=2, column=0, padx=10, pady=10, sticky="w")

    entrypass = ctk.CTkEntry(main_frame, width=300, height=35,
                               font=ctk.CTkFont(size=13), show='●')
    entrypass.grid(row=2, column=1, padx=10, pady=10)

    showpass = ctk.CTkButton(main_frame, text="Показать", width=80, height=35,
                               command=show_pass)
    showpass.grid(row=2, column=2, padx=5, pady=10)

    button_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
    button_frame.grid(row=3, column=0, columnspan=3, pady=20)

    def pastpass():
        pas = entrypass.get()
        paste = pyperclip.paste()
        if pas != paste:
            entrypass.delete(0, tk.END)
            entrypass.insert(0, paste)

    def gen_pass():
        entrypass.delete(0, tk.END)
        alphabet = string.ascii_letters + string.digits + string.punctuation
        generator = ''.join(random.choice(alphabet) for _ in range(12))
        entrypass.insert(0, generator)

    def addpass():
        service = entryservice.get()
        login = entrylogin.get()
        password = entrypass.get()

        if service and password and login:
            try:
                encrypted_password = encrypt_password(password, public_key)

                cursor.execute('''
                            INSERT INTO passwords (service, login, password)
                            VALUES (?, ?, ?)
                            ''', (service, login, encrypted_password))
                connection.commit()
                add.destroy()
                messagebox.showinfo("Успех", "Пароль успешно добавлен!")
                load_passwords()
            except sqlite3.IntegrityError:
                messagebox.showerror("Ошибка!", "Такой сервис уже существует!")
        else:
            messagebox.showerror("Ошибка!", "Все поля должны быть заполнены!")

    past = ctk.CTkButton(button_frame, text="Вставить", command=pastpass,
                          width=120, height=35)
    past.grid(row=0, column=0, padx=5)

    generate = ctk.CTkButton(button_frame, text="Сгенерировать", command=gen_pass,
                               width=150, height=35)
    generate.grid(row=0, column=1, padx=5)

    addpasword = ctk.CTkButton(button_frame, text="Сохранить", command=addpass,
                                 width=120, height=35, fg_color="green", hover_color="darkgreen")
    addpasword.grid(row=0, column=2, padx=5)

def view_password():
    try:
        selected = Listbox.curselection()[0]
        service = Listbox.get(selected)

        viewpas = ctk.CTkToplevel(root)
        viewpas.geometry('500x400')
        viewpas.title(f'Пароль для {service}')
        viewpas.transient(root)
        viewpas.grab_set()

        viewpas.update_idletasks()
        x = (viewpas.winfo_screenwidth() // 2) - (500 // 2)
        y = (viewpas.winfo_screenheight() // 2) - (400 // 2)
        viewpas.geometry(f'500x400+{x}+{y}')

        cursor.execute("SELECT login, password FROM passwords WHERE service = ?", (service,))
        result = cursor.fetchone()

        if result:
            login = result[0]
            encrypted_password = result[1]

            try:
                password = decrypt_password(encrypted_password, private_key)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось расшифровать пароль: {str(e)}")
                viewpas.destroy()
                return

            title_label = ctk.CTkLabel(viewpas, text=f"{service}",
                                        font=ctk.CTkFont(size=24, weight="bold"))
            title_label.pack(pady=30)

            info_frame = ctk.CTkFrame(viewpas)
            info_frame.pack(pady=20, padx=40, fill="both", expand=True)

            serv_label = ctk.CTkLabel(info_frame, text=f"Сервис: {service}",
                                       font=ctk.CTkFont(size=16))
            serv_label.pack(pady=15)

            login_label = ctk.CTkLabel(info_frame, text=f"Логин: {login}",
                                        font=ctk.CTkFont(size=16))
            login_label.pack(pady=10)

            pass_frame = ctk.CTkFrame(info_frame, fg_color="transparent")
            pass_frame.pack(pady=15)

            pass_label = ctk.CTkLabel(pass_frame, text=f"Пароль: {password}",
                                        font=ctk.CTkFont(size=14))
            pass_label.pack(side="left", padx=5)

            def copy_pass():
                pyperclip.copy(password)
                messagebox.showinfo("Успех!", "Пароль скопирован в буфер обмена!")

            copypass = ctk.CTkButton(pass_frame, text="Копировать", command=copy_pass,
                                       width=100, height=30)
            copypass.pack(side="left", padx=10)

    except Exception as e:
        pass

def load_passwords():
    Listbox.delete(0, tk.END)
    cursor.execute("SELECT service FROM passwords ORDER BY service")
    services = cursor.fetchall()
    for service in services:
        Listbox.insert(tk.END, service[0])

def del_pass():
    try:
        selected_index = Listbox.curselection()
        if not selected_index:
            return

        selected = selected_index[0]
        service = Listbox.get(selected)

        answer = messagebox.askyesno("Подтверждение удаления",
                                     f"Вы уверены, что хотите удалить пароль для {service}?")

        if answer:
            cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
            connection.commit()
            load_passwords()
            messagebox.showinfo("Успех", "Пароль успешно удален!")

    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")

title_label = ctk.CTkLabel(root, text="Менеджер паролей",
                            font=ctk.CTkFont(size=30, weight="bold"))
title_label.pack(pady=20)

button_container = ctk.CTkFrame(root, fg_color="transparent")
button_container.pack(pady=10)

add_button = ctk.CTkButton(button_container, text='Добавить пароль', command=addwin,
                             width=150, height=40, font=ctk.CTkFont(size=14))
add_button.grid(row=0, column=0, padx=10)

view_button = ctk.CTkButton(button_container, text='Посмотреть', command=view_password,
                              width=150, height=40, font=ctk.CTkFont(size=14))
view_button.grid(row=0, column=1, padx=10)

del_button = ctk.CTkButton(button_container, text='Удалить', command=del_pass,
                             width=150, height=40, font=ctk.CTkFont(size=14),
                             fg_color="red", hover_color="darkred")
del_button.grid(row=0, column=2, padx=10)

list_label = ctk.CTkLabel(root, text="Сохраненные сервисы:",
                           font=ctk.CTkFont(size=16))
list_label.pack(pady=(20, 5))

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

show_auth_window()

def on_closing():
    if connection:
        connection.close()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
