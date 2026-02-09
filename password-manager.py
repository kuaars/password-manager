from tkinter import *
from tkinter import messagebox
from tkinter import ttk
import tkinter as tk
import random
import string
import sqlite3
import pyperclip
import hashlib
import base64
import os
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import rsa
import pickle

def check_first_run():
    return not os.path.exists('keys.enc')

def derive_key(password):
    return hashlib.sha256(password.encode()).digest()

def encrypt_data(data, password):
    key = derive_key(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(data, AES.block_size))
    return base64.b64encode(iv + encrypted).decode()

def decrypt_data(encrypted_data, password):
    key = derive_key(password)
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(encrypted_data[16:]), AES.block_size)
    return decrypted

def save_keys(public_key, private_key, password):
    keys_data = {
        'public': public_key.save_pkcs1(),
        'private': private_key.save_pkcs1()
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
    return rsa.encrypt(password.encode(), public_key)

def decrypt_password(encrypted_password, private_key):
    return rsa.decrypt(encrypted_password, private_key).decode()

connection = None
cursor = None
public_key = None
private_key = None

def init_database():
    global connection, cursor
    connection = sqlite3.connect('passwords.db')
    cursor = connection.cursor()
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS passwords (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service TEXT NOT NULL UNIQUE,
        login TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')
    connection.commit()

def show_auth_window():
    auth = Toplevel(root)
    auth.title("Аутентификация")
    auth.geometry("400x200")
    auth.resizable(False, False)
    auth.transient(root)
    auth.grab_set()
    
    def on_auth():
        global public_key, private_key
        password = entry_pass.get()
        
        if not password:
            messagebox.showerror("Ошибка", "Введите пароль!")
            return
            
        try:
            if check_first_run():
                label_status.config(text="Генерация ключей...")
                auth.update()
                
                (pub_key, priv_key) = rsa.newkeys(2048)
                save_keys(pub_key, priv_key, password)
                
                public_key, private_key = pub_key, priv_key
                
                auth.destroy()
                messagebox.showinfo("Первый запуск", 
                                  "Ключи сгенерированы и сохранены!\nЗапомните ваш пароль - он нужен для доступа к данным.")
                root.deiconify()
            else:
                public_key, private_key = load_keys(password)
                auth.destroy()
                root.deiconify()
                
        except Exception as e:
            messagebox.showerror("Ошибка", f"Неверный пароль или повреждены ключи!{e}")
    
    label = ttk.Label(auth, text="Введите мастер-пароль:", font=('Arial', 12))
    label.pack(pady=20)
    
    entry_pass = ttk.Entry(auth, width=30, font=('Arial', 12), show='*')
    entry_pass.pack(pady=10)
    entry_pass.focus()
    
    label_status = ttk.Label(auth, text="", font=('Arial', 10))
    label_status.pack(pady=5)
    
    if check_first_run():
        label_status.config(text="Первый запуск: будут созданы новые ключи")
    
    btn_auth = ttk.Button(auth, text="Войти", command=on_auth)
    btn_auth.pack(pady=10)
    
    def on_enter(event):
        on_auth()
    
    entry_pass.bind('<Return>', on_enter)
    
    root.withdraw()
    auth.wait_window(auth)

root = Tk()
root.title("Менеджер паролей")
root.geometry('1000x1000')

show_auth_window()

init_database()

generator = ''
shpas = '*'

def addwin():
    add = Toplevel(root)
    add.title("Добавить пароль")
    add.geometry("700x700")
    add.transient(root)
    add.grab_set()
    
    def show_pass():
        if entrypass['show'] == '*':
            entrypass.config(show='')
            showpass.config(text="X")
        else:
            entrypass.config(show='*')
            showpass.config(text="✓")
    
    service_label = ttk.Label(add, text="Сервис:", font=('Arial', 12))
    service_label.grid(row=0, column=0, padx=5, pady=5, sticky=W)
    
    login_label = ttk.Label(add, text="Логин:", font=('Arial', 12))
    login_label.grid(row=1, column=0, padx=5, pady=5, sticky=W)
    
    password_label = ttk.Label(add, text="Пароль:", font=('Arial', 12))
    password_label.grid(row=2, column=0, padx=5, pady=5, sticky=W)

    entryservice = ttk.Entry(add, width=30, font=('Arial', 12))
    entryservice.grid(row=0, column=1, padx=5, pady=5)
    
    entrylogin = ttk.Entry(add, width=30, font=('Arial', 12))
    entrylogin.grid(row=1, column=1, padx=5, pady=5)

    entrypass = ttk.Entry(add, width=30, font=('Arial', 12), show='*')
    entrypass.grid(row=2, column=1, padx=5, pady=5)

    showpass = ttk.Button(add, text="✓", command=show_pass)
    showpass.grid(row=2, column=4, padx=5, pady=5)
    
    def pastpass():
        pas = entrypass.get()
        paste = pyperclip.paste()
        if pas != paste:
            entrypass.delete(0, tk.END)
            entrypass.insert(0, paste)
        else:
            showpass.state=["disabled"]

    def gen_pass():
        entrypass.delete(0, tk.END)
        alphabet = string.ascii_letters + string.digits + string.punctuation
        generator = ''.join(random.choice(alphabet) for _ in range(10))
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
                messagebox.showinfo("Успех", "Пароль добавлен!")
                Listbox.insert(END, service)
            except sqlite3.IntegrityError:
                messagebox.showerror("Ошибка!", "Такой сервис уже существует!")
        else:
            messagebox.showerror("Ошибка!", "Поля не должны быть пустыми!")
    
    past = ttk.Button(add, text="Вставить", command=pastpass)
    past.grid(row=2, column=2, columnspan=2, pady=10)
    
    addpasword = ttk.Button(add, text="Добавить", command=addpass)
    addpasword.grid(row=3, column=0, columnspan=2, pady=10)

    generate = ttk.Button(add, text="Сгенерировать Пароль", command=gen_pass)
    generate.grid(row=4, column=0, columnspan=2, pady=10)

def view_password():
    try:
        selected = Listbox.curselection()[0]
        service = Listbox.get(selected)
        
        viewpas = Toplevel(root)
        viewpas.geometry('600x600')
        viewpas.title(f'Пароль для {service}')
        viewpas.transient(root)
        viewpas.grab_set()
        
        cursor.execute("SELECT login, password FROM passwords WHERE service = ?", (service,))
        result = cursor.fetchone()
        
        if result:
            login = result[0]
            encrypted_password = result[1]
            
            try:
                password = decrypt_password(encrypted_password, private_key)
            except:
                messagebox.showerror("Ошибка", "Не удалось расшифровать пароль!")
                viewpas.destroy()
                return
            
            serv_label = ttk.Label(viewpas, text=f"Сервис: {service}", font=('Arial', 14))
            serv_label.pack(pady=20)

            login_label = ttk.Label(viewpas, text=f"Логин: {login}", font=('Arial', 14))
            login_label.pack(pady=10)

            pass_label = ttk.Label(viewpas, text=f"Пароль: {password}", font=('Arial', 12))
            pass_label.pack(pady=10)

            def copy_pass():
                pyperclip.copy(password)
                messagebox.showinfo("Успех!", "Пароль успешно скопирован в буфер обмена!")

            copypass = ttk.Button(viewpas, text="Копировать Пароль", command=copy_pass)
            copypass.pack(pady=10)
            
    except Exception as e:
        pass

def load_passwords():
    Listbox.delete(0, END)
    cursor.execute("SELECT service FROM passwords")
    services = cursor.fetchall()
    for service in services:
        Listbox.insert(END, service[0])

def del_pass():
    try:
        selected_index = Listbox.curselection()
        if not selected_index:
            return
            
        selected = selected_index[0]
        service = Listbox.get(selected)
        
        answer = messagebox.askyesno("ВНИМАНИЕ!", f"Вы уверены, что хотите удалить пароль для {service}?")
        
        if answer:
            cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
            connection.commit()
            load_passwords()
            
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")

add_button = ttk.Button(root, text='Добавить пароль', command=addwin)
add_button.pack(pady=20)

view_button = ttk.Button(root, text='Посмотреть', command=view_password)
view_button.pack(pady=10)

del_button = ttk.Button(root, text='Удалить', command=del_pass)
del_button.pack(pady=10)

Listbox = Listbox(root, width=60, height=30, font=("Arial", 12), selectmode=SINGLE)
Listbox.pack(pady=20)

load_passwords()

def on_closing():
    if connection:
        connection.close()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_closing)
root.mainloop()
