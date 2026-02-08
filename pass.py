from tkinter import *
from tkinter import messagebox
from tkinter import ttk
import sqlite3

root = Tk()
root.title("Менеджер паролей")
root.geometry('1000x1000')

connection = sqlite3.connect('passwords.db')
cursor = connection.cursor()

cursor.execute('''
CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
)
''')
connection.commit()

def addwin():
    add = Toplevel(root)
    add.title("Добавить пароль")
    add.geometry("500x500")
    
    service_label = ttk.Label(add, text="Сервис:", font=('Arial', 12))
    service_label.grid(row=0, column=0, padx=5, pady=5, sticky=W)
    
    password_label = ttk.Label(add, text="Пароль:", font=('Arial', 12))
    password_label.grid(row=1, column=0, padx=5, pady=5, sticky=W)
    
    entryservice = ttk.Entry(add, width=30, font=('Arial', 12))
    entryservice.grid(row=0, column=1, padx=5, pady=5)
    
    entrypass = ttk.Entry(add, width=30, font=('Arial', 12), show="*")
    entrypass.grid(row=1, column=1, padx=5, pady=5)
    
    def addpass():
        service = entryservice.get()
        password = entrypass.get()
        if service and password:
            try:
                cursor.execute('''
                            INSERT INTO passwords (service, password)
                            VALUES (?, ?)
                            ''', (service, password))
                connection.commit()
                add.destroy()
                messagebox.showinfo("Успех", "Пароль добавлен!")
                Listbox.insert(END, service)
            except sqlite3.IntegrityError:
                messagebox.showerror("Ошибка!", "Такой сервис уже существует!")
        else:
            messagebox.showerror("Ошибка!", "Поля не должны быть пустыми!")
    
    addpasword = ttk.Button(add, text="Добавить", command=addpass)
    addpasword.grid(row=2, column=0, columnspan=2, pady=10)
def open():
    selected = Listbox.curselection()[0]
    if 0 <= selected < Listbox.size():
        service = listbox.get(selected)
def wview():
            viewpas = Toplevel(root)
            viewpas.geometry('600x600')
            viewpas.title(f'Пароль для {service}')
            cursor.execute("SELECT password FROM passwords WHERE service = ? ", (service))
            ps = cursor.fetchall()
            serv = ttk.Label(text=f"{service}").pack()
            passw = ttk.Label(text=f"{ps}").pack()

add = ttk.Button(root, text='Добавить пароль', command=addwin)
add.pack(pady=20)
opn = ttk.Button(text='Посмотреть', command=wview)
opn.pack()
Listbox = Listbox(root, width=60, height=30, font=("Arial", 12), selectmode=SINGLE)
Listbox.pack()
root.mainloop() 