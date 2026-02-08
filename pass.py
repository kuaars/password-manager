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
    login TEXT NOT NULL,
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
    
    login_label = ttk.Label(add, text="Логин:", font=('Arial', 12))
    login_label.grid(row=1, column=0, padx=5, pady=5, sticky=W)
    
    password_label = ttk.Label(add, text="Пароль:", font=('Arial', 12))
    password_label.grid(row=2, column=0, padx=5, pady=5, sticky=W)

    entryservice = ttk.Entry(add, width=30, font=('Arial', 12))
    entryservice.grid(row=0, column=1, padx=5, pady=5)
    
    entrylogin = ttk.Entry(add, width=30, font=('Arial', 12))
    entrylogin.grid(row=1, column=1, padx=5, pady=5)

    entrypass = ttk.Entry(add, width=30, font=('Arial', 12), show="*")
    entrypass.grid(row=2, column=1, padx=5, pady=5)
    
    def addpass():
        service = entryservice.get()
        login = entrylogin.get()
        password = entrypass.get()
        if service and password and login:
            try:
                cursor.execute('''
                            INSERT INTO passwords (service, login, password)
                            VALUES (?, ?, ?)
                            ''', (service, login, password))
                connection.commit()
                add.destroy()
                messagebox.showinfo("Успех", "Пароль добавлен!")
                Listbox.insert(END, service)
            except sqlite3.IntegrityError:
                messagebox.showerror("Ошибка!", "Такой сервис уже существует!")
        else:
            messagebox.showerror("Ошибка!", "Поля не должны быть пустыми!")
    
    addpasword = ttk.Button(add, text="Добавить", command=addpass)
    addpasword.grid(row=3, column=0, columnspan=2, pady=10)

def view_password():
    try:
        selected = Listbox.curselection()[0]
        service = Listbox.get(selected)
        
        viewpas = Toplevel(root)
        viewpas.geometry('600x600')
        viewpas.title(f'Пароль для {service}')
        
        cursor.execute("SELECT login, password FROM passwords WHERE service = ?", (service,))
        result = cursor.fetchone()
        
        if result:
            login = result[0]  # Первый элемент - логин
            password = result[1]  # Второй элемент - пароль
            
            serv_label = ttk.Label(viewpas, text=f"Сервис: {service}", font=('Arial', 14))
            serv_label.pack(pady=20)

            login_label = ttk.Label(viewpas, text=f"Логин: {login}", font=('Arial', 14))
            login_label.pack(pady=10)

            pass_label = ttk.Label(viewpas, text=f"Пароль: {password}", font=('Arial', 12))
            pass_label.pack(pady=10)
        else:
            messagebox.showerror("Ошибка", "Пароль не найден!")
            
    except IndexError:
        messagebox.showerror("Ошибка", "Выберите сервис из списка!")
    except Exception as e:
        messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")

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
            messagebox.showerror("Ошибка", "Выберите сервис из списка!")
            return
            
        selected = selected_index[0]
        service = Listbox.get(selected)
        
        answer = messagebox.askyesno("ВНИМАНИЕ!", f"Вы уверены, что хотите удалить пароль для {service}?")
        
        if answer:
            cursor.execute("DELETE FROM passwords WHERE service = ?", (service,))
            connection.commit()
            messagebox.showinfo("Успех", f"Пароль для {service} удален!")
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

root.mainloop()
connection.close()
