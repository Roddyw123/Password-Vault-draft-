import sqlite3, hashlib
from tkinter import *
from tkinter import simpledialog
from functools import partial
import random
# default directory password is test123
# database code
with sqlite3.connect('password_vault.db') as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS masterpassword(
id INTEGER PRIMARY KEY,
password TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS vault(
id INTEGER PRIMARY KEY,
website TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")


# Create PopUp
def popUp(text):
    answer = simpledialog.askstring("Fill in the boxes", text)
    print(answer)

    return answer


# Initiate window
window = Tk()
window.update()


window.title("Password Vault")


def hashPassword(input):
    hash1 = hashlib.md5(input)
    hash1 = hash1.hexdigest()

    return hash1


def firstTimeScreen():
    window.geometry('250x125')
    lbl = Label(window, text="Choose a Master Password")
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*")
    txt.pack()
    txt.focus()

    lbl1 = Label(window, text="Configure (re-enter) master password")
    lbl1.config(anchor=CENTER)
    lbl1.pack()

    txt1 = Entry(window, width=20, show="*")
    txt1.pack()

    def savePassword():
        if txt.get() == txt1.get():
            hashedPassword = hashPassword(txt.get().encode('utf-8'))

            insert_password = """INSERT INTO masterpassword(password)
            VALUES(?) """
            cursor.execute(insert_password, [(hashedPassword)])
            db.commit()

            vaultScreen()
        else:
            lbl.config(text="Password Config Failed")

    btn = Button(window, text="Save", command=savePassword)
    btn.pack(pady=5)


def loginScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x150')
    #window.configure(bg='gray')

    Label(window, text="Welcome Back!", width=300, height=2, bg='#80d8ff').pack()
    lbl = Label(window, text="Master Password", bg='gray')
    lbl.config(anchor=CENTER)
    lbl.pack()

    txt = Entry(window, width=20, show="*", bg='gray', highlightbackground='gray', highlightcolor='gray', highlightthickness=4, border=4)
    txt.pack()
    txt.focus()

    lbl1 = Label(window, bg='gray')
    lbl1.config(anchor=CENTER)
    lbl1.pack(side=TOP)

    def getMasterPassword():
        checkHashedPassword = hashPassword(txt.get().encode('utf-8'))
        cursor.execute('SELECT * FROM masterpassword WHERE id = 1 AND password = ?', [(checkHashedPassword)])
        return cursor.fetchall()

    def checkPassword():
        password = getMasterPassword()

        if password:
            vaultScreen()
        else:
            txt.delete(0, 'end')
            lbl1.config(text="Wrong Password")

    btn = Button(window, text="Submit", command=checkPassword, highlightbackground='black', highlightcolor='#D4D4D4')
    btn.pack(pady=1)


def vaultScreen():
    for widget in window.winfo_children():
        widget.destroy()

    def addEntry():
        text1 = "Website"
        text2 = "Username"
        text3 = "Password"
        website = popUp(text1)
        username = popUp(text2)
        password = popUp(text3)

        insert_fields = """INSERT INTO vault(website, username, password) 
        VALUES(?, ?, ?) """
        cursor.execute(insert_fields, (website, username, password))
        db.commit()

        vaultScreen()

    def removeEntry(input):
        cursor.execute("DELETE FROM vault WHERE id = ?", (input,))
        db.commit()
        vaultScreen()

    def generatePassword():
        global chars
        global lblpass
        lenpass = IntVar()
        passchar = StringVar()
        chars = ''
        window1 = Toplevel(window)
        window1.title("Generate Password")
        window1.geometry("320x220")
        Label(window1, text="Generate Password", width='300', height='2', bg='#80d8ff').pack()
        lblpass = Label(window1)

        def create_pass():
            chars1 = str(passchar.get())
            length = int(lenpass.get())
            print(chars)
            print(length)
            passwords_generated = 1
            for x in range(0,passwords_generated):
                passwordnum = ""
                for x in range(0, length):
                    random_password = random.choice(chars1)
                    passwordnum = passwordnum + random_password
                print(passwordnum)




            passchar.delete(0, END)
            lenpass.delete(0, END)
            lblpass.config(text=passwordnum)

        def defaultchar(text):
            passchar.insert(0, text)

        genBut = Button(window1, text="Generate Password", pady=5, width='20', command=create_pass)
        Label(window1, text="Desired Characters in RNG Pass", pady=5).pack()
        lenpass = Entry(window1, width="20")
        passchar = Entry(window1, width='20')
        passchar.pack()
        Button(window1, text="Add default chars", width='20', command=lambda: defaultchar("qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890-=!@#$%^&*()_+`~[]{};':/<>?))")).pack()
        Label(window1, text="Desired length of RNG pass", pady=5).pack()
        lenpass.pack()
        genBut.pack()
        lblpass.pack()


    window.geometry('750x550')
    window.resizable(height=None, width=None)
    lbl = Label(window, text="Password Vault", bg='#80d8ff')
    lbl.grid(column=1)

    Lb = Label(window, text="Search By ID:")
    Lb.grid(column=0, row=1, columnspan=2)
    En = Entry(window, width=5)
    En.grid(column=1, row=1, columnspan=2)

    btn = Button(window, text="Add Password", command=addEntry)
    btn.grid(column=0, row=2, columnspan=2)

    btn1 = Button(window, text="Generate password", command=generatePassword)
    btn1.grid(column=1, row=2, columnspan=2)

    lbl = Label(window, text="Website")
    lbl.grid(row=3, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=3, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=3, column=2, padx=80)

    cursor.execute('SELECT * FROM vault')
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute('SELECT * FROM vault')
            array = cursor.fetchall()

            lbl1 = Label(window, text=(array[i][1]), font=("Times", 12))
            lbl1.grid(column=0, row=(i + 4))
            lbl2 = Label(window, text=(array[i][2]), font=("Times", 12))
            lbl2.grid(column=1, row=(i + 4))
            lbl3 = Label(window, text=(array[i][3]), font=("Times", 12))
            lbl3.grid(column=2, row=(i + 4))

            btn = Button(window, text="Remove", command=partial(removeEntry, array[i][0]))
            btn.grid(column=3, row=(i + 4), pady=10)

            i = i + 1

            cursor.execute('SELECT * FROM vault')
            if (len(cursor.fetchall()) <= i):
                break


cursor.execute('SELECT * FROM masterpassword')
if (cursor.fetchall()):
    loginScreen()
else:
    firstTimeScreen()
window.mainloop()