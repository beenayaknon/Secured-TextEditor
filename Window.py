from tkinter import *
from tkinter import messagebox as message
from tkinter import filedialog as fd
from Stack import *
from tkinter.simpledialog import askstring
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode
import os

class Window:
    def __init__(self):
        self.isFileOpen = True
        self.File = ""
        self.isFileChange = False
        self.elecnt = 0
        self.mode = "normal"
        self.fileTypes = [('Text Document', '*.txt')]
        self.Key = ""
        self.Salt = None
        self.encrypted_data = None

        self.window = Tk()
        self.window.geometry("1200x700+200+150")
        self.window.wm_title("Untitled")

        self.TextBox = Text(self.window, highlightthickness=0, font=("Helvetica", 14))

        self.menuBar = Menu(self.window, bg="#eeeeee", font=("Helvetica", 13), borderwidth=0)
        self.window.config(menu=self.menuBar)

        self.fileMenu = Menu(self.menuBar, tearoff=0, activebackground="#d5d5e2", bg="#eeeeee", bd=2, font="Helvetica")
        self.fileMenu.add_command(label="    New       Ctrl+N", command=self.new_file, )
        self.fileMenu.add_command(label="    Open...      Ctrl+O", command=self.open_file)
        self.fileMenu.add_command(label="    Save as...        Ctrl+S", command=self.save_new_file)
        self.fileMenu.add_separator()
        self.fileMenu.add_command(label="    Exit          Ctrl+D", command=self._quit)
        self.menuBar.add_cascade(label="   File   ", menu=self.fileMenu)

        self.editMenu = Menu(self.menuBar, tearoff=0, activebackground="#d5d5e2", bg="#eeeeee", bd=2,
                             font="Helvetica", )
        self.editMenu.add_command(label="    Undo    Ctrl+Z", command=self.undo)
        self.editMenu.add_command(label="    Redo    Ctrl+Shift+Z", command=self.redo)
        self.editMenu.add_separator()
        self.editMenu.add_command(label="    Cut    Ctrl+X", command=self.cut)
        self.editMenu.add_command(label="    Copy    Ctrl+C", command=self.copy)
        self.editMenu.add_command(label="    Paste   Ctrl+V", command=self.paste)
        self.menuBar.add_cascade(label="   Edit   ", menu=self.editMenu)
 
        self.viewMenu = Menu(self.menuBar, tearoff=0, activebackground="#d5d5e2", bg="#eeeeee", bd=2,
                             font="Helvetica", )
        self.viewMenu.add_command(label="   Change Mode   ", command=self.change_color)
        self.menuBar.add_cascade(label="   View   ", menu=self.viewMenu)

        self.helpMenu = Menu(self.menuBar, tearoff=0, activebackground="#d5d5e2", bg="#eeeeee", bd=2,
                             font="Helvetica", )
        self.helpMenu.add_command(label="    About   ", command=self.about)
        self.menuBar.add_cascade(label="   Help   ", menu=self.helpMenu)

        self.UStack = Stack(self.TextBox.get("1.0", "end-1c"))
        self.RStack = Stack(self.TextBox.get("1.0", "end-1c"))
    
    # 1. Creates a new file
    def new_file(self):
        self.TextBox.config(state=NORMAL)
        if self.isFileOpen:
            if len(self.File) > 0:
                self.secure_save_file(self.File)
            else:
                self.save_new_file()
            self.window.wm_title("Untitled")
            self.TextBox.delete('1.0', END)
            self.File = ''
        else:
            self.isFileOpen = True
            self.window.wm_title("Untitled")

        self.Salt = ""
        self.Key = ""
        self.isFileChange = False

        if self.UStack.size() > 0:
            self.UStack.clear_stack()
            self.UStack.add(self.TextBox.get("1.0", "end-1c"))

    # 2. Open a file which opens a file in editing mode
    def open_file(self):
        self.TextBox.config(state=NORMAL)
        if self.isFileOpen:
            self.secure_save_file(self.File)

        # open new file
        filename = fd.askopenfilename(filetypes=self.fileTypes, defaultextension="*.*")
        if len(filename) != 0:
            self.isFileChange = False
            while True:
                # Ask the user to enter the encryption key
                key_input = askstring("Encryption Key", "Enter the encryption key to decrypt the file:")
                if key_input is None or key_input == "":
                    message.showinfo("Information", "Operation cancelled or no key provided. File cannot be opened")
                    break

                # Key is inputted, try to decrypt
                try:
                    with open(filename, "rb") as f:
                        file_contents = f.read()
                        salt, encrypted_data = file_contents.split(b'|', 1)
                    self.Salt = salt
                    self.Key = key_input

                    kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend()
                    )
                    key = urlsafe_b64encode(kdf.derive(key_input.encode()))
                    cipher_suite = Fernet(key)
                    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
                    self.TextBox.delete('1.0', END)
                    self.TextBox.insert(END, decrypted_data)
                    self.window.wm_title(filename)
                    self.isFileOpen = True
                    self.File = filename
                    break
                except Exception as e:
                    message.showerror("Decryption Error", "Failed to decrypt the file. Ensure you've entered the correct key.")
        
        self.encrypted_data = ""

        if self.UStack.size() > 0:
            self.UStack.clear_stack()
            self.UStack.add(self.TextBox.get("1.0", "end-1c"))
    
    # 3. save with new encrypt (before closing)
    def secure_save_file(self, file):
        result = message.askquestion('Window Title', 'Do You Want to Save Changes')
        if result == "yes":
            if len(file) == 0:
                inputValue = self.TextBox.get("1.0", "end-1c")
                personal_key = askstring("Encryption Key", "Enter your encryption key before saving:")
                if personal_key:
                    salt = os.urandom(16)
                    kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                            backend=default_backend()
                            )
                    key = urlsafe_b64encode(kdf.derive(personal_key.encode()))
                    cipher_suite = Fernet(key)
                    encrypted_data = cipher_suite.encrypt(inputValue.encode())
                    self.encrypted_data = encrypted_data
                    # ask where to save the file
                    filename = fd.asksaveasfilename(filetypes=self.fileTypes, defaultextension=".txt")
                    if filename:
                        with open(filename, "wb") as f:
                            f.write(salt + b"|" + encrypted_data)

                        self.File = filename
                        self.window.wm_title(filename)
                        self.isFileChange = False
                        message.showinfo("Encryption", "Your file has been encrypted.")
                        self.Key = personal_key
                        self.Salt = salt
            else:
                while (True):
                    personal_key = askstring("Encryption Key", "Enter your encryption key before saving:")
                    if not personal_key:
                        break;
                    if personal_key and personal_key == self.Key:
                        salt = os.urandom(16)
                        kdf = PBKDF2HMAC(
                            algorithm=hashes.SHA256(),
                            length=32,
                            salt=salt,
                            iterations=100000,
                            backend=default_backend()
                        )
                        key = urlsafe_b64encode(kdf.derive((self.Key).encode()))
                        inputValue = self.TextBox.get("1.0", "end-1c")
                        cipher_suite = Fernet(key)
                        encrypted_data = cipher_suite.encrypt(inputValue.encode())
                        self.TextBox.delete('1.0', END)
                        with open(file, "wb") as f:
                            f.write(salt + b"|" + encrypted_data)
                        self.Salt = salt
                        break
                    else:
                        message.showerror("Decryption Error", "Failed to decrypt the file. Ensure you've entered the correct key.")
            self.isFileChange = False

    # 4. secure save before close/new file/open file
    def save_new_file(self):
        result = message.askquestion('Window Title', 'Do You Want to Save Changes')
        if result == "yes":
            inputValue = self.TextBox.get("1.0", "end-1c")
            # Save new file = Ask for new encryption
            personal_key = askstring("Encryption Key", "Enter your encryption key:")
            if personal_key:
                salt = os.urandom(16)
                kdf = PBKDF2HMAC(
                        algorithm=hashes.SHA256(),
                        length=32,
                        salt=salt,
                        iterations=100000,
                        backend=default_backend()
                        )
                key = urlsafe_b64encode(kdf.derive(personal_key.encode()))
                cipher_suite = Fernet(key)
                encrypted_data = cipher_suite.encrypt(inputValue.encode())
                self.encrypted_data = encrypted_data
                # ask where to save the file
                filename = fd.asksaveasfilename(filetypes=self.fileTypes, defaultextension=".txt")
                if filename:
                    with open(filename, "wb") as f:
                        f.write(salt + b"|" + encrypted_data)

                    self.File = filename
                    self.window.wm_title(filename)
                    self.isFileChange = False
                    message.showinfo("Encryption", "Your file has been encrypted.")
                    self.Key = personal_key
                    self.Salt = salt
                else:
                    message.showerror("Encryption Key Required", "No encryption key provided. File not saved.")


    # 5. Writing in file
    def write_file(self, file):
        inputValue = self.TextBox.get("1.0", "end-1c")
        outfile = open(file, "w")
        outfile.write(inputValue)

    # 7. This function invokes whenever a key is pressed whether it is a special-key or a normal key
    def key_pressed(self, event):
        if event.char == "\x1a" and event.keysym == "Z":
            self.redo()
        elif event.char == "\x1a" and event.keysym == "z":
            self.undo()
        elif event.char == "\x13":
            self.save_new_file()
        elif event.char == "\x0f":
            self.open_file()
        elif event.char == "\x0e":
            self.new_file()
        elif event.char == "\x04":
            self._quit()
        elif event.char == " " or event.char == ".":
            self.isFileChange = True
            inputValue = self.TextBox.get("1.0", "end-1c")
            self.UStack.add(inputValue)
        elif event.keysym == 'Return':
            self.isFileChange = True
            inputValue = self.TextBox.get("1.0", "end-1c")
            self.UStack.add(inputValue)
        elif event.keysym == 'BackSpace':
            self.isFileChange = True
            inputValue = self.TextBox.get("1.0", "end-1c")
            self.UStack.add(inputValue)
        elif (event.keysym == 'Up' or event.keysym == 'Down') or (event.keysym == 'Left' or event.keysym == 'Right'):
            self.isFileChange = True
            self.elecnt = 0
            inputValue = self.TextBox.get("1.0", "end-1c")
            self.UStack.add(inputValue)
        else:
            self.isFileChange = True
            inputValue = self.TextBox.get("1.0", "end-1c")
            if self.elecnt >= 1:
                self.UStack.remove()
            self.UStack.add(inputValue)
            self.elecnt += 1

        if self.TextBox.get("1.0", "end-1c") == self.UStack.ele(0):
            self.isFileChange = False

    # 8. Undo the data by calling Stack class functions
    def undo(self):
        self.isFileChange = True
        if self.UStack.size() == 1:
            self.UStack.remove()
            self.UStack.add(self.TextBox.get("1.0", "end-1c"))
        else:
            self.RStack.add(self.UStack.remove())
            text = self.UStack.peek()
            self.TextBox.delete('1.0', END)
            self.TextBox.insert(END, text)

    # 9. Redo/Rewrite the task/data by calling Stack class functions
    def redo(self):
        if self.RStack.size() > 1:
            text = self.RStack.peek()
            self.TextBox.delete('1.0', END)
            self.TextBox.insert(END, text)
            self.UStack.add(text)
            self.RStack.remove()

    # 10. Close the window (called when the close button at the right-top is clicked)
    def on_closing(self):
        if self.isFileOpen and self.isFileChange:
            self.secure_save_file(self.File)
        self._quit()

    # 11. Quit or Exit Function to exit from Text-Editor
    def _quit(self):
        self.window.quit()
        self.window.destroy()

    # 12. Night mode view by changing the color of Text widget
    def change_color(self):

        if self.mode == "normal":
            self.mode = "dark"
            self.TextBox.configure(background="#2f2b2b", foreground="#BDBDBD", font=("Helvetica", 14),
                                   insertbackground="white")
        else:
            self.mode = "normal"
            self.TextBox.configure(background="white", foreground="black", font=("Helvetica", 14),
                                   insertbackground="black")

    # 13. About
    def about(self):
        outfile = open("About.txt", "r")
        text = outfile.read()
        self.TextBox.insert(END, text)
        self.TextBox.config(state=DISABLED)

    # 14. Copy
    def copy(self):
        self.TextBox.clipboard_clear()
        text = self.TextBox.get("sel.first", "sel.last")
        self.TextBox.clipboard_append(text)

    # 15. Cut
    def cut(self):
        self.copy()
        self.TextBox.delete("sel.first", "sel.last")
        self.UStack.add(self.TextBox.get("1.0", "end-1c"))

    # 16. Paste
    def paste(self):
        text = self.TextBox.selection_get(selection='CLIPBOARD')
        self.TextBox.insert('insert', text)
        self.UStack.add(self.TextBox.get("1.0", "end-1c"))