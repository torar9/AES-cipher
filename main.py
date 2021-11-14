from tkinter.messagebox import showerror
from tkinter import filedialog
from Crypto.Cipher import AES
from Crypto import Random
from tkinter import *
import tkinter as tk
import pygubu
import base64

class MainWindow:
    def __init__(self):
        self.builder = builder = pygubu.Builder()
        builder.add_from_file('ukol3.ui')
        self.main_frame = builder.get_object('main_frame')
        builder.connect_callbacks(self)

        self.text_load_btn = builder.get_object('text_load_btn')
        self.input_text = builder.get_object('input_text')
        self.key_field = builder.get_object('key_field')

        self.vector_group = builder.get_variable("vector_group")
        self.mode_group = builder.get_variable("mode_group")
        self.key_group = builder.get_variable("key_group")

        self.radiobutton1 = builder.get_object('radiobutton1')
        self.radiobutton2 = builder.get_object('radiobutton2')
        self.vector_callback()

        self.radiobutton3 = builder.get_object('radiobutton3')
        self.radiobutton4 = builder.get_object('radiobutton4')
        self.mode_callback()

        self.radiobutton5 = builder.get_object('radiobutton5')
        self.radiobutton6 = builder.get_object('radiobutton6')
        self.radiobutton7 = builder.get_object('radiobutton7')
        self.key_callback()

        self.file_path = ""

    def encrypt(self, message, key, mode):
        iv = Random.new().read(AES.block_size)
        if mode == AES.MODE_CBC:
            cipher = AES.new(key, mode, iv)
        else:
            cipher = AES.new(key, mode)
        padding = AES.block_size - len(message) % AES.block_size
        message += bytes([padding]) * padding
        data = iv + cipher.encrypt(message)
        result = base64.b64encode(data)

        self.input_text.delete(1.0, "end")
        self.input_text.insert(1.0, result)

    def decrypt(self, message, key, mode):
        message = base64.b64decode(message)
        iv = message[:AES.block_size]

        if mode == AES.MODE_CBC:
            cipher = AES.new(key, mode, iv)
        else:
            cipher = AES.new(key, mode)
        data = cipher.decrypt(message[AES.block_size:])
        padding = data[-1]

        if data[-padding:] != bytes([padding]) * padding:
            raise ValueError("Invalid padding...") # remove the padding

        self.input_text.delete(1.0, "end")
        self.input_text.insert(1.0, data[:-padding].decode("utf-8"))

    def encrypt_btn_click(self):
        message = self.input_text.get("1.0", END).encode('utf-8')
        key = self.key_field.get()
        if len(key) < self.key_len or len(key) > self.key_len:
            raise Exception("Délka klíče musí být: {} znaků. Máte {} znaků".format(self.key_len, len(key)))

        key = bytes(key, "utf-8")
        self.encrypt(message, key, self.mode)

    def decrypt_btn_click(self):
        message = self.input_text.get("1.0", END)
        key = self.key_field.get()
        if len(key) < self.key_len or len(key) > self.key_len:
            raise Exception(
                "Délka klíče musí být: {} znaků. Máte {} znaků".format(self.key_len, len(key)))

        key = bytes(key, "utf-8")
        self.decrypt(message, key, self.mode)
    def text_load_btn_click(self):
        file_path = filedialog.askopenfilename(title="Vyber textový soubor", filetypes=
        [
            ('text files', ('.txt'))
        ])
        if not file_path or file_path is None or file_path == "":
            return

        with open(file_path, 'r') as file:
            data = file.read()
            file.close()

        self.input_text.delete(1.0, "end")
        self.input_text.insert(1.0, data)

    def save_btn_click(self):
        save_location = filedialog.asksaveasfile(mode='w', initialfile="cipher", defaultextension=".txt",
                                                 filetypes=
                                                 [
                                                     ('text files', ('.txt'))
                                                 ])
        if save_location is None or not save_location or save_location == "":
            return

        message = self.input_text.get("1.0", END)
        save_location.write(message)
        save_location.close()

    def vector_callback(self):
        self.vector = self.vector_group.get()

    def mode_callback(self):
        value = self.mode_group.get()
        if value == 1:
            self.mode = AES.MODE_CBC
        else:
            self.mode = AES.MODE_ECB

    def key_callback(self):
        value = self.key_group.get()

        if value == 1:
            self.key_len = 16
        elif value == 2:
            self.key_len = 24
        else:
            self.key_len = 32

    def clear_btn_callback(self):
        self.input_text.delete(1.0, "end")
        self.key_field.delete(0, END)

    def run(self):
        self.main_frame.mainloop()

if __name__ == '__main__':
    root = Tk()
    root.title("KOSBD - úkol č. 3")
    app = MainWindow()

    def report_callback_exception(self, exc, val, tb):
        showerror("Error", message=str(val))

    tk.Tk.report_callback_exception = report_callback_exception
    app.run()