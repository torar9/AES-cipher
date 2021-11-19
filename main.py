from tkinter.messagebox import showerror
from tkinter import filedialog
from tkinter import *
from Crypto.Cipher import AES
from pygubu.builder import ttkstdwidgets
from pygubu.builder import *
from Crypto import Random
from tkinter import *
import tkinter as tk
import threading
import pygubu
import base64
import os

class MainWindow:
    def __init__(self, root):
        self.root = root
        #načtení a nastavení GUI
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
        self.big_input = False

        self.file_path = ""

    def encrypt(self, message, key, mode):
        try:
            #Výběr způsobu generování vektoru 'random' nebo 'null' podle výběru uživatele
            if self.vector == 1:
                # Vygenerování náhodného vektoru
                iv = Random.new().read(AES.block_size)
            else:
                #Vygenerování vektoru dosazením samých null hodnot do bloku
                iv = b'\0' * AES.block_size
            # Použít iv v případě CBC
            if mode == AES.MODE_CBC:
                cipher = AES.new(key, mode, iv)
            else:
                #V případě ECB knihovna IV nepožaduje
                cipher = AES.new(key, mode)

            # Uspořádaní dat po blocích
            padding = AES.block_size - len(message) % AES.block_size
            message += bytes([padding]) * padding

            # Zašifrování textu
            data = iv + cipher.encrypt(message) # IV + zpráva
            # Zakodování BASE64
            result = base64.b64encode(data)

            #Nastavení textu v GUI
            result = result.decode()
            # Z výkonostních důvodů povolit maximálně 55 znaků na řádek
            if self.big_input:
                result = '\n'.join(result[i:i + 55] for i in range(0, len(result), 55))
                
            self.input_text.delete(1.0, "end")
            self.input_text.insert(1.0, result)
        except Exception as e:
            raise Exception("Něco se nepovedlo.\nZkuste překontrolovat konfiguraci.")

    def decrypt(self, message, key, mode):
        try:
            # Dekodování zprávy BASE64
            message = base64.b64decode(message)
            # Získání vektoru (první blok -> prvních 16 B)
            iv = message[:AES.block_size]

            # Použít iv v případě CBC
            if mode == AES.MODE_CBC:
                cipher = AES.new(key, mode, iv)
            else:
                cipher = AES.new(key, mode)
            # Dešifrování dat
            data = cipher.decrypt(message[AES.block_size:])
            padding = data[-1]

            if data[-padding:] != bytes([padding]) * padding:
                raise ValueError("Neplatné rozdělení bloků")

            self.input_text.delete(1.0, "end")
            self.input_text.insert(1.0, data[:-padding].decode("utf-8"))
        except Exception as e:
            raise Exception("Něco se nepovedlo.\nZkuste překontrolovat konfiguraci.")

    def encrypt_btn_click(self):
        self.input_text.config(state=NORMAL)
        #Získání zprávy k zakódování z widgety a následné zakódování textu do UTF-8
        message = self.input_text.get("1.0", END).encode('utf-8')

        key = self.key_field.get()
        if len(key) < self.key_len or len(key) > self.key_len:
            raise Exception("Délka klíče musí být: {} znaků.\nMáte: {} znaků".format(self.key_len, len(key)))

        #Transformace zprávy do bytové podoby
        key = bytes(key, "utf-8")
        self.encrypt(message, key, self.mode)

    def decrypt_btn_click(self):
        self.input_text.config(state=NORMAL)
        # Získání zprávy k zakódování a zakódování textu do UTF-8
        message = self.input_text.get("1.0", END).encode('utf-8')
        key = self.key_field.get()
        if len(key) < self.key_len or len(key) > self.key_len:
            raise Exception(
                "Délka klíče musí být: {} znaků.\nMáte {} znaků".format(self.key_len, len(key)))

        # Transformace zprávy do bytové podoby
        key = bytes(key, "utf-8")
        self.decrypt(message, key, self.mode)

    def load_file(self):
        #Otevření dialogového okna pro načtení textového souboru
        try:
            file_path = filedialog.askopenfilename(title="Vyber textový soubor", filetypes=
            [
                ('text files', ('.txt'))
            ])
            if not file_path or file_path is None or file_path == "":
                return

            #Otevření samostatného souboru a načtení dat
            with open(file_path, 'r') as file:
                data = file.read()
                file_size = os.path.getsize(file_path)

                self.big_input = True if file_size >= 1000001 else False

                self.input_text.delete(1.0, "end")
                self.input_text.insert(1.0, data)
                file.close()
        except Exception as e:
            raise Exception("Nepovedlo se načíst soubor: " + str(e))

    def text_load_btn_click(self):
        # Spuštění nového vlákna pro načtení souboru
        startit = threading.Thread(target=self.load_file)
        startit.start()

    def save_file(self):
        #Uložení souboru
        try:
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
        except Exception as e:
            raise Exception("Soubor se nepovedlo uložit:  " + str(e))

    def save_btn_click(self):
        #Spuštění nového vlákna pro uložení souboru
        startit = threading.Thread(target=self.save_file)
        startit.start()

    def vector_callback(self):
        #callback funkce pro nastavení vektoru po kliknutí na tlačítko
        self.vector = self.vector_group.get()

    def mode_callback(self):
        #callback funkce pro nastavení módu
        value = self.mode_group.get()
        if value == 1:
            self.mode = AES.MODE_CBC
        else:
            self.mode = AES.MODE_ECB

    def key_callback(self):
        #callback funkce pro nastavení velikosti klíče po kliknutí na radiobutton
        value = self.key_group.get()

        if value == 1:
            self.key_len = 16
        elif value == 2:
            self.key_len = 24
        else:
            self.key_len = 32

    def clear_btn_callback(self):
        #callback funkce pro tlačítko reset
        self.input_text.delete(1.0, "end")
        self.key_field.delete(0, END)

    def run(self):
        self.main_frame.mainloop()

if __name__ == '__main__':
    root = Tk()
    root.title("KOSBD - úkol č. 3")
    app = MainWindow(root)
    
    #Nastavení dialogového okna pro oznámení chyb
    def report_callback_exception(self, exc, val, tb):
        showerror("Error", message=str(val))

    tk.Tk.report_callback_exception = report_callback_exception
    app.run()