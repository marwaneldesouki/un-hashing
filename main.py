from tkinter import *
from tkinter import ttk
import hashlib as h
import base64







class App(Tk):
    def __init__(self):#0main_1winner
        try:
            super().__init__()
            self.geometry('480x230')
            self.__main__()
        except Exception as ex:
            pass
    def save_file(self,text,encryption_name):
        if(encryption_name=="md5"):
            lines_in_file = open("md5.txt", 'r').readlines()
            number_of_lines = len(lines_in_file)
            f = open ("md5.txt","a")
            if(number_of_lines==0):
                f.write(text)
                f.close()
            else:
                f.write("\n"+text)
                f.close()
        else:
            lines_in_file = open("sha.txt", 'r').readlines()
            number_of_lines = len(lines_in_file)
            f = open ("sha.txt","a")
            if(number_of_lines==0):
                f.write(text)
                f.close()
            else:
                f.write("\n"+text)
                f.close()


    def md5_encode(self,text='c'):
        hash_obj= h.md5(text.encode())
        md5_hash=hash_obj.hexdigest()
        return md5_hash

    def md5_decode(self,text):
        f = open("md5.txt","r")
        for word in f:
            encoded_word = app.md5_encode(word)
            if(encoded_word == text):
                print(word)
                return word
    def sha_encode(self,text):
        hash_obj= h.sha256(text.encode())
        sha_hash=hash_obj.hexdigest()
        return sha_hash

    def sha_decode(self,text):
        f = open("sha.txt","r")
        for word in f:
            encoded_word = app.sha_encode(word)
            if(encoded_word == text):
                print(word)
                return word

    def inputs(self,enc_lbl,text,hash_name,enc_dec):
        if(enc_dec=="enc"):
            match hash_name:
                case "md5":
                    try:
                        app.save_file(text,"md5")
                        encoded_text = app.md5_encode(text)
                        print(encoded_text)
                        enc_lbl.config(text="EncodedText:"+encoded_text)
                    except:
                        print("format error")
                        enc_lbl.config(text="format error")

                case "sha":
                    try:
                        app.save_file(text,"sha")
                        encoded_text = app.sha_encode(text)
                        print(encoded_text)
                        enc_lbl.config(text="EncodedText:"+encoded_text)
                    except:
                        print("format error")
                        enc_lbl.config(text="format error")
                case "base64":
                    try:
                        base64_bytes = base64.b64encode(text.encode('utf-8'))
                        encoded_text = str(base64_bytes)
                        print(encoded_text)
                        enc_lbl.config(text="EncodedText:"+encoded_text)
                    except:
                        print("format error")
                        enc_lbl.config(text="format error")

                    
        else:
            match hash_name:
                case "md5":
                    try:
                        print("md5")
                        decoded_text = app.md5_decode(text)
                        print(decoded_text)
                        enc_lbl.config(text="DecodedText:"+decoded_text)
                    except:
                        print("format error")
                        enc_lbl.config(text="format error")
                    
                case "sha":
                    try:
                        print("sha")
                        decoded_text = app.sha_decode(text)
                        print(decoded_text)
                        enc_lbl.config(text="DecodedText:"+decoded_text)
                    except:
                        print("format error")
                        enc_lbl.config(text="format error")
                case "base64":
                    try:
                        base64_bytes = base64.b64decode(str(text).encode('utf-8')).decode("utf-8")
                        decoded_text = base64_bytes
                        print(decoded_text)
                        enc_lbl.config(text="DecodedText:"+decoded_text)
                    except:
                        print("format error")
                        enc_lbl.config(text="format error")
                    
   
        
    
    def __main__(self):
        self.title("xxx")
        self.config(background='white')
        # Create and style buttons
        notebook = ttk.Notebook(self)
        tab1 = Frame(notebook)
        tab2 = Frame(notebook)
        notebook.add(tab1,text="Encryption")
        notebook.add(tab2,text="Decryption")
        notebook.pack(expand=True,fill="both")
        ######tab1#########
        combo_enc = ttk.Combobox(tab1,values=('md5','sha','base64'))
        combo_enc.set("md5")
        combo_enc.pack()
        Label(tab1,text="Your Text:",width=15,height=2).pack()
        encode_bx=Entry(tab1,name="encode_bx")
        encode_bx.pack()
        enc_lbl = Label(tab1,name="encoded_label",width=100,height=2)
        Button(tab1,text="Encrypt" ,command=lambda: app.inputs(enc_lbl,encode_bx.get(),combo_enc.get(),"enc")).pack()
        enc_lbl.pack()
        enc_lbl.config(text="EncodedText:",)
        ######tab2#########
        combo_dec = ttk.Combobox(tab2,values=('md5','sha','base64'))
        combo_dec.set("md5")
        combo_dec.pack()
        Label(tab2,text="Your Text:",width=15,height=2).pack()
        decode_bx=Entry(tab2,name="decode_bx")
        decode_bx.pack()
        dec_lbl = Label(tab2,name="decoded_label",width=100,height=2)
        Button(tab2,text="Decrypt" ,command=lambda: app.inputs(dec_lbl,decode_bx.get(),combo_dec.get(),"dec")).pack()
        dec_lbl.pack()
        dec_lbl.config(text="DecodedText:",)
        
        

    



app = App()
app.mainloop()