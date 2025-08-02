import base64
import tkinter as tk
from tkinter import ttk
import random
import string

MORSE_CODE_DICT={'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.','G':'--.',
'H':'....','I':'..','J':'.---','K':'-.-','L':'.-..','M':'--','N':'-.','O':'---','P':'.--.',
'Q':'--.-','R':'.-.','S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-','Y':'-.--',
'Z':'--..','1':'.----','2':'..---','3':'...--','4':'....-','5':'.....','6':'-....','7':'--...',
'8':'---..','9':'----.','0':'-----',', ':'--..--','.':'.-.-.-','?':'..--..','/':'-..-.',
'-':'-....-','(':'-.--.',')':'-.--.-',' ':'/'}
REVERSE_MORSE_DICT={v:k for k,v in MORSE_CODE_DICT.items()}

def process_key(key):
    processed=[]
    for c in key[:3]:
        processed.append(c.upper() if c.isalpha() else 'A')
    while len(processed)<3:processed.append('A')
    return ''.join(processed)

def text_to_morse(text):
    return ' '.join([MORSE_CODE_DICT[char] for char in text.upper() if char in MORSE_CODE_DICT])

def morse_to_text(morse):
    return ''.join([REVERSE_MORSE_DICT[code] for code in morse.split(' ') if code in REVERSE_MORSE_DICT])

def binary_to_letters(binary_str):
    return binary_str.replace('1','I').replace('0','l')

def letters_to_binary(letter_str):
    return letter_str.replace('I','1').replace('l','0')

def encrypt_with_key(text,key):
    key=process_key(key)
    key_value=sum(ord(c) for c in key)
    return ''.join([chr(ord(char)+(key_value%10)) for char in text])

def decrypt_with_key(text,key):
    key=process_key(key)
    key_value=sum(ord(c) for c in key)
    return ''.join([chr(ord(char)-(key_value%10)) for char in text])

def encode_text(input_str):
    key=''.join(random.choices(string.ascii_uppercase,k=3))
    encoded=text_to_morse(input_str)
    encoded=base64.b64encode(encoded.encode('utf-8')).decode('utf-8')
    encoded=encrypt_with_key(encoded,key)
    encoded=encoded.encode('utf-8').hex()
    binary_str=''.join([format(ord(c),'08b') for c in encoded])
    encoded=binary_to_letters(binary_str)
    return f"tRus~{encoded}",key

def decode_text(encoded_str,key):
    if not encoded_str.startswith("tRus~"):
        return ''.join(random.choices(string.ascii_letters+string.digits,k=10))
    try:
        encoded_str=encoded_str[5:]
        binary_str=letters_to_binary(encoded_str)
        decoded=[chr(int(binary_str[i:i+8],2)) for i in range(0,len(binary_str),8) if len(binary_str[i:i+8])==8]
        decoded_str=''.join(decoded)
        decoded_bytes=bytes.fromhex(decoded_str)
        decoded_str=decoded_bytes.decode('utf-8')
        decoded_str=decrypt_with_key(decoded_str,key)
        decoded_str=base64.b64decode(decoded_str).decode('utf-8')
        return morse_to_text(decoded_str)
    except:
        return ''.join(random.choices(string.ascii_letters+string.digits,k=10))

class EncoderDecoderGUI:
    def __init__(self,root):
        self.root=root
        self.root.title("tk")
        self.root.geometry("800x550")
        self.root.resizable(True,True)
        style=ttk.Style()
        style.configure("TLabel",font=("SimHei",10))
        style.configure("TText",font=("SimHei",10))
        
        encrypt_frame=ttk.LabelFrame(root,text="加密 (自动生成密钥)")
        encrypt_frame.pack(fill="both",expand=True,padx=10,pady=5)
        ttk.Label(encrypt_frame,text="输入要加密的文本:").pack(anchor="w",padx=5,pady=5)
        self.encrypt_input=tk.Text(encrypt_frame,height=2,wrap=tk.WORD)
        self.encrypt_input.pack(fill="both",expand=True,padx=5,pady=5)
        self.encrypt_btn=ttk.Button(encrypt_frame,text="生成加密结果",command=self.generate_encrypt)
        self.encrypt_btn.pack(padx=5,pady=5)
        ttk.Label(encrypt_frame,text="加密结果 (I=1, l=0):").pack(anchor="w",padx=5,pady=5)
        self.encrypt_output=tk.Text(encrypt_frame,height=2,wrap=tk.WORD,state="disabled")
        self.encrypt_output.pack(fill="both",expand=True,padx=5,pady=5)
        ttk.Label(encrypt_frame,text="加密密钥 (请记录用于解密):",foreground="red").pack(anchor="w",padx=5,pady=5)
        self.generated_key_var=tk.StringVar(value="尚未生成")
        ttk.Label(encrypt_frame,textvariable=self.generated_key_var,font=("Arial",12,"bold")).pack(anchor="w",padx=5,pady=5)
        
        decrypt_frame=ttk.LabelFrame(root,text="解密 (输入密钥)")
        decrypt_frame.pack(fill="both",expand=True,padx=10,pady=5)
        ttk.Label(decrypt_frame,text="输入解密密钥:").pack(anchor="w",padx=5,pady=5)
        self.decrypt_key_var=tk.StringVar()
        self.decrypt_key_entry=ttk.Entry(decrypt_frame,textvariable=self.decrypt_key_var,width=10,font=("Arial",12,"bold"))
        self.decrypt_key_entry.pack(anchor="w",padx=5,pady=5)
        ttk.Label(decrypt_frame,text="输入要解密的字符串:").pack(anchor="w",padx=5,pady=5)
        self.decrypt_input=tk.Text(decrypt_frame,height=2,wrap=tk.WORD)
        self.decrypt_input.pack(fill="both",expand=True,padx=5,pady=5)
        self.decrypt_btn=ttk.Button(decrypt_frame,text="解密",command=self.perform_decrypt)
        self.decrypt_btn.pack(padx=5,pady=5)
        ttk.Label(decrypt_frame,text="解密结果:").pack(anchor="w",padx=5,pady=5)
        self.decrypt_output=tk.Text(decrypt_frame,height=2,wrap=tk.WORD,state="disabled")
        self.decrypt_output.pack(fill="both",expand=True,padx=5,pady=5)
        
        self.status_var=tk.StringVar()
        self.status_var.set("请输入文本加密，或输入密钥和解密字符串解密")
        status_bar=ttk.Label(root,textvariable=self.status_var,relief=tk.SUNKEN,anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM,fill=tk.X)
    
    def generate_encrypt(self):
        input_text=self.encrypt_input.get("1.0",tk.END).strip()
        try:
            if input_text:
                encrypted,key=encode_text(input_text)
                self.encrypt_output.config(state="normal")
                self.encrypt_output.delete("1.0",tk.END)
                self.encrypt_output.insert(tk.END,encrypted)
                self.encrypt_output.config(state="disabled")
                self.generated_key_var.set(key)
                self.status_var.set(f"加密成功，密钥: {key} (请使用把这个密钥告诉解密的人)")
            else:self.status_var.set("请输入要加密的文本")
        except Exception as e:self.status_var.set(f"加密错误: {str(e)}")
    
    def perform_decrypt(self):
        input_text=self.decrypt_input.get("1.0",tk.END).strip()
        key=self.decrypt_key_var.get().strip()
        try:
            if input_text:
                decrypted=decode_text(input_text,key)
                self.decrypt_output.config(state="normal")
                self.decrypt_output.delete("1.0",tk.END)
                self.decrypt_output.insert(tk.END,decrypted)
                self.decrypt_output.config(state="disabled")
                self.status_var.set("解密完成")
            else:self.status_var.set("请输入要解密的字符串")
        except:
            random_str=''.join(random.choices(string.ascii_letters+string.digits,k=10))
            self.decrypt_output.config(state="normal")
            self.decrypt_output.delete("1.0",tk.END)
            self.decrypt_output.insert(tk.END,random_str)
            self.decrypt_output.config(state="disabled")
            self.status_var.set("解密完成")

if __name__=="__main__":
    root=tk.Tk()
    app=EncoderDecoderGUI(root)
    root.mainloop()