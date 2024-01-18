import tkinter as tk
import hashlib
import pandas as pd

def generate():
    width = 700
    height = 700
    window = tk.Toplevel(root)
    window.title("Hash Generator")
    window.geometry(f"{width}x{height}")
    hash_text = entry.get().encode('utf-8')
    custom_font=("Monotype Corsiva",15)
    
    md5_hash = hashlib.md5()
    md5_hash.update(hash_text)
    md5_hash = md5_hash.hexdigest()
    
    sha1_hash = hashlib.sha1()
    sha1_hash.update(hash_text)
    sha1_hash = sha1_hash.hexdigest()
    
    sha224_hash = hashlib.sha224()
    sha224_hash.update(hash_text)
    sha224_result = sha224_hash.hexdigest()
    
    sha256_hash = hashlib.sha256()
    sha256_hash.update(hash_text)
    sha256_result = sha256_hash.hexdigest()
    
    sha384_hash = hashlib.sha384()
    sha384_hash.update(hash_text)
    sha384_result = sha384_hash.hexdigest()
    
    sha512_hash = hashlib.sha512()
    sha512_hash.update(hash_text)
    sha512_result = sha512_hash.hexdigest()
    
    label_md5 = tk.Label(window, text=f"MD5: {md5_hash}", font = custom_font)
    label_md5.pack(pady=15)

    label_sha1 = tk.Label(window, text=f"SHA-1: {sha1_hash}", font = custom_font)
    label_sha1.pack(pady=15)

    label_sha224 = tk.Label(window, text=f"SHA-224: {sha224_result}", font = custom_font)
    label_sha224.pack(pady=15)

    label_sha256 = tk.Label(window, text=f"SHA-256: {sha256_result}", font = custom_font)
    label_sha256.pack(pady=15)

    label_sha384 = tk.Label(window, text=f"SHA-384: {sha384_result}", font = custom_font)
    label_sha384.pack(pady=15)

    label_sha512 = tk.Label(window, text=f"SHA-512: {sha512_result}", font = custom_font)
    label_sha512.pack(pady=15)
    
    try:
        existing_df = pd.read_excel('Output.xlsx')
    except FileNotFoundError:
        existing_df = pd.DataFrame(columns=['String', 'SHA-1','SHA-224','SHA-256','SHA-384','SHA-512','MD5'])
    
    data = {'String' : [entry.get()] ,  'SHA-1': [sha1_hash] , 'SHA-224': [sha224_result] ,'SHA-256':[sha256_result] , 'SHA-384': [sha384_result], 'SHA-512': [sha512_result], 'MD5': [md5_hash] }
    df = pd.concat([existing_df, pd.DataFrame(data)], ignore_index=True)
    
    excel_file_path = 'Output.xlsx'
    df.to_excel(excel_file_path , index = False)
    print(f'Data has been saved to {excel_file_path}')

root = tk.Tk()
root.title("Hash Generator")

width = 350 
height = 500
root.geometry(f"{width}x{height}")

custom_font=("Monotype Corsiva",25)
label = tk.Label(root, text="Bikram's Hash Generator", font = custom_font)
label.pack()

custom_font=("Monotype Corsiva",20)
label1 = tk.Label(root, text = "Enter String : ", font = custom_font)
label1.pack(pady =20)

entry = tk.Entry(root,width=100)
entry.pack(pady = 10)

submit_button = tk.Button(root , text ="Generate Hash",command=generate , width = 25 , height = 5)
submit_button.pack(pady = 15)

root.mainloop()
