from Crypto.Cipher import AES

# Cargar la clave desde el archivo
with open("./data/clave.psw", "rb") as archivo:
    clave_128 = archivo.read()

with open("./data/extension.txt", "rb") as archivo:
    sufijo = archivo.read().decode()

# 3. DESENCRIPTAR EL ARCHIVO
with open("./data/file_encrypted.bin", "rb") as archivo:
    # Leemos en el mismo orden: nonce (16 bytes), MAC (16 bytes) y el resto de datos
    nonce_leido = archivo.read(16)
    etiqueta_mac_leida = archivo.read(16)
    datos_para_desencriptar = archivo.read()

# Desencriptamos y verificamos la integridad del archivo
cipher_decrypt = AES.new(clave_128, AES.MODE_GCM, nonce=nonce_leido)

try:
    datos_recuperados = cipher_decrypt.decrypt_and_verify(datos_para_desencriptar, etiqueta_mac_leida)
    
    with open("./media/output/output" + sufijo, "wb") as archivo:
        archivo.write(datos_recuperados)
    print("Archivo desencriptado con éxito.")
    
except ValueError:
    print("Error: La clave es incorrecta o el archivo ha sido modificado.")