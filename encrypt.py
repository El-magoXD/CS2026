import glob
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# 1. GENERAR LA CLAVE DE 128 BITS (16 bytes = 128 bits)
clave_128 = get_random_bytes(16)
print("Clave generada (en bytes):", clave_128)
with open("./data/clave.psw", "wb") as archivo:
    archivo.write(clave_128)

# 2. ENCRIPTAR EL ARCHIVO
archivos = glob.glob("./media/input/*")

archivo = archivos[0]

sufijo = Path(archivo).suffix
with open("./data/extension.txt", "wb") as ext:
    ext.write(sufijo.encode())

with open(archivo, "rb") as archivo:
    datos_originales = archivo.read()

# El modo GCM requiere un "nonce" (número usado una sola vez)
cipher_encrypt = AES.new(clave_128, AES.MODE_GCM)
nonce = cipher_encrypt.nonce
datos_encriptados, etiqueta_mac = cipher_encrypt.encrypt_and_digest(datos_originales)

# Guardamos el nonce, la etiqueta de verificación (MAC) y los datos encriptados
with open("./data/file_encrypted.bin", "wb") as archivo:
    archivo.write(nonce)
    archivo.write(etiqueta_mac)
    archivo.write(datos_encriptados)

    