# RSA.py
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA3_256
from Crypto.PublicKey import RSA


# -------------------------------------------------------------
# 1. PAR DE CLAVES RSA
# -------------------------------------------------------------
def generar_claves():
    """Genera el par de claves RSA (2048 bits)."""
    privada = RSA.generate(2048)
    publica = privada.public_key()
    return privada, publica

# -------------------------------------------------------------
# 2. CIFRADO / DESCIFRADO DE LA CLAVE AES DEL ARCHIVO
# -------------------------------------------------------------
def cifrar_con_publica(clave_aes, clave_publica):
    """Cifra la clave AES con la clave pública RSA: E_Ku(kf)"""
    cifrador = PKCS1_OAEP.new(clave_publica)
    return cifrador.encrypt(clave_aes)

def descifrar_con_privada(clave_cifrada, clave_privada):
    """Descifra la clave AES con la clave privada RSA: D_ku(E_Ku(kf))"""
    descifrador = PKCS1_OAEP.new(clave_privada)
    return descifrador.decrypt(clave_cifrada)

# -------------------------------------------------------------
# 3. DERIVACIÓN DE PASSWORD -> CLAVE AES128 (con SHA3-256)
# -------------------------------------------------------------
def derivar_clave_password(password: str) -> bytes:
    """Convierte el texto de la contraseña en 16 bytes (AES-128) usando SHA-3."""
    h = SHA3_256.new()
    h.update(password.encode("utf-8"))
    return h.digest()[:16]

# -------------------------------------------------------------
# 4. GUARDAR / RECUPERAR CLAVE PRIVADA PROTEGIDA CON AES-128
# -------------------------------------------------------------
def proteger_clave_privada(clave_privada, password: str):
    """Cifra la clave privada RSA con AES-128 usando la contraseña."""
    # Convertimos la clave privada a bytes binarios
    priv_bytes = clave_privada.export_key(format="DER")
    
    # Obtenemos la clave AES128 del password
    k_pu = derivar_clave_password(password)
    
    # Ciframos con AES-GCM (igual que en encrypt.py)
    cipher = AES.new(k_pu, AES.MODE_GCM)
    cifrado, tag = cipher.encrypt_and_digest(priv_bytes)
    
    # Devolvemos el nonce, el tag de autenticación y los datos cifrados
    return cipher.nonce, tag, cifrado

def recuperar_clave_privada(nonce: bytes, tag: bytes, cifrado: bytes, password: str):
    """Descifra la clave privada RSA usando la contraseña."""
    k_pu = derivar_clave_password(password)
    cipher = AES.new(k_pu, AES.MODE_GCM, nonce=nonce)
    
    # Si la contraseña es incorrecta, salta ValueError
    priv_bytes = cipher.decrypt_and_verify(cifrado, tag)
    return RSA.import_key(priv_bytes)


# =============================================================
# PRUEBA INTEGRAL
# =============================================================
""" if __name__ == "__main__":
    print("--- INICIANDO PRUEBA COMPLETA DE RSA + PROTECCIÓN ---")
    
    # 1. Generar par de claves
    privada, publica = generar_claves()
    print("1. Claves RSA creadas.")
    
    # 2. Cifrar una clave AES simulada
    clave_aes_simulada = b"ClaveDeFichero16"
    clave_aes_cifrada = cifrar_con_publica(clave_aes_simulada, publica)
    print(f"2. Clave AES del archivo cifrada con éxito.")
    
    # 3. Proteger la clave privada con una contraseña
    password_usuario = "MiPasswordSecreto123"
    nonce, tag, privada_cifrada = proteger_clave_privada(privada, password_usuario)
    print("3. Clave privada RSA cifrada con AES-128 a partir de la contraseña.")
    
    # Simulamos que cerramos la app y borramos la clave privada de memoria
    del privada
    
    # 4. Recuperar la clave privada usando la contraseña correcta
    privada_recuperada = recuperar_clave_privada(nonce, tag, privada_cifrada, password_usuario)
    print("4. Clave privada descifrada y recuperada en memoria con la contraseña.")
    
    # 5. Descifrar la clave AES con la clave privada recuperada
    clave_aes_recuperada = descifrar_con_privada(clave_aes_cifrada, privada_recuperada)
    print(f"5. Clave AES descifrada: {clave_aes_recuperada}")
    
    assert clave_aes_simulada == clave_aes_recuperada
    print("\n¡FLUJO COMPLETO DE RSA SUPERADO SIN ERRORES!") """