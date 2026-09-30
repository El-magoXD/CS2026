from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# 1. Función para crear el par de claves (Pública y Privada)
def generar_claves():
    """
    Crea un par de claves RSA de 2048 bits.
    Devuelve: (clave_privada, clave_publica)
    """
    privada = RSA.generate(2048)
    publica = privada.public_key()
    return privada, publica

# 2. Función para cifrar la clave AES usando la clave pública
def cifrar_con_publica(clave_aes, clave_publica):
    """
    Bloquea/cifra la clave AES usando la clave pública.
    """
    cifrador = PKCS1_OAEP.new(clave_publica)
    clave_cifrada = cifrador.encrypt(clave_aes)
    return clave_cifrada

# 3. Función para descifrar la clave AES usando la clave privada
def descifrar_con_privada(clave_cifrada, clave_privada):
    """
    Desbloquea/descifra la clave AES usando la clave privada.
    """
    descifrador = PKCS1_OAEP.new(clave_privada)
    clave_original = descifrador.decrypt(clave_cifrada)
    return clave_original


# =====================================================================
# BLOQUE DE PRUEBA: Solo se ejecuta si ejecutas este archivo directamente
# =====================================================================
if __name__ == "__main__":
    print("--- INICIANDO PRUEBA DE RSA ---")
    
    # Paso A: Generar las dos claves
    print("1. Generando claves RSA...")
    privada, publica = generar_claves()
    print("   -> Claves generadas correctamente.")
    
    # Paso B: Simular una clave secreta que queremos proteger
    # (Por ejemplo, una clave AES de 16 bytes cualquiera)
    clave_secreta_simulada = b"EstaClaveEsDe16B"
    print(f"2. Clave secreta original: {clave_secreta_simulada}")
    
    # Paso C: Cifrar con la clave pública
    clave_protegida = cifrar_con_publica(clave_secreta_simulada, publica)
    print(f"3. Clave cifrada (parece basura ilegible): {clave_protegida[:30]}...")
    
    # Paso D: Descifrar con la clave privada
    clave_recuperada = descifrar_con_privada(clave_protegida, privada)
    print(f"4. Clave recuperada con la clave privada: {clave_recuperada}")
    
    # Comprobación final
    if clave_secreta_simulada == clave_recuperada:
        print("\n ¡TODO FUNCIONA PERFECTAMENTE!")
    else:
        print("\n Algo ha fallado.")