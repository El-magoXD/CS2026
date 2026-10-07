# CS2026 - Cifrado de archivos con AES + RSA

Este proyecto implementa un flujo básico de cifrado de archivos:

- Genera una clave AES-128 aleatoria por archivo.
- Cifra el contenido del archivo con AES-GCM.
- Cifra la clave AES con la clave pública RSA.
- Protege la clave privada RSA con una contraseña mediante KDF + AES-GCM.

## Uso

Instala la dependencia de criptografía antes de ejecutar la aplicación:

```bash
python -m pip install -r requirements.txt
```

### Interfaz gráfica

Ejecuta la aplicación y selecciona la pestaña **Cifrar** o **Descifrar**:

```bash
python main.py
```

En ambas pestañas puedes elegir los archivos de entrada y la ruta de salida. Para descifrar, selecciona también el archivo `.key.enc` correspondiente, la clave privada RSA protegida y la contraseña con la que se guardó esa clave.

### Línea de comandos

1. Encriptar un archivo:

   python encrypt.py /ruta/al/archivo.txt --password "mi-contraseña"

   Esto crea:
   - data/archivo.enc
   - data/archivo.key.enc
   - data/rsa_public.pem
   - data/rsa_private.enc

2. Desencriptar un archivo:

   python decrypt.py \
     --encrypted-file data/archivo.enc \
     --key-file data/archivo.key.enc \
     --password "mi-contraseña" \
     --output /ruta/de/salida/archivo.txt

La clave privada RSA se almacena cifrada con AES-128 derivando una clave desde la contraseña mediante PBKDF2-HMAC-SHA256 y un salt aleatorio.

Al reutilizar un par RSA existente, usa la misma contraseña con la que se protegió su clave privada. Si se pierde esa contraseña o el archivo `rsa_private.enc`, los archivos cifrados con ese par no podrán recuperarse. El programa comprueba el par y la contraseña antes de cifrar para evitar crear archivos que luego no se puedan descifrar.
