# CS2026 - Cifrado de archivos con AES + RSA

Aplicación de escritorio y herramientas de consola para cifrar y descifrar archivos. Cada archivo se cifra con una clave AES aleatoria; esta clave se protege con RSA, y la clave privada RSA se protege con una contraseña.

## Funcionamiento

### Componentes del proyecto

- `crypto/aes.py`: genera claves AES y cifra o descifra archivos con AES-GCM.
- `crypto/rsa.py`: genera un par RSA de 2048 bits y cifra o descifra claves AES con RSA-OAEP.
- `crypto/passwords.py`: deriva una clave AES-128 de la contraseña con PBKDF2-HMAC-SHA256 y un salt aleatorio. Usa esa clave para proteger la clave privada RSA con AES-GCM.
- `encrypt.py` y `decrypt.py`: realizan el proceso de cifrado y descifrado desde la línea de comandos.
- `main.py`: interfaz gráfica de Tkinter para elegir los archivos de entrada y salida.

### Qué ocurre al cifrar

1. Se genera una clave AES-128 aleatoria nueva para el archivo.
2. AES-GCM cifra el contenido. El archivo resultante contiene el nonce, la etiqueta de autenticación y el contenido cifrado.
3. La clave AES se cifra con la clave pública RSA.
4. Si aún no existe un par RSA, se genera. La clave pública se guarda como `rsa_public.pem`; la clave privada se guarda protegida con contraseña como `rsa_private.enc`.
5. Si ya existe un par RSA, se comprueba que la contraseña pueda desbloquear la clave privada y que ambas claves pertenezcan al mismo par antes de cifrar.

El resultado por cada archivo consta de dos archivos asociados:

```text
archivo.enc       Contenido cifrado con AES-GCM
archivo.key.enc   Clave AES cifrada con RSA-OAEP
```

### Qué ocurre al descifrar

1. La contraseña y el salt guardado en `rsa_private.enc` permiten derivar la clave AES que desbloquea la clave privada RSA.
2. La clave privada RSA recupera la clave AES del archivo `.key.enc`.
3. AES-GCM descifra el archivo y verifica su integridad mediante la etiqueta de autenticación.
4. Si la contraseña es incorrecta, las claves no corresponden o el archivo fue dañado, la operación falla.

El nombre y la extensión del archivo original no se guardan dentro del archivo cifrado. Al descifrar, hay que seleccionar o escribir el nombre y la extensión deseados para el archivo de salida.

## Requisitos e instalación

Se necesita Python 3.9 o posterior. Tkinter debe estar disponible en la instalación de Python; en algunas distribuciones de Linux se instala por separado como paquete del sistema.

Crea un entorno virtual desde la carpeta del proyecto:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

En Windows (PowerShell):

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

Con el entorno virtual activado, instala la dependencia:

```bash
python -m pip install -r requirements.txt
```

Al terminar, puedes salir del entorno virtual con `deactivate`.

## Uso de la interfaz gráfica

Con el entorno virtual activado, inicia la aplicación:

```bash
python main.py
```

La ventana tiene dos pestañas:

- **Cifrar:** selecciona el archivo original, dónde guardar el `.enc` y la contraseña que protegerá la clave privada RSA. El archivo `.key.enc` complementario se guarda junto al archivo cifrado.
- **Descifrar:** selecciona el `.enc`, su `.key.enc`, la clave privada RSA protegida, la contraseña correspondiente y la ruta de salida. Si el `.key.enc` complementario está junto al `.enc`, la aplicación lo propone automáticamente.

La interfaz pide confirmación antes de reemplazar archivos existentes y muestra el resultado o el error de la operación.

## Uso desde la línea de comandos

### Cifrar un archivo

```bash
python encrypt.py /ruta/al/archivo.txt --password "mi-contraseña"
```

Por defecto, los archivos cifrados y el par RSA se guardan en `data/`. Para elegir otra carpeta:

```bash
python encrypt.py /ruta/al/archivo.txt \
  --password "mi-contraseña" \
  --output-dir /ruta/de/salida
```

El programa crea un `.enc` y un `.key.enc` basados en el nombre del archivo original. Si el par RSA ya existe, usa la contraseña con la que se protegió la clave privada.

### Descifrar un archivo

```bash
python decrypt.py \
  --encrypted-file data/archivo.enc \
  --key-file data/archivo.key.enc \
  --password "mi-contraseña" \
  --output /ruta/de/salida/archivo.txt
```

Por defecto, el programa busca `rsa_private.enc` junto al archivo cifrado y luego en `data/`. Si está en otra ubicación, indícala explícitamente:

```bash
python decrypt.py \
  --encrypted-file /ruta/archivo.enc \
  --key-file /ruta/archivo.key.enc \
  --private-key /ruta/rsa_private.enc \
  --password "mi-contraseña" \
  --output /ruta/archivo.txt
```

## Claves y seguridad

- La contraseña no se guarda. Se usa PBKDF2-HMAC-SHA256 con un salt aleatorio para derivar una clave AES-128 que protege la clave privada RSA.
- El salt no es secreto y se almacena junto a los datos cifrados de la clave privada. La contraseña sí debe mantenerse en secreto y ser robusta.
- Guarda de forma segura el `.enc`, su `.key.enc`, `rsa_private.enc` y la contraseña. Los cuatro son necesarios para recuperar el archivo.
- Si pierdes la clave privada o la contraseña, no podrás descifrar los archivos protegidos por ese par RSA. La clave AES cifrada de cada archivo debe corresponder a esa misma clave privada.
- El `.gitignore` excluye `data/`, `media/`, claves y archivos cifrados para no publicar datos locales accidentalmente. La clave pública no es secreta, pero en este proyecto también se guarda en `data/` y queda excluida.
- `.gitignore` no elimina archivos que ya estén siendo seguidos por Git ni borra archivos publicados anteriormente. Antes de subir cambios, revisa el estado del repositorio y asegúrate de que no haya claves privadas ni datos personales.
