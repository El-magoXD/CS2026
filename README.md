# CS2026 - Cifrado de archivos con AES + RSA

Aplicación de escritorio y herramientas de consola para cifrar y descifrar archivos. Cada archivo se cifra con una clave AES aleatoria; esta clave se protege con RSA, y la clave privada RSA se protege con una contraseña. La interfaz gráfica guarda los archivos cifrados y las claves en una base de datos SQLite local.

## Funcionamiento

### Componentes del proyecto

- `crypto/aes.py`: genera claves AES y cifra o descifra archivos con AES-GCM.
- `crypto/rsa.py`: genera un par RSA de 2048 bits y cifra o descifra claves AES con RSA-OAEP.
- `crypto/passwords.py`: deriva una clave AES-128 de la contraseña con PBKDF2-HMAC-SHA256 y un salt aleatorio. Usa esa clave para proteger la clave privada RSA con AES-GCM.
- `database/database.py`: crea y consulta las tablas SQLite para los archivos cifrados y el par RSA protegido.
- `services/file_service.py`: conecta las operaciones criptográficas con el almacenamiento SQLite.
- `encrypt.py` y `decrypt.py`: realizan el proceso de cifrado y descifrado desde la línea de comandos.
- `main.py`: interfaz gráfica de Tkinter para elegir los archivos de entrada y salida.

### Qué ocurre al cifrar

1. Se genera una clave AES-128 aleatoria nueva para el archivo.
2. AES-GCM cifra el contenido. El archivo resultante contiene el nonce, la etiqueta de autenticación y el contenido cifrado.
3. La clave AES se cifra con la clave pública RSA.
4. Si aún no hay un par RSA en la base de datos, se genera. La clave pública se guarda como BLOB y la clave privada como BLOB cifrado con una clave AES derivada de la contraseña.
5. Si ya existe un par RSA, se comprueba que la contraseña pueda desbloquear la clave privada y que ambas claves pertenezcan al mismo par antes de cifrar.

La interfaz guarda en SQLite una entrada por archivo con el contenido cifrado, la clave AES cifrada con RSA, el nombre original y el tamaño. No guarda el contenido original ni la clave AES en claro.

### Qué ocurre al descifrar

1. La contraseña y el salt guardado con la clave privada protegida permiten derivar la clave AES que desbloquea la clave privada RSA.
2. La clave privada RSA recupera la clave AES guardada como BLOB en SQLite o en el archivo `.key.enc`.
3. AES-GCM descifra el archivo y verifica su integridad mediante la etiqueta de autenticación.
4. Si la contraseña es incorrecta, las claves no corresponden o el archivo fue dañado, la operación falla.

El nombre y la extensión del archivo original no se guardan dentro del contenido cifrado. En la biblioteca SQLite, el nombre original sí se conserva como metadato y se propone al elegir la ruta de salida.

## Almacenamiento SQLite

La aplicación gráfica crea automáticamente la base de datos local en:

```text
data/secure_storage.sqlite3
```

Contiene las tablas:

- `keypairs`: almacena la clave pública RSA y la clave privada RSA cifrada con AES-GCM. La contraseña no se guarda.
- `encrypted_files`: almacena el contenido AES-GCM cifrado como BLOB, la clave AES cifrada con RSA como BLOB, el nombre original, el tamaño y la fecha de guardado.

La base de datos guarda cifrados tanto el contenido del archivo como los materiales de clave que permiten recuperarlo. El nombre y tamaño del archivo son metadatos y no están cifrados. SQLite no cifra automáticamente el fichero de base de datos completo; protege la base de datos local y mantén una copia de seguridad segura.

En la primera ejecución, si encuentra el par RSA existente en `data/rsa_public.pem` y `data/rsa_private.enc`, lo importa a SQLite tras comprobar la contraseña. Los archivos originales de las claves no se borran. Si no encuentra ninguno, crea un par nuevo dentro de la base de datos. Si solo encuentra uno de los dos archivos, informa del par incompleto y no crea otro que pudiera dejar inaccesibles datos cifrados previamente.

La versión actual usa un único par RSA local y no implementa todavía cuentas de usuario ni compartición entre usuarios. El esquema puede ampliarse más adelante para relacionar archivos con usuarios y añadir una tabla de comparticiones.

La aplicación cifra el archivo completo en memoria antes de guardarlo como BLOB. Es práctico para archivos moderados, pero tanto el uso de memoria como el tamaño de la base de datos crecen con los archivos; para archivos muy grandes convendría guardar el contenido cifrado en disco y usar SQLite solo para sus metadatos y claves.

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

La ventana tiene tres pestañas:

- **Cifrar:** selecciona el archivo original y escribe la contraseña que protegerá la clave privada RSA. El contenido cifrado y las claves asociadas se guardan en SQLite.
- **Biblioteca SQLite:** consulta los archivos guardados y descifra una selección eligiendo la contraseña y la ruta de salida.
- **Descifrar:** descifra archivos `.enc` y `.key.enc` que ya estén guardados como ficheros externos, por ejemplo los generados por la línea de comandos.

La interfaz pide confirmación antes de reemplazar archivos existentes y muestra el resultado o el error de la operación.

Los archivos cifrados que ya existían como `.enc` y `.key.enc` no se importan automáticamente a la biblioteca; se pueden descifrar desde la pestaña **Descifrar**.

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

El programa crea un `.enc` y un `.key.enc` basados en el nombre del archivo original en la carpeta de salida. Este flujo de consola sigue guardando los datos como ficheros; la interfaz gráfica usa la base de datos SQLite. Si el par RSA ya existe, usa la contraseña con la que se protegió la clave privada.

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
- Para las entradas creadas desde la interfaz, conserva `data/secure_storage.sqlite3` y la contraseña. La base de datos contiene el archivo cifrado, la clave AES cifrada y la clave privada RSA protegida.
- Si pierdes la clave privada o la contraseña, no podrás descifrar los archivos protegidos por ese par RSA. La clave AES cifrada de cada archivo debe corresponder a esa misma clave privada.
- El `.gitignore` excluye `data/`, `media/`, claves y archivos cifrados para no publicar datos locales accidentalmente. La clave pública no es secreta, pero en este proyecto también se guarda en `data/` y queda excluida.
- `.gitignore` no elimina archivos que ya estén siendo seguidos por Git ni borra archivos publicados anteriormente. Antes de subir cambios, revisa el estado del repositorio y asegúrate de que no haya claves privadas ni datos personales.
