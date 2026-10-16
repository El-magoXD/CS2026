# CS2026 - Cifrado de archivos con AES + RSA

Aplicación de escritorio y herramientas de consola para cifrar y descifrar archivos. Cada archivo se cifra con una clave AES aleatoria; esta clave se protege con la clave pública RSA del usuario, y la clave privada RSA se protege con la contraseña de ese usuario. La interfaz gráfica gestiona cuentas locales y guarda los archivos cifrados y las claves en una base de datos SQLite.

## Funcionamiento

### Componentes del proyecto

- `crypto/aes.py`: genera claves AES y cifra o descifra archivos con AES-GCM.
- `crypto/rsa.py`: genera un par RSA de 2048 bits y cifra o descifra claves AES con RSA-OAEP.
- `crypto/passwords.py`: deriva una clave AES-128 de la contraseña con PBKDF2-HMAC-SHA256 y un salt aleatorio. Usa esa clave para proteger la clave privada RSA con AES-GCM.
- `database/database.py`: crea y consulta las tablas SQLite de usuarios y archivos cifrados, y migra la base de datos antigua de un solo par RSA.
- `services/file_service.py`: conecta las operaciones criptográficas con el almacenamiento SQLite.
- `encrypt.py` y `decrypt.py`: realizan el proceso de cifrado y descifrado desde la línea de comandos.
- `main.py`: interfaz gráfica de Tkinter para iniciar sesión, crear cuentas y cifrar/descifrar archivos.

### Sesión y contraseña

Al iniciar la aplicación se selecciona una cuenta y se introduce su contraseña. La contraseña se usa para derivar una clave AES-128 que desbloquea la clave privada RSA cifrada del usuario. Si la autenticación tiene éxito, la clave privada se conserva en memoria durante esa sesión; no se vuelve a pedir la contraseña al cifrar o descifrar archivos desde la interfaz. Al cerrar la aplicación, se elimina la referencia de sesión a esa clave.

Al crear una cuenta se genera un par RSA propio. La contraseña no se guarda en la base de datos: solo se almacena la clave privada RSA protegida con AES-GCM y la clave pública. La misma contraseña permite desbloquear esa clave privada en futuros inicios de sesión.

### Qué ocurre al cifrar

1. Se genera una clave AES-128 aleatoria nueva para el archivo.
2. AES-GCM cifra el contenido. El archivo resultante contiene el nonce, la etiqueta de autenticación y el contenido cifrado.
3. La clave AES se cifra con la clave pública RSA de la cuenta activa.

La interfaz guarda en SQLite una entrada por archivo con el identificador del propietario, el contenido cifrado, la clave AES cifrada con RSA, el nombre original y el tamaño. No guarda el contenido original ni la clave AES en claro. Cada cuenta solo lista y puede descifrar sus propios registros.

### Qué ocurre al descifrar

1. Al iniciar sesión, la contraseña y el salt guardado con la clave privada protegida permiten derivar la clave AES que desbloquea la clave privada RSA del usuario.
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

- `users`: almacena el nombre de cuenta, la clave pública RSA y la clave privada RSA cifrada con AES-GCM. La contraseña no se guarda.
- `encrypted_files`: almacena el identificador del usuario propietario, el contenido AES-GCM cifrado como BLOB, la clave AES cifrada con RSA como BLOB, el nombre original, el tamaño y la fecha de guardado.

La base de datos guarda cifrados tanto el contenido del archivo como los materiales de clave que permiten recuperarlo. El nombre y tamaño del archivo son metadatos y no están cifrados. SQLite no cifra automáticamente el fichero de base de datos completo; protege la base de datos local y mantén una copia de seguridad segura.

Al abrir una base de datos creada por la versión anterior, la aplicación migra el único par RSA y los archivos cifrados existentes a una cuenta llamada `usuario`, conservando el contenido cifrado. Inicia sesión con la contraseña que protegía la clave privada anterior. La migración deja de usar la tabla antigua `keypairs`; los archivos externos `.enc` y `.key.enc` continúan disponibles en la pestaña de descifrado externo.

La versión actual separa los archivos por cuenta y genera un par RSA por usuario. La compartición segura entre usuarios todavía no está implementada.

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

Al iniciarse, la aplicación muestra una pantalla para elegir una cuenta e introducir su contraseña. Si aún no existe una cuenta, se puede crear una; al crearla, se genera y protege su par RSA.

La ventana principal tiene tres pestañas:

- **Cifrar:** selecciona el archivo original. Se cifra con una clave nueva y se protege con la clave pública de la cuenta activa; no vuelve a pedir la contraseña.
- **Biblioteca SQLite:** muestra los archivos de la cuenta activa y permite descifrar una selección eligiendo la ruta de salida. Usa la clave privada desbloqueada durante el inicio de sesión.
- **Descifrar:** descifra archivos externos `.enc` y `.key.enc` con la clave privada de la cuenta activa, sin pedir de nuevo la contraseña. La clave `.key.enc` debe haberse cifrado con la clave pública de esa cuenta.

La interfaz pide confirmación antes de reemplazar archivos existentes y muestra el resultado o el error de la operación.

Los archivos cifrados que ya existían como `.enc` y `.key.enc` no se importan automáticamente a la biblioteca. Se pueden abrir desde la pestaña **Descifrar** si su clave AES se cifró para la clave pública de la cuenta activa.

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

El programa crea un `.enc` y un `.key.enc` basados en el nombre del archivo original en la carpeta de salida. Este flujo de consola sigue guardando los datos como ficheros y es independiente del inicio de sesión de la interfaz; recibe la contraseña con `--password` en cada ejecución y usa el par RSA de sus archivos de clave.

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

- La contraseña no se guarda. Se usa PBKDF2-HMAC-SHA256 con un salt aleatorio para derivar una clave AES-128 que protege la clave privada RSA. En la interfaz se introduce al iniciar sesión; el objeto de clave privada desbloqueado se mantiene en memoria mientras la sesión está activa.
- El salt no es secreto y se almacena junto a los datos cifrados de la clave privada. La contraseña sí debe mantenerse en secreto y ser robusta.
- Para archivos creados con la línea de comandos, conserva el `.enc`, su `.key.enc`, `rsa_private.enc` y la contraseña con la que se protegió esa clave. Para los archivos de la interfaz, conserva la base SQLite y la contraseña de la cuenta.
- Para las entradas creadas desde la interfaz, conserva `data/secure_storage.sqlite3` y la contraseña de la cuenta. La base de datos contiene el archivo cifrado, la clave AES cifrada y la clave privada RSA protegida de cada usuario.
- Si pierdes la clave privada o la contraseña, no podrás descifrar los archivos protegidos por ese par RSA. La clave AES cifrada de cada archivo debe corresponder a esa misma clave privada.
- El `.gitignore` excluye `data/`, `media/`, claves y archivos cifrados para no publicar datos locales accidentalmente. La clave pública no es secreta, pero en este proyecto también se guarda en `data/` y queda excluida.
- `.gitignore` no elimina archivos que ya estén siendo seguidos por Git ni borra archivos publicados anteriormente. Antes de subir cambios, revisa el estado del repositorio y asegúrate de que no haya claves privadas ni datos personales.

## Para convertir ejecutable

Para generar un **`.exe` de Windows**, usa **PyInstaller desde Windows**, no desde WSL. La versión que genera PyInstaller depende del sistema donde se ejecuta: desde WSL producirías un ejecutable Linux, no un `.exe` de Windows.

La capa de base de datos ya usa `data/secure_storage.sqlite3` durante el desarrollo y `%LOCALAPPDATA%\CS2026\secure_storage.sqlite3` cuando se ejecuta empaquetada. Crea la carpeta de destino si todavía no existe.

### Crear el ejecutable

1. Copia o abre el proyecto en una carpeta normal de Windows —por ejemplo, `C:\Users\TuUsuario\CS2026`—. No incluyas `.venv`, `data` ni `media`: contienen dependencias locales o datos personales.

2. En PowerShell, dentro de la carpeta del proyecto, prepara el entorno:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pyinstaller
```

3. Genera primero la versión recomendada, en formato de carpeta:

```powershell
python -m PyInstaller --noconfirm --clean --onedir --windowed --name CS2026 main.py
```

El ejecutable queda en:

```text
dist\CS2026\CS2026.exe
```

Prueba a abrirlo directamente desde esa carpeta. En formato `--onedir`, distribuye **toda la carpeta `dist\CS2026`**, no solo el `.exe`.

Cuando esa versión funcione, puedes probar un único archivo:

```powershell
python -m PyInstaller --noconfirm --clean --onefile --windowed --name CS2026 main.py
```

Ese ejecutable queda en `dist\CS2026.exe`, pero tarda más en arrancar y extrae componentes a una carpeta temporal, por eso recomiendo empezar con `--onedir`.

SQLite ya viene incluido con Python y Tkinter normalmente se detecta automáticamente. Si al abrir la aplicación empaquetada aparece un error indicando que no encuentra `Crypto`, prueba a generar el paquete con `--collect-all Crypto`.

La base de datos y las claves **no deben incluirse dentro del ejecutable ni subirse al repositorio**. El programa creará sus propios datos al ejecutarse. Si quieres conservar tu base de datos actual, haz una copia de seguridad privada antes de cambiar la ruta; no la distribuyas con el `.exe`.
