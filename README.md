# CS2026 - Servicio seguro de archivos AES + RSA

Aplicación de escritorio y API para registrar usuarios, cifrar archivos multimedia y compartirlos de forma segura. El cliente cifra cada archivo con una clave AES-128 aleatoria, envuelve esa clave con RSA-OAEP y solo envía al servidor contenido cifrado. El servidor expone una API HTTPS y puede guardar los registros en MariaDB/MySQL; para desarrollo local usa SQLite.

## Funcionamiento

### Componentes del proyecto

- `crypto/aes.py`: genera claves AES y cifra o descifra archivos con AES-GCM.
- `crypto/rsa.py`: genera un par RSA de 2048 bits y cifra o descifra claves AES con RSA-OAEP.
- `crypto/passwords.py`: deriva una clave AES-128 de la contraseña con PBKDF2-HMAC-SHA256 y un salt aleatorio. Usa esa clave para proteger la clave privada RSA con AES-GCM.
- `api/main.py` y `api/models.py`: API FastAPI, autenticación, permisos, archivos y comparticiones; SQLAlchemy permite usar SQLite en local o MariaDB/MySQL en el servidor.
- `api/client.py`: cliente HTTPS usado por la interfaz para hablar con la API y cifrar/descifrar localmente.
- `database/database.py` y `services/file_service.py`: almacenamiento SQLite y servicio de la versión local anterior; la interfaz actual usa la API remota.
- `encrypt.py` y `decrypt.py`: realizan el proceso de cifrado y descifrado desde la línea de comandos.
- `main.py`: interfaz gráfica de Tkinter para iniciar sesión, crear cuentas y cifrar/descifrar archivos.

### Sesión y contraseña

Al iniciar la aplicación se introduce el nombre de usuario y la contraseña. El servidor verifica una derivación scrypt de la contraseña y entrega la clave privada RSA todavía cifrada; el cliente la desbloquea localmente con PBKDF2-HMAC-SHA256 y AES-GCM. La clave privada ya desbloqueada se conserva solo en memoria durante la sesión. La contraseña no se almacena en claro, pero se transmite a la API durante alta e inicio de sesión, por lo que un servidor remoto debe usar HTTPS.

Al crear una cuenta, el cliente genera el par RSA y protege la clave privada antes de enviarla. El servidor almacena la clave pública, la clave privada protegida y una verificación scrypt de la contraseña; no recibe la clave privada en claro.

### Qué ocurre al cifrar

1. Se genera una clave AES-128 aleatoria nueva para el archivo.
2. AES-GCM cifra el contenido. El archivo resultante contiene el nonce, la etiqueta de autenticación y el contenido cifrado.
3. La clave AES se cifra con la clave pública RSA de la cuenta activa.

La interfaz envía al servidor el contenido AES-GCM cifrado y la clave AES cifrada con la clave pública del propietario. El servidor guarda esos datos y los metadatos; no recibe el archivo ni la clave AES en claro. Cada usuario autenticado solo puede listar y descifrar sus registros.

### Qué ocurre al descifrar

1. Al iniciar sesión, la contraseña y el salt guardado con la clave privada protegida permiten derivar la clave AES que desbloquea la clave privada RSA del usuario.
2. La clave privada RSA recupera la clave AES protegida en el servidor o en el archivo `.key.enc`.
3. AES-GCM descifra el archivo y verifica su integridad mediante la etiqueta de autenticación.
4. Si la contraseña es incorrecta, las claves no corresponden o el archivo fue dañado, la operación falla.

El nombre, el tamaño y la fecha se conservan como metadatos legibles en el servidor; el nombre original se propone al elegir la ruta de salida.

### Compartir un archivo

1. El propietario elige uno de sus archivos e indica el nombre del destinatario.
2. El cliente recupera la clave AES localmente y la cifra con la clave pública RSA del destinatario.
3. La API guarda el nuevo envoltorio RSA en una relación de compartición, sin duplicar el archivo cifrado.
4. El destinatario ve el archivo en **Compartidos conmigo** y lo descifra localmente con su propia clave privada.

El propietario puede retirar el permiso desde **Mis archivos**, indicando el usuario destinatario. La revocación impide futuras descargas, pero no puede borrar copias que el destinatario ya haya descargado o descifrado. La clave pública del destinatario se obtiene del mismo servidor; esta versión no incluye una autoridad independiente para verificarla, así que para un modelo que contemple un servidor malicioso hay que comparar su huella por un canal externo confiable.

## API y bases de datos

La aplicación de escritorio habla con FastAPI, no se conecta directamente a MariaDB. Las credenciales de MariaDB deben existir únicamente en el servidor. Las sesiones usan tokens aleatorios de duración limitada, y cada endpoint verifica propietario o destinatario.

Por defecto, la API local crea `data/server.sqlite3`. Para conectarla a MariaDB/MySQL se configura `CS2026_DATABASE_URL` **en el servidor**, por ejemplo:

```text
mysql+pymysql://cs2026_user:CAMBIAR_PASSWORD@localhost:3306/cs2026?charset=utf8mb4
```

La API crea las tablas al arrancar. La cuenta MariaDB debe tener permisos solo sobre la base de datos de la aplicación. Mantén el puerto MariaDB (normalmente 3306) en la interfaz local del servidor; no lo expongas a Internet. Para archivos grandes, el contenido cifrado se almacena como `LONGBLOB` en MariaDB.

Los archivos se leen y cifran íntegramente en memoria, por lo que esta versión está orientada a archivos de tamaño moderado. Los registros de la SQLite local de la versión anterior no se migran automáticamente al servidor.

### Ejecutar localmente

En un terminal, instala dependencias y arranca la API con su SQLite local de desarrollo:

```bash
python -m pip install -r requirements.txt
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

En otro terminal, inicia el cliente:

```bash
python main.py
```

El cliente usa por defecto `http://127.0.0.1:8000`. Los usuarios, archivos y comparticiones locales se guardan en `data/server.sqlite3`; la API no necesita una base MySQL para probar el flujo.

### Desplegar la API en `magocloud.ddns.net`

1. Instala Python y MariaDB en el servidor Linux. Crea una base `cs2026` y un usuario dedicado; limita MariaDB a conexiones locales. Por ejemplo, desde la consola MariaDB:

   ```sql
   CREATE DATABASE cs2026 CHARACTER SET utf8mb4;
   CREATE USER 'cs2026_user'@'localhost' IDENTIFIED BY 'UNA_PASSWORD_LARGA';
   GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, INDEX, ALTER
       ON cs2026.* TO 'cs2026_user'@'localhost';
   FLUSH PRIVILEGES;
   ```

   Usa una contraseña real generada para el servidor, no el texto de ejemplo, y no la guardes en el repositorio.
2. En la terminal del servidor, configura la URL privada de la base y arranca la API solo en loopback:

   ```bash
   export CS2026_DATABASE_URL='mysql+pymysql://cs2026_user:CAMBIAR_PASSWORD@localhost:3306/cs2026?charset=utf8mb4'
   uvicorn api.main:app --host 127.0.0.1 --port 8000
   ```

3. Publica el puerto local 8000 mediante un proxy inverso (por ejemplo Nginx) con un certificado TLS válido para `magocloud.ddns.net`. El bloque HTTPS del proxy debe pasar las peticiones a `http://127.0.0.1:8000`; no publiques directamente el puerto 8000 ni el 3306.
4. En cada cliente, configura `CS2026_API_URL=https://magocloud.ddns.net` antes de iniciar la app. No pongas la URL, usuario ni contraseña de MariaDB en el cliente.

Comprueba el servicio con `curl https://magocloud.ddns.net/health`; debe responder `{"status":"ok"}`. Configura Uvicorn para que se inicie como servicio del sistema y guarda la URL de MariaDB en un archivo de entorno del servidor con permisos restringidos.

La aplicación no se ha desplegado automáticamente en ese servidor: hacen falta acceso al host, configurar MariaDB, DNS/TLS y el proxy inverso. No uses HTTP para una API remota: el cliente lo rechaza.

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

Con el entorno virtual activado, instala las dependencias:

```bash
python -m pip install -r requirements.txt
```

Al terminar, puedes salir del entorno virtual con `deactivate`.

## Uso de la interfaz gráfica

Con el entorno virtual activado, inicia la aplicación:

```bash
python main.py
```

En Windows PowerShell, configura primero la URL de la API local o remota:

```powershell
$env:CS2026_API_URL = "https://magocloud.ddns.net"
python main.py
```

En Linux/macOS:

```bash
CS2026_API_URL=https://magocloud.ddns.net python main.py
```

Al iniciarse, la aplicación pide el nombre de usuario y la contraseña. Si aún no existe una cuenta, se puede registrar una; el cliente genera el par RSA y protege su clave privada antes de enviarla al servidor.

La ventana principal ofrece estas pestañas:

- **Cifrar:** selecciona el archivo original. Se cifra con una clave nueva y se protege con la clave pública de la cuenta activa; no vuelve a pedir la contraseña.
- **Mis archivos:** lista los archivos del usuario en el servidor, permite descifrarlos y compartirlos con otro usuario.
- **Compartidos conmigo:** lista los archivos recibidos y permite descifrarlos con la clave privada del destinatario.
- **Descifrar:** descifra archivos externos `.enc` y `.key.enc` con la clave privada de la cuenta activa, sin pedir de nuevo la contraseña. La clave `.key.enc` debe haberse cifrado con la clave pública de esa cuenta.

La interfaz pide confirmación antes de reemplazar archivos existentes y muestra el resultado o el error de la operación. Al descifrar, ofrece abrir el archivo recuperado con la aplicación predeterminada del sistema; solo lo abre si el usuario confirma. Para compartir, escribe el nombre exacto de una cuenta existente.

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

- La contraseña no se almacena en claro: la API guarda un verificador scrypt con salt. La clave privada RSA se cifra en el cliente mediante PBKDF2-HMAC-SHA256 y AES-128-GCM. El cliente transmite la contraseña a la API durante el alta y el inicio de sesión; el despliegue remoto requiere HTTPS.
- El salt no es secreto y se almacena junto a los datos cifrados de la clave privada. La contraseña sí debe mantenerse en secreto y ser robusta.
- La API conserva el archivo cifrado, la clave AES cifrada con RSA y la clave privada RSA protegida. Los nombres, tamaños y fechas son metadatos visibles.
- Para archivos creados con la línea de comandos, conserva el `.enc`, su `.key.enc`, `rsa_private.enc` y la contraseña con la que se protegió esa clave. Para los archivos de la interfaz, conserva el acceso a la API, su base de datos y la contraseña del usuario.
- Si pierdes la clave privada o la contraseña, no podrás descifrar los archivos protegidos por ese par RSA. La clave AES cifrada de cada archivo debe corresponder a esa misma clave privada.
- Compartir no copia el archivo: el cliente cifra la clave AES para el destinatario. Revocar después el acceso no elimina los archivos que el destinatario ya haya descargado.
- La clave pública del destinatario se obtiene de la API. Esta versión confía en el servidor para distribuir las claves; para protegerse de un servidor malicioso, hay que verificar la huella de la clave pública por otro canal confiable.
- El `.gitignore` excluye `data/`, `media/`, claves y archivos cifrados para no publicar datos locales accidentalmente. La clave pública no es secreta, pero en este proyecto también se guarda en `data/` y queda excluida.
- `.gitignore` no elimina archivos que ya estén siendo seguidos por Git ni borra archivos publicados anteriormente. Antes de subir cambios, revisa el estado del repositorio y asegúrate de que no haya claves privadas ni datos personales.

## Para convertir ejecutable

Para generar un **`.exe` de Windows**, usa **PyInstaller desde Windows**, no desde WSL. La versión que genera PyInstaller depende del sistema donde se ejecuta: desde WSL producirías un ejecutable Linux, no un `.exe` de Windows.

El ejecutable es un cliente de la API; no incluye la base del servidor ni credenciales de MariaDB. Configura `CS2026_API_URL` en el equipo antes de iniciar el `.exe` (por ejemplo, `https://magocloud.ddns.net`). En PowerShell:

```powershell
$env:CS2026_API_URL = "https://magocloud.ddns.net"
.\dist\CS2026\CS2026.exe
```

La API remota debe presentar un certificado HTTPS válido.

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
