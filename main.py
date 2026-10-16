#!/usr/bin/env python3

from __future__ import annotations

import queue
import threading
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from Crypto.PublicKey import RSA

from database.database import DEFAULT_DATABASE_PATH, initialize_database, list_users
from services.file_service import (
    AuthenticatedUser,
    authenticate_user,
    decrypt_external_file,
    decrypt_file_from_database,
    encrypt_file_to_database,
    get_database_files,
    register_user,
)


class CryptoApp(tk.Tk):
    def __init__(self, session: AuthenticatedUser) -> None:
        super().__init__()
        self.user_id = session.id
        self.username = session.username
        self.private_key: RSA.RsaKey | None = session.private_key
        self.title(f"Cifrado de archivos AES + RSA — {self.username}")
        self.geometry("820x560")
        self.minsize(700, 500)
        initialize_database(DEFAULT_DATABASE_PATH)
        self.protocol("WM_DELETE_WINDOW", self._close_app)

        self.results: queue.Queue[tuple[bool, str, str]] = queue.Queue()
        self.active_button: ttk.Button | None = None

        self.encrypt_input = tk.StringVar()

        self.decrypt_input = tk.StringVar()
        self.decrypt_key_file = tk.StringVar()
        self.decrypt_output = tk.StringVar()

        self.status = tk.StringVar(value="Selecciona una operación.")
        self._build_ui()

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=16)
        container.pack(fill="both", expand=True)

        heading = ttk.Label(
            container,
            text=f"Cifrado de archivos — sesión: {self.username}",
            font=("TkDefaultFont", 16, "bold"),
        )
        heading.pack(anchor="w", pady=(0, 12))

        notebook = ttk.Notebook(container)
        notebook.pack(fill="both", expand=True)

        encrypt_tab = ttk.Frame(notebook, padding=14)
        decrypt_tab = ttk.Frame(notebook, padding=14)
        library_tab = ttk.Frame(notebook, padding=14)
        notebook.add(encrypt_tab, text="Cifrar")
        notebook.add(decrypt_tab, text="Descifrar")
        notebook.add(library_tab, text="Biblioteca SQLite")

        self._build_encrypt_tab(encrypt_tab)
        self._build_decrypt_tab(decrypt_tab)
        self._build_library_tab(library_tab)

        ttk.Separator(container).pack(fill="x", pady=(12, 8))
        ttk.Label(container, textvariable=self.status, wraplength=680).pack(anchor="w")

    def _add_file_row(
        self,
        parent: ttk.Frame,
        row: int,
        label: str,
        variable: tk.StringVar,
        browse_command: Callable[[], None],
    ) -> None:
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=7)
        entry = ttk.Entry(parent, textvariable=variable)
        entry.grid(row=row, column=1, sticky="ew", padx=(12, 8), pady=7)
        ttk.Button(parent, text="Examinar…", command=browse_command).grid(
            row=row, column=2, sticky="ew", pady=7
        )

    def _build_encrypt_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        self._add_file_row(
            parent,
            0,
            "Archivo original",
            self.encrypt_input,
            self._choose_encrypt_input,
        )
        ttk.Label(
            parent,
            text=(
                "La clave privada RSA de esta cuenta ya se desbloqueó al iniciar "
                "sesión. El contenido cifrado y su clave AES protegida se guardarán "
                f"en:\n{DEFAULT_DATABASE_PATH}"
            ),
            wraplength=620,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(12, 8))

        self.encrypt_button = ttk.Button(
            parent,
            text="Cifrar y guardar en SQLite",
            command=self._start_encryption,
        )
        self.encrypt_button.grid(row=2, column=0, columnspan=3, sticky="e", pady=(12, 0))

    def _build_decrypt_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(1, weight=1)

        self._add_file_row(
            parent,
            0,
            "Archivo cifrado (.enc)",
            self.decrypt_input,
            self._choose_decrypt_input,
        )
        self._add_file_row(
            parent,
            1,
            "Clave AES cifrada (.key.enc)",
            self.decrypt_key_file,
            self._choose_decrypt_key_file,
        )
        self._add_file_row(
            parent,
            2,
            "Guardar archivo descifrado como",
            self.decrypt_output,
            self._choose_decrypt_output,
        )

        ttk.Label(
            parent,
            text=(
                "Se utilizará la clave privada RSA desbloqueada al iniciar sesión. "
                "El nombre y la extensión de salida los eliges aquí."
            ),
            wraplength=620,
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(12, 8))

        self.decrypt_button = ttk.Button(
            parent,
            text="Descifrar archivo",
            command=self._start_decryption,
        )
        self.decrypt_button.grid(row=4, column=0, columnspan=3, sticky="e", pady=(12, 0))

    def _build_library_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        ttk.Label(
            parent,
            text=(
                f"Archivos de {self.username} guardados en:\n"
                f"{DEFAULT_DATABASE_PATH}"
            ),
            wraplength=680,
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        self.library = ttk.Treeview(
            parent,
            columns=("id", "name", "created", "size"),
            show="headings",
            selectmode="browse",
        )
        self.library.heading("id", text="ID")
        self.library.heading("name", text="Archivo original")
        self.library.heading("created", text="Guardado")
        self.library.heading("size", text="Tamaño")
        self.library.column("id", width=55, stretch=False, anchor="center")
        self.library.column("name", width=260)
        self.library.column("created", width=190)
        self.library.column("size", width=100, stretch=False, anchor="e")
        self.library.grid(row=1, column=0, columnspan=2, sticky="nsew")

        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=self.library.yview)
        scrollbar.grid(row=1, column=2, sticky="ns")
        self.library.configure(yscrollcommand=scrollbar.set)
        self.library.bind("<Double-1>", self._on_library_double_click)

        ttk.Button(
            parent,
            text="Actualizar lista",
            command=self._refresh_library,
        ).grid(row=2, column=0, sticky="w", pady=(12, 0))
        self.decrypt_stored_button = ttk.Button(
            parent,
            text="Descifrar seleccionado…",
            command=self._decrypt_selected_database_file,
        )
        self.decrypt_stored_button.grid(row=2, column=1, sticky="e", pady=(12, 0))
        self._refresh_library()

    def _on_library_double_click(self, event: tk.Event) -> None:
        row = self.library.identify_row(event.y)
        if row:
            self.library.selection_set(row)
            self._decrypt_selected_database_file()

    def _refresh_library(self) -> None:
        entries = self.library.get_children()
        if entries:
            self.library.delete(*entries)
        for entry in get_database_files(self.user_id, DEFAULT_DATABASE_PATH):
            self.library.insert(
                "",
                "end",
                values=(
                    entry.id,
                    entry.original_name,
                    entry.created_at,
                    f"{entry.size_bytes:,} bytes",
                ),
            )

    def _choose_encrypt_input(self) -> None:
        selected = filedialog.askopenfilename(title="Seleccionar archivo para cifrar")
        if not selected:
            return
        self.encrypt_input.set(selected)

    def _choose_decrypt_input(self) -> None:
        selected = filedialog.askopenfilename(
            title="Seleccionar archivo cifrado",
            filetypes=[("Archivos cifrados", "*.enc"), ("Todos los archivos", "*")],
        )
        if not selected:
            return
        encrypted_file = Path(selected)
        self.decrypt_input.set(str(encrypted_file))
        companion_key = encrypted_file.with_suffix(".key.enc")
        if companion_key.is_file():
            self.decrypt_key_file.set(str(companion_key))
        if not self.decrypt_output.get():
            self.decrypt_output.set(str(encrypted_file.with_name(f"{encrypted_file.stem}_descifrado")))

    def _choose_decrypt_key_file(self) -> None:
        selected = filedialog.askopenfilename(
            title="Seleccionar clave AES cifrada",
            filetypes=[("Claves AES cifradas", "*.key.enc"), ("Todos los archivos", "*")],
        )
        if selected:
            self.decrypt_key_file.set(selected)

    def _choose_decrypt_output(self) -> None:
        encrypted_file = Path(self.decrypt_input.get()) if self.decrypt_input.get() else None
        initial_name = (
            f"{encrypted_file.stem}_descifrado" if encrypted_file else "archivo_descifrado"
        )
        selected = filedialog.asksaveasfilename(
            title="Guardar archivo descifrado",
            initialdir=str(encrypted_file.parent) if encrypted_file else str(Path.home()),
            initialfile=initial_name,
        )
        if selected:
            self.decrypt_output.set(selected)

    def _confirm_overwrite(self, paths: list[Path]) -> bool:
        existing = [str(path) for path in paths if path.exists()]
        if not existing:
            return True
        return messagebox.askyesno(
            "Confirmar reemplazo",
            "Estos archivos ya existen y se reemplazarán:\n\n"
            + "\n".join(existing)
            + "\n\n¿Quieres continuar?",
            parent=self,
        )

    def _start_encryption(self) -> None:
        source_text = self.encrypt_input.get().strip()
        if not source_text:
            messagebox.showerror(
                "Faltan datos",
                "Selecciona el archivo original.",
                parent=self,
            )
            return

        source = Path(source_text).expanduser().resolve()
        if not source.is_file():
            messagebox.showerror("Archivo no encontrado", f"No existe el archivo:\n{source}", parent=self)
            return

        self._run_in_background(
            self.encrypt_button,
            "Cifrado guardado en SQLite",
            lambda: self._encrypt(source),
        )

    def _encrypt(self, source: Path) -> str:
        file_id = encrypt_file_to_database(
            source,
            self.user_id,
            DEFAULT_DATABASE_PATH,
        )
        return f"{source.name} se guardó cifrado en SQLite con el ID {file_id}."

    def _decrypt_selected_database_file(self) -> None:
        selection = self.library.selection()
        if not selection:
            messagebox.showerror(
                "No hay selección",
                "Selecciona un archivo de la biblioteca.",
                parent=self,
            )
            return

        values = self.library.item(selection[0], "values")
        file_id = int(values[0])
        original_name = str(values[1])

        output = filedialog.asksaveasfilename(
            title="Guardar archivo descifrado",
            initialdir=str(Path.home()),
            initialfile=original_name,
        )
        if not output:
            return
        destination = Path(output).expanduser().resolve()
        if not self._confirm_overwrite([destination]):
            return

        self._run_in_background(
            self.decrypt_stored_button,
            "Descifrado completado",
            lambda: self._decrypt_database_file(file_id, destination),
        )

    def _decrypt_database_file(self, file_id: int, output: Path) -> str:
        destination = decrypt_file_from_database(
            file_id,
            self.user_id,
            self._require_private_key(),
            output,
            DEFAULT_DATABASE_PATH,
        )
        return f"Archivo descifrado correctamente:\n{destination}"

    def _start_decryption(self) -> None:
        encrypted_text = self.decrypt_input.get().strip()
        key_text = self.decrypt_key_file.get().strip()
        output_text = self.decrypt_output.get().strip()
        if not all((encrypted_text, key_text, output_text)):
            messagebox.showerror(
                "Faltan datos",
                "Selecciona el archivo cifrado, su clave AES y la ruta de salida.",
                parent=self,
            )
            return

        encrypted_file = Path(encrypted_text).expanduser().resolve()
        key_file = Path(key_text).expanduser().resolve()
        output = Path(output_text).expanduser().resolve()
        for path, description in (
            (encrypted_file, "archivo cifrado"),
            (key_file, "clave AES cifrada"),
        ):
            if not path.is_file():
                messagebox.showerror(
                    "Archivo no encontrado",
                    f"No existe el {description}:\n{path}",
                    parent=self,
                )
                return
        if output in (encrypted_file, key_file):
            messagebox.showerror(
                "Salida no válida",
                "El archivo de salida no puede sobrescribir los archivos de entrada.",
                parent=self,
            )
            return
        if not self._confirm_overwrite([output]):
            return

        self._run_in_background(
            self.decrypt_button,
            "Descifrado completado",
            lambda: self._decrypt(encrypted_file, key_file, output),
        )

    def _decrypt(
        self,
        encrypted_file: Path,
        key_file: Path,
        output: Path,
    ) -> str:
        try:
            destination = decrypt_external_file(
                encrypted_file,
                key_file,
                self._require_private_key(),
                output,
            )
        except ValueError as exc:
            raise ValueError(
                "No se pudo descifrar el archivo. Comprueba que pertenezca a "
                f"{self.username} y que no esté dañado. Detalle: {exc}"
            ) from exc
        return f"Archivo descifrado correctamente:\n{destination}"

    def _require_private_key(self) -> RSA.RsaKey:
        if self.private_key is None:
            raise RuntimeError("La sesión ya no tiene una clave privada desbloqueada.")
        return self.private_key

    def _run_in_background(
        self,
        button: ttk.Button,
        success_title: str,
        operation: Callable[[], str],
    ) -> None:
        self.active_button = button
        button.configure(state="disabled")
        self.status.set("Procesando…")

        def worker() -> None:
            try:
                result = operation()
            except Exception as exc:
                self.results.put((False, f"{type(exc).__name__}: {exc}", success_title))
            else:
                self.results.put((True, result, success_title))

        threading.Thread(target=worker, daemon=True).start()
        self.after(100, self._poll_results)

    def _poll_results(self) -> None:
        try:
            succeeded, message, title = self.results.get_nowait()
        except queue.Empty:
            self.after(100, self._poll_results)
            return

        if self.active_button is not None:
            self.active_button.configure(state="normal")
            self.active_button = None
        self.status.set(message.splitlines()[0])
        if succeeded:
            if title == "Cifrado guardado en SQLite":
                self._refresh_library()
            messagebox.showinfo(title, message, parent=self)
        else:
            messagebox.showerror("No se pudo completar la operación", message, parent=self)

    def _close_app(self) -> None:
        self.private_key = None
        self.destroy()


class AccountLoginDialog(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Iniciar sesión")
        self.resizable(False, False)
        self.session: AuthenticatedUser | None = None
        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self._build_ui()
        self._refresh_users()
        self.protocol("WM_DELETE_WINDOW", self._cancel)

    def _build_ui(self) -> None:
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text="Selecciona tu usuario e inicia sesión").grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(0, 12)
        )

        ttk.Label(frame, text="Usuario").grid(row=1, column=0, sticky="w", pady=6)
        self.user_selector = ttk.Combobox(
            frame,
            textvariable=self.username,
            state="readonly",
            width=28,
        )
        self.user_selector.grid(row=1, column=1, sticky="ew", padx=(12, 0), pady=6)

        ttk.Label(frame, text="Contraseña").grid(row=2, column=0, sticky="w", pady=6)
        password_entry = ttk.Entry(frame, textvariable=self.password, show="*")
        password_entry.grid(row=2, column=1, sticky="ew", padx=(12, 0), pady=6)
        password_entry.bind("<Return>", self._on_password_return)

        buttons = ttk.Frame(frame)
        buttons.grid(row=3, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(buttons, text="Crear usuario…", command=self._open_registration).pack(
            side="left", padx=(0, 8)
        )
        self.login_button = ttk.Button(buttons, text="Iniciar sesión", command=self._login)
        self.login_button.pack(side="left")
        frame.columnconfigure(1, weight=1)
        self.geometry("430x190")

    def _on_password_return(self, _event: tk.Event) -> None:
        _ = _event
        self._login()

    def _refresh_users(self, select: str | None = None) -> None:
        users = list_users(DEFAULT_DATABASE_PATH)
        self.user_selector.configure(values=users)
        if select and select in users:
            self.username.set(select)
        elif users and self.username.get() not in users:
            self.username.set(users[0])
        elif not users:
            self.username.set("")
        self.login_button.configure(state="normal" if users else "disabled")

    def _login(self) -> None:
        username = self.username.get().strip()
        password = self.password.get()
        if not username or not password:
            messagebox.showerror(
                "Faltan datos",
                "Selecciona un usuario e introduce su contraseña.",
                parent=self,
            )
            return
        try:
            self.session = authenticate_user(username, password, DEFAULT_DATABASE_PATH)
        except ValueError as exc:
            self.password.set("")
            messagebox.showerror("No se pudo iniciar sesión", str(exc), parent=self)
            return
        self.password.set("")
        self.destroy()

    def _open_registration(self) -> None:
        RegistrationDialog(self, self._register_user)

    def _register_user(self, username: str, password: str, confirmation: str) -> None:
        if password != confirmation:
            messagebox.showerror(
                "Las contraseñas no coinciden",
                "Vuelve a escribir ambas contraseñas.",
                parent=self,
            )
            return
        try:
            register_user(username, password, DEFAULT_DATABASE_PATH)
            self.session = authenticate_user(username, password, DEFAULT_DATABASE_PATH)
        except ValueError as exc:
            messagebox.showerror("No se pudo crear el usuario", str(exc), parent=self)
            return
        self.password.set("")
        self.destroy()

    def _cancel(self) -> None:
        self.session = None
        self.destroy()


class RegistrationDialog(tk.Toplevel):
    def __init__(
        self,
        parent: AccountLoginDialog,
        on_register: Callable[[str, str, str], None],
    ) -> None:
        super().__init__(parent)
        self.parent_dialog = parent
        self.on_register = on_register
        self.title("Crear usuario")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.username = tk.StringVar()
        self.password = tk.StringVar()
        self.confirmation = tk.StringVar()
        frame = ttk.Frame(self, padding=18)
        frame.pack(fill="both", expand=True)
        fields = (
            ("Usuario", self.username, False),
            ("Contraseña", self.password, True),
            ("Repetir contraseña", self.confirmation, True),
        )
        for row, (label, variable, hidden) in enumerate(fields):
            ttk.Label(frame, text=label).grid(row=row, column=0, sticky="w", pady=6)
            ttk.Entry(
                frame,
                textvariable=variable,
                show="*" if hidden else "",
                width=30,
            ).grid(row=row, column=1, sticky="ew", padx=(12, 0), pady=6)
        ttk.Button(frame, text="Crear cuenta", command=self._submit).grid(
            row=len(fields), column=0, columnspan=2, sticky="e", pady=(14, 0)
        )
        frame.columnconfigure(1, weight=1)
        self.geometry("420x210")

    def _submit(self) -> None:
        username = self.username.get().strip()
        password = self.password.get()
        confirmation = self.confirmation.get()
        if not username or not password or not confirmation:
            messagebox.showerror(
                "Faltan datos",
                "Completa el usuario y los dos campos de contraseña.",
                parent=self,
            )
            return
        self.password.set("")
        self.confirmation.set("")
        self.on_register(username, password, confirmation)


def main() -> None:
    initialize_database(DEFAULT_DATABASE_PATH)
    login = AccountLoginDialog()
    login.mainloop()
    session = login.session
    login.session = None
    del login
    if session is None:
        return
    app = CryptoApp(session)
    del session
    app.mainloop()


if __name__ == "__main__":
    main()
