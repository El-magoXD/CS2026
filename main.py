#!/usr/bin/env python3

from __future__ import annotations

import queue
import threading
import tkinter as tk
from collections.abc import Callable
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from crypto.aes import decrypt_file
from crypto.passwords import decrypt_private_key
from crypto.rsa import decrypt_with_private
from database.database import DEFAULT_DATABASE_PATH, initialize_database
from decrypt import DEFAULT_PRIVATE_KEY_PATH
from services.file_service import (
    decrypt_file_from_database,
    encrypt_file_to_database,
    get_database_files,
)


class CryptoApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Cifrado de archivos AES + RSA")
        self.geometry("820x560")
        self.minsize(700, 500)
        initialize_database(DEFAULT_DATABASE_PATH)

        self.results: queue.Queue[tuple[bool, str, str]] = queue.Queue()
        self.active_button: ttk.Button | None = None

        self.encrypt_input = tk.StringVar()
        self.encrypt_password = tk.StringVar()

        self.decrypt_input = tk.StringVar()
        self.decrypt_key_file = tk.StringVar()
        self.decrypt_private_key = tk.StringVar(value=str(DEFAULT_PRIVATE_KEY_PATH))
        self.decrypt_output = tk.StringVar()
        self.decrypt_password = tk.StringVar()

        self.status = tk.StringVar(value="Selecciona una operación.")
        self._build_ui()

    def _build_ui(self) -> None:
        container = ttk.Frame(self, padding=16)
        container.pack(fill="both", expand=True)

        heading = ttk.Label(
            container,
            text="Cifrado de archivos",
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

    def _add_password_row(self, parent: ttk.Frame, row: int, variable: tk.StringVar) -> None:
        ttk.Label(parent, text="Contraseña de la clave RSA").grid(
            row=row, column=0, sticky="w", pady=7
        )
        ttk.Entry(parent, textvariable=variable, show="*").grid(
            row=row, column=1, columnspan=2, sticky="ew", padx=(12, 0), pady=7
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
        self._add_password_row(parent, 1, self.encrypt_password)

        ttk.Label(
            parent,
            text=(
                "El contenido cifrado, su clave AES cifrada con RSA y la clave "
                "privada RSA protegida se guardarán en la base de datos local:\n"
                f"{DEFAULT_DATABASE_PATH}"
            ),
            wraplength=620,
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=(12, 8))

        self.encrypt_button = ttk.Button(
            parent,
            text="Cifrar y guardar en SQLite",
            command=self._start_encryption,
        )
        self.encrypt_button.grid(row=3, column=0, columnspan=3, sticky="e", pady=(12, 0))

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
            "Clave privada RSA protegida",
            self.decrypt_private_key,
            self._choose_decrypt_private_key,
        )
        self._add_file_row(
            parent,
            3,
            "Guardar archivo descifrado como",
            self.decrypt_output,
            self._choose_decrypt_output,
        )
        self._add_password_row(parent, 4, self.decrypt_password)

        ttk.Label(
            parent,
            text="El nombre y la extensión de salida los eliges aquí.",
            wraplength=620,
        ).grid(row=5, column=0, columnspan=3, sticky="w", pady=(12, 8))

        self.decrypt_button = ttk.Button(
            parent,
            text="Descifrar archivo",
            command=self._start_decryption,
        )
        self.decrypt_button.grid(row=6, column=0, columnspan=3, sticky="e", pady=(12, 0))

    def _build_library_tab(self, parent: ttk.Frame) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(1, weight=1)
        ttk.Label(
            parent,
            text=f"Archivos y claves protegidas almacenados en:\n{DEFAULT_DATABASE_PATH}",
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
        for entry in get_database_files(DEFAULT_DATABASE_PATH):
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

    def _choose_decrypt_private_key(self) -> None:
        selected = filedialog.askopenfilename(
            title="Seleccionar clave privada RSA protegida",
            initialdir=str(DEFAULT_PRIVATE_KEY_PATH.parent),
            filetypes=[("Claves privadas protegidas", "*.enc"), ("Todos los archivos", "*")],
        )
        if selected:
            self.decrypt_private_key.set(selected)

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
        password = self.encrypt_password.get()
        if not source_text or not password:
            messagebox.showerror(
                "Faltan datos",
                "Selecciona el archivo original y escribe la contraseña.",
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
            lambda: self._encrypt(source, password),
        )

    def _encrypt(self, source: Path, password: str) -> str:
        try:
            file_id = encrypt_file_to_database(source, password, DEFAULT_DATABASE_PATH)
        except ValueError as exc:
            raise ValueError(
                "No se pudo validar o guardar el par RSA. Comprueba la contraseña "
                f"y los archivos de clave. Detalle: {exc}"
            ) from exc

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
        password = simpledialog.askstring(
            "Contraseña",
            "Contraseña de la clave privada RSA:",
            show="*",
            parent=self,
        )
        if password is None:
            return
        if not password:
            messagebox.showerror(
                "Falta la contraseña",
                "Escribe la contraseña de la clave privada RSA.",
                parent=self,
            )
            return

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
            lambda: self._decrypt_database_file(file_id, password, destination),
        )

    def _decrypt_database_file(self, file_id: int, password: str, output: Path) -> str:
        try:
            destination = decrypt_file_from_database(
                file_id,
                password,
                output,
                DEFAULT_DATABASE_PATH,
            )
        except ValueError as exc:
            raise ValueError(
                "No se pudo descifrar el archivo. Comprueba la contraseña y que "
                f"los datos no estén dañados. Detalle: {exc}"
            ) from exc
        return f"Archivo descifrado correctamente:\n{destination}"

    def _start_decryption(self) -> None:
        encrypted_text = self.decrypt_input.get().strip()
        key_text = self.decrypt_key_file.get().strip()
        private_text = self.decrypt_private_key.get().strip()
        output_text = self.decrypt_output.get().strip()
        password = self.decrypt_password.get()
        if not all((encrypted_text, key_text, private_text, output_text, password)):
            messagebox.showerror(
                "Faltan datos",
                "Selecciona el archivo cifrado, su clave AES, la clave privada, "
                "la salida y escribe la contraseña.",
                parent=self,
            )
            return

        encrypted_file = Path(encrypted_text).expanduser().resolve()
        key_file = Path(key_text).expanduser().resolve()
        private_key_file = Path(private_text).expanduser().resolve()
        output = Path(output_text).expanduser().resolve()
        for path, description in (
            (encrypted_file, "archivo cifrado"),
            (key_file, "clave AES cifrada"),
            (private_key_file, "clave privada RSA"),
        ):
            if not path.is_file():
                messagebox.showerror(
                    "Archivo no encontrado",
                    f"No existe el {description}:\n{path}",
                    parent=self,
                )
                return
        if output in (encrypted_file, key_file, private_key_file):
            messagebox.showerror(
                "Salida no válida",
                "El archivo de salida no puede sobrescribir ninguno de los archivos de entrada.",
                parent=self,
            )
            return
        if not self._confirm_overwrite([output]):
            return

        self._run_in_background(
            self.decrypt_button,
            "Descifrado completado",
            lambda: self._decrypt(encrypted_file, key_file, private_key_file, output, password),
        )

    def _decrypt(
        self,
        encrypted_file: Path,
        key_file: Path,
        private_key_file: Path,
        output: Path,
        password: str,
    ) -> str:
        try:
            private_key = decrypt_private_key(private_key_file.read_bytes(), password)
        except ValueError as exc:
            raise ValueError(
                "No se pudo desbloquear la clave privada. La contraseña puede ser "
                f"incorrecta o el archivo estar dañado. Detalle: {exc}"
            ) from exc

        try:
            aes_key = decrypt_with_private(key_file.read_bytes(), private_key)
        except ValueError as exc:
            raise ValueError(
                "La clave AES seleccionada no corresponde a esta clave privada RSA."
            ) from exc

        output.parent.mkdir(parents=True, exist_ok=True)
        try:
            decrypt_file(encrypted_file, output, aes_key)
        except ValueError as exc:
            raise ValueError(
                "No se pudo verificar o descifrar el archivo. Puede estar dañado "
                f"o no corresponder a la clave AES. Detalle: {exc}"
            ) from exc
        return f"Archivo descifrado correctamente:\n{output}"

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


def main() -> None:
    app = CryptoApp()
    app.mainloop()


if __name__ == "__main__":
    main()
