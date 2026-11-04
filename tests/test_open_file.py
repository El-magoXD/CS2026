from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from main import open_file_with_default_application


class OpenDecryptedFileTests(unittest.TestCase):
    def test_linux_uses_xdg_open_without_a_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "decrypted image.jpg"
            path.write_bytes(b"image")

            with patch("main.sys.platform", "linux"), patch("main.subprocess.Popen") as popen:
                open_file_with_default_application(path)

            popen.assert_called_once_with(["xdg-open", str(path)])

    def test_missing_file_is_not_opened(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            path = Path(temporary_directory) / "missing-file"
            with patch("main.subprocess.Popen") as popen:
                with self.assertRaises(FileNotFoundError):
                    open_file_with_default_application(path)
            popen.assert_not_called()


if __name__ == "__main__":
    unittest.main()
