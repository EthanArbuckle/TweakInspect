from __future__ import annotations

import itertools
import plistlib
import tarfile
import tempfile
from pathlib import Path

import unix_ar
from strongarm.macho import MachoParser

from tweakinspect.codesearches.class_addMethod import ClassAddMethodCodeSearchOperation
from tweakinspect.codesearches.class_replaceMethod import ClassReplaceMethodCodeSearchOperation
from tweakinspect.codesearches.logos_register_hook import LogosRegisterHookCodeSearchOperation
from tweakinspect.codesearches.method_setImplementation import MethodSetImpCodeSearchOperation
from tweakinspect.codesearches.MSHookFunction import MSHookFunctionCodeSearchOperation
from tweakinspect.codesearches.MSHookMessageEx import MSHookMessageExCodeSearchOperation
from tweakinspect.models import Hook
from tweakinspect.set_id0 import does_call_setgid0, does_call_setuid0


class Executable(object):
    """An executable from the tweak package"""

    def __init__(
        self, original_file_name: str | None = None, file_bytes: bytes | None = None, file_path: Path | None = None
    ) -> None:
        self.original_file_name = original_file_name
        self.file_path = Path(file_path) if file_path else None
        if file_path is None and file_bytes is not None:
            temp_file = tempfile.NamedTemporaryFile(mode="wb", delete=False)
            temp_file.write(file_bytes)
            self.file_path = Path(temp_file.name)
        self.hooked_symbols: list[Hook] | None = None
        self.binary = MachoParser(self.file_path).get_arm64_slice()

    def cleanup(self) -> None:
        if self.file_path and self.file_path.exists():
            self.file_path.unlink()

    def get_hooks(self) -> list[Hook]:
        """A list of the methods/functions the executable hooks"""
        if not self.hooked_symbols:
            self.hooked_symbols = list(
                itertools.chain(
                    *[
                        ClassAddMethodCodeSearchOperation(self).analyze(),
                        ClassReplaceMethodCodeSearchOperation(self).analyze(),
                        LogosRegisterHookCodeSearchOperation(self).analyze(),
                        MSHookFunctionCodeSearchOperation(self).analyze(),
                        MSHookMessageExCodeSearchOperation(self).analyze(),
                        MethodSetImpCodeSearchOperation(self).analyze(),
                    ]
                )
            )

        return self.hooked_symbols

    def get_entitlements(self) -> dict:
        """Get the entitlements the executable is signed with"""
        parsed_entitlements = plistlib.loads(self.binary.get_entitlements())
        return parsed_entitlements or {}

    def does_escalate_to_root(self) -> bool:
        # Does the executable try to escalate to root via setuid(0)/setgid(0)
        return does_call_setuid0(self) or does_call_setgid0(self)

    def __str__(self) -> str:
        if self.original_file_name:
            return f"Executable({self.original_file_name})"
        return str(self.file_path)


class DebFile(object):
    """A deb file containing a tweak or executable"""

    def __init__(self, deb_path: Path) -> None:
        self.deb_path = deb_path
        self._extracted_files: dict[str, bytes] = {}
        self.data_tarball: tarfile.TarFile | None = None
        self.executable_files: list[Executable] | None = None
        self._parse_deb()

    def _parse_deb(self) -> None:
        """Find the data archive within the provided deb file"""
        ar_file = unix_ar.ArFile(file=self.deb_path.open(mode="rb"))
        for filename in ar_file._name_map.keys():
            if b"data." in filename:
                data_tarball_ar = ar_file.open(filename.decode("utf-8"))
                self.data_tarball = tarfile.open(fileobj=data_tarball_ar, mode="r:*")
                return

        raise Exception("failed to find data archive")

    def all_files(self) -> list[str]:
        """The files in the deb that make up the package"""
        if self.data_tarball:
            return [member.name for member in self.data_tarball.getmembers()]
        return []

    def get_file(self, filename: str) -> bytes | None:
        """Get a file from the tweak by name"""
        if filename not in self._extracted_files and self.data_tarball:
            try:
                extracted_file = self.data_tarball.extractfile(filename)
            except KeyError:
                return None
            if extracted_file:
                file_bytes = extracted_file.read()
                self._extracted_files[filename] = file_bytes

        return self._extracted_files.get(filename, None)

    def get_executables(self) -> list[Executable]:
        """Mach-Os from the deb"""
        if self.executable_files is None:
            self.executable_files = []
            for filename in self.all_files():
                file_bytes = self.get_file(filename)
                if file_bytes:
                    magic = int.from_bytes(file_bytes[0:4], "big")
                    if magic in MachoParser.SUPPORTED_MAG:
                        # Write it to file
                        executable = Executable(original_file_name=filename, file_bytes=file_bytes)
                        self.executable_files.append(executable)
        return self.executable_files
