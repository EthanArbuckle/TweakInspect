from pathlib import Path

from idaapi import SN_NOCHECK, get_input_file_path, set_name

from tweakinspect.codesearches.class_addMethod import ClassAddMethodCodeSearchOperation
from tweakinspect.codesearches.class_replaceMethod import ClassReplaceMethodCodeSearchOperation
from tweakinspect.codesearches.logos_register_hook import LogosRegisterHookCodeSearchOperation
from tweakinspect.codesearches.method_setImplementation import MethodSetImpCodeSearchOperation
from tweakinspect.codesearches.MSHookFunction import MSHookFunctionCodeSearchOperation
from tweakinspect.codesearches.MSHookMessageEx import MSHookMessageExCodeSearchOperation
from tweakinspect.executable import Executable
from tweakinspect.models import Hook, NewObjectiveCMethodTarget


class TweakInspectIDA:
    def __init__(self) -> None:
        self.codesearch_ops = [
            MSHookFunctionCodeSearchOperation,
            MSHookMessageExCodeSearchOperation,
            MethodSetImpCodeSearchOperation,
            ClassAddMethodCodeSearchOperation,
            ClassReplaceMethodCodeSearchOperation,
            LogosRegisterHookCodeSearchOperation,
        ]

    def rename_address(self, address: int, new_name: str) -> None:
        """Rename an address in IDA. The address may be a function, data, etc."""
        ida_friendly_new_name = self.sanitize_name(new_name)
        if set_name(address, new_name, SN_NOCHECK) != 1:
            print(f"Failed to rename {hex(address)} to {ida_friendly_new_name}")
        else:
            print(f"{hex(address):>10} -> {ida_friendly_new_name}")

    def sanitize_name(self, name: str) -> str:
        """Remove characters that IDA doesn't like in names (objc brackets, colons, spaces)"""
        for char_to_remove in ["-", "+", "[", "]", "(", ")"]:
            name = name.replace(char_to_remove, "")

        for char_to_replace in [" ", ":", ",", "__"]:
            name = name.replace(char_to_replace, "_")

        if name.endswith("_"):
            name = name[:-1]

        return name

    def run(self) -> None:
        binary_path = get_input_file_path()
        if not binary_path:
            print("[Error] Unable to get the current binary path")
            return

        executable = Executable(file_path=Path(binary_path))
        hooks: list[Hook] = []
        for code_search_op in self.codesearch_ops:
            hooks.extend(code_search_op(executable).analyze())  # type: ignore

        if not hooks:
            print("No hooks found in binary")
            return

        print(f"Found {len(hooks)} hooks")
        for hook in hooks:
            # Rename the replacement function to HOOKED_<target_name> (or NEW_<target_name> for "%new" methods)
            symbol_qualifier = "NEW_" if isinstance(hook.target, NewObjectiveCMethodTarget) else "HOOK_"
            self.rename_address(hook.replacement_address, f"{symbol_qualifier}_{hook.target.name}")
            if hook.original_address > 0:
                # Rename the pointer to the hooked item's original implementation to ORIG_<target_name>
                self.rename_address(hook.original_address, f"ORIG_{hook.target.name}")


if __name__ == "__main__":
    inspector = TweakInspectIDA()
    inspector.run()
