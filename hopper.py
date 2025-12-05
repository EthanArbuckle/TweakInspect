from pathlib import Path
from typing import Type

from tweakinspect.codesearch import FunctionHookCodeSearchOperation
from tweakinspect.codesearches.logos_register_hook import LogosRegisterHookCodeSearchOperation
from tweakinspect.codesearches.method_setImplementation import MethodSetImpCodeSearchOperation
from tweakinspect.codesearches.MSHookFunction import MSHookFunctionCodeSearchOperation
from tweakinspect.codesearches.MSHookMessageEx import MSHookMessageExCodeSearchOperation
from tweakinspect.executable import Executable

print("TweakInspect hook analysis running")

doc = Document.getCurrentDocument()  # type: ignore[name-defined] # noqa: F821
__TEXT_SEG = doc.getSegmentByName("__TEXT")

p = Path(doc.getExecutableFilePath())

executable = Executable(original_file_name="unknown", file_path=p)
codesearch_ops: list[Type[FunctionHookCodeSearchOperation]] = [
    MSHookFunctionCodeSearchOperation,
    MSHookMessageExCodeSearchOperation,
    MethodSetImpCodeSearchOperation,
    LogosRegisterHookCodeSearchOperation,
]

for code_search_op in codesearch_ops:
    for hook in code_search_op(executable).analyze():
        new_routine_name = str(hook)
        function_address = hook.replacement_address

        print(f"{hook} at {hex(hook.replacement_address)}")
        __TEXT_SEG.setNameAtAddress(function_address, new_routine_name)

print("TweakInspect hook analysis complete")
