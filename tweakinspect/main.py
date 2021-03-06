from cgitb import Hook
from dataclasses import dataclass
import sys
from pathlib import Path
from typing import List, Optional

from capstone import CsInsn
from capstone.arm64_const import ARM64_OP_IMM, ARM64_REG_SP
from strongarm.macho import MachoAnalyzer, ObjcSelector, VirtualMemoryPointer
from strongarm.objc import ObjcFunctionAnalyzer, ObjcInstruction, RegisterContents
from strongarm_dataflow.register_contents import RegisterContentsType

# from tweakinspect.executable import DebFile
from tweakinspect.registers import capstone_enum_for_register, register_name_for_capstone_enum


@dataclass
class HookMapping:
    hooked_function_name: str
    replacement_hook_function_address: int

    def __str__(self) -> str:
        return self.hooked_function_name

    def __repr__(self) -> str:
        return str(self)

    def __hash__(self) -> int:
        return hash(self.hooked_function_name)

    def __eq__(self, __o: object) -> bool:
        return self.hooked_function_name == __o


def _get_register_contents_at_instruction(
    function_analyzer: ObjcFunctionAnalyzer, register: str, start_instr: CsInsn, strongarm: bool = True
):
    # Strongarm isn't working for a lot of cases, so only use it if specified by the caller.
    # Otherwise,
    # fallback to a reimplementation of SA's get_register_contents_at_instruction()
    if strongarm:
        strongarm_result = function_analyzer.get_register_contents_at_instruction(register, start_instr)
        if strongarm_result.type != RegisterContentsType.UNKNOWN and strongarm_result.value:
            return strongarm_result

    # Starting at the provided instruction's address, walk the stack
    # backwards searching for the value of the specified register.
    # The target register will change as instructions are enumerated
    # as data may be passed around between registers
    target_register = register
    offset = 0
    function_size = start_instr.address - function_analyzer.start_address
    for current_address_offset in range(0, function_size, 4):

        current_address = start_instr.address - current_address_offset
        instr = function_analyzer.get_instruction_at_address(current_address)
        if not instr:
            continue

        if len(instr.operands) < 2 or instr.mnemonic.startswith("b") or instr.mnemonic == "cbz":
            continue

        dst = instr.operands[0]
        src = instr.operands[1]
        # The src/dst is swapped for some instructions
        if instr.mnemonic in ["str", "stur"]:
            dst = instr.operands[1]
            src = instr.operands[0]

        # If the *destination* register of this instruction is not the current *target register*,
        # skip to the "next" (previous) instruction
        capstone_format_target_reg = capstone_enum_for_register(target_register)
        if capstone_format_target_reg != dst.reg:
            continue

        # Be mindful of situtations like "[sp, #40]", where the register itself (sp) is
        # not enough information to determine if this is actually a relevant target
        # TODO: should not be limited to sp
        if capstone_format_target_reg in [ARM64_REG_SP] and len(instr.operands) > 1 and "+" in target_register:
            target_offset = int(target_register.split("+")[1])
            sp_offset = dst.mem.base + dst.mem.disp
            if target_offset != sp_offset:
                continue

        # TODO: should not be limited to sp
        if src.reg in [ARM64_REG_SP] and len(instr.operands) > 1:
            if "+" in target_register:
                target_offset = int(target_register.split("+")[1])
                sp_offset = src.mem.base + src.mem.disp
                if target_offset != sp_offset:
                    continue

        # Handle situations in which an address is calculated across 2 instructions:
        # adrp  x3, #0xf000
        # add   x3, #30
        # in which x3 should be evalutated to #0xf030
        if instr.mnemonic == "adrp":
            next_instr = function_analyzer.get_instruction_at_address(current_address + 4)
            if next_instr.mnemonic == "add":
                offset = next_instr.operands[-1].mem.base

        # If this register contains an immediate value, it's likely the value being targeted.
        # Return the value
        if src.type == ARM64_OP_IMM:
            reg_value = src.mem.base + offset
            return RegisterContents(RegisterContentsType.IMMEDIATE, reg_value)

        # This instruction's destination register matches the current target register,
        # but the source register is not an immediate value; likely another register.
        # Update the target_register to this instruction's source register
        # and keep searching
        target_register = register_name_for_capstone_enum(src.reg)
        offset = src.mem.disp
        # TODO: should not be limited to sp
        if src.reg == ARM64_REG_SP and len(instr.operands) > 1:
            sp_offset = src.mem.base + src.mem.disp
            target_register = f"{target_register}+{sp_offset}"


def find_calls_to_function_before_address(
    function_analyzer: ObjcFunctionAnalyzer, function_name: str, end_address: int
) -> List[ObjcInstruction]:
    """Invocations of function_name within the current function scope, from start of function to end_address"""
    function_calls = []
    for call_target in function_analyzer.call_targets:
        # Add functions that match the specified name, and are before end_address
        if call_target.symbol and function_name in call_target.symbol and call_target.address < end_address:
            function_calls.append(call_target)
    return function_calls


def last_invocation_of_function(
    function_analyzer: ObjcFunctionAnalyzer, function_name: str, current_address: int
) -> Optional[ObjcInstruction]:
    """The invocation of function_name in closest proximity (and preceding) to current_address"""
    function_calls = find_calls_to_function_before_address(function_analyzer, function_name, current_address)
    if len(function_calls) > 0:
        # The last function call will be closest to current_address
        return function_calls[-1]
    return None


def read_string_from_register(
    function_analyzer: ObjcFunctionAnalyzer, register: str, callsite: ObjcInstruction
) -> Optional[str]:
    """Get the string that used in a objc_getClass() invocation"""
    # The previous instruction dealing with the target register
    reg_contents = _get_register_contents_at_instruction(function_analyzer, register, callsite)
    return function_analyzer.binary.read_string_at_address(reg_contents.value)


def string_from_literal_or_selref_address(analyzer: MachoAnalyzer, address: VirtualMemoryPointer) -> Optional[str]:
    def _string_from_literal_or_selref_address(_address) -> Optional[str]:
        for func in [
            analyzer.objc_helper.selector_for_selref,
            analyzer.objc_helper.selector_for_selector_literal,
            analyzer.binary.read_string_at_address,
        ]:
            try:
                value = func(_address)
                if value:
                    if isinstance(value, ObjcSelector):
                        return value.name
                    return value
            except:
                pass

    # TODO:
    # Sometimes there is a selector address without virtual base
    return _string_from_literal_or_selref_address(address) or _string_from_literal_or_selref_address(
        address + 0x100000000
    )


def find_setImplementations(executable) -> List[HookMapping]:
    """Find invocations of method_setImplementation"""
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    method_setImplementation = analyzer.callable_symbol_for_symbol_name("_method_setImplementation")
    if not method_setImplementation:
        return found_calls

    invocations = analyzer.calls_to(method_setImplementation.address)
    for idx, invocation in enumerate(invocations):
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            executable.binary, invocation.caller_func_start_address
        )
        # The first arg is a Class
        # Look for a call to objc_getClass()
        getClass_invocation = last_invocation_of_function(function_analyzer, "objc_getClass", invocation.caller_addr)
        if not getClass_invocation:
            continue

        # Found objc_getClass(), x0 should be a string that is the class name
        class_name = read_string_from_register(function_analyzer, "x0", getClass_invocation)
        # The second arg is a Method
        # Look for calls to getInstanceMethod/getClassMethod
        getMethod_invocations = find_calls_to_function_before_address(
            function_analyzer, "class_getInstanceMethod", invocation.caller_addr
        )
        if not getMethod_invocations:
            continue
        correlated_idx = max(idx, len(getMethod_invocations) - 1)
        getMethod_invocation = getMethod_invocations[correlated_idx]

        # x1 should be a selector that is the method to get
        sel_value = _get_register_contents_at_instruction(
            function_analyzer, "x1", getMethod_invocation.raw_instr, strongarm=False
        )
        if sel_value.type == RegisterContentsType.IMMEDIATE:
            selector_name = string_from_literal_or_selref_address(analyzer, sel_value.value)
            new_routine_name = f"%hook [{class_name} {selector_name}]"

            replacement_func = _get_register_contents_at_instruction(
                function_analyzer,
                "x1",
                function_analyzer.get_instruction_at_address(invocation.caller_addr),
                strongarm=False,
            )
            found_calls.append(
                HookMapping(
                    hooked_function_name=new_routine_name, replacement_hook_function_address=replacement_func.value
                )
            )
    return found_calls


def find_logos_register_hook(executable):
    """Find invocations of _logos_register_hook"""
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)

    register_hook_candidates = [
        function for function in analyzer.exported_symbol_names_to_pointers if "logos_register_hook" in function
    ]
    if not register_hook_candidates:
        return found_calls

    _logos_register_hook = analyzer.callable_symbol_for_symbol_name(register_hook_candidates[0])
    if not _logos_register_hook:
        return found_calls

    invocations = analyzer.calls_to(_logos_register_hook.address)
    for invocation in invocations:
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            executable.binary, invocation.caller_func_start_address
        )

        # The first arg is a Class
        # Look for a call to objc_getClass()
        getClass_invocation = last_invocation_of_function(function_analyzer, "objc_getClass", invocation.caller_addr)
        if not getClass_invocation:
            continue

        # Found objc_getClass(), x0 should be a string that is the class name
        class_name = read_string_from_register(function_analyzer, "x0", getClass_invocation)

        # The second arg is a selector
        instruction = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instruction)
        x1 = function_analyzer.get_register_contents_at_instruction("x1", parsed_instructions)
        selector = analyzer.objc_helper.selector_for_selref(x1.value)

        found_calls.append(f"%hook [{class_name} {selector.name}]")
    return found_calls


def find_MSHookMessageEx(executable) -> List[HookMapping]:
    """Find invocations of MSHookMessageEx"""
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    MSHookMessageEx = analyzer.callable_symbol_for_symbol_name("_MSHookMessageEx")
    if not MSHookMessageEx:
        return found_calls

    invocations = analyzer.calls_to(MSHookMessageEx.address)
    for invocation in invocations:

        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            executable.binary, invocation.caller_func_start_address
        )
        # The first arg is the Class on which a method will be intrumented.
        # Look for a call to objc_getClass()
        getClass_invocation = last_invocation_of_function(function_analyzer, "objc_getClass", invocation.caller_addr)
        if not getClass_invocation:
            continue

        # Found objc_getClass(), x0 should be a string that is the class name
        class_name = read_string_from_register(function_analyzer, "x0", getClass_invocation)

        # The next arg is a selector that is the Method to instrument.
        # It should be in x1
        instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)
        selector_val = _get_register_contents_at_instruction(
            function_analyzer, "x1", parsed_instructions.raw_instr, strongarm=False
        )
        selector_name = string_from_literal_or_selref_address(analyzer, selector_val.value)
        new_routine_name = f"%hook [{class_name} {selector_name}]"

        replacement_func = _get_register_contents_at_instruction(
            function_analyzer, "x2", parsed_instructions.raw_instr, strongarm=False
        )

        found_calls.append(
            HookMapping(hooked_function_name=new_routine_name, replacement_hook_function_address=replacement_func.value)
        )

    return found_calls


def find_MSHookFunction(executable) -> List[HookMapping]:
    """Find invocations of MSHookFunction"""
    found_calls = []
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    MSHookFunction = analyzer.callable_symbol_for_symbol_name("_MSHookFunction")
    if not MSHookFunction:
        return found_calls

    invocations = analyzer.calls_to(MSHookFunction.address)
    for invocation in invocations:

        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            executable.binary, invocation.caller_func_start_address
        )
        instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)

        # The first arg is the function to hook.
        # First, see if its an address that correlates with a known function
        x0 = _get_register_contents_at_instruction(function_analyzer, "x0", instructions)
        x1 = _get_register_contents_at_instruction(function_analyzer, "x1", instructions)
        if x0.value:
            # This could be a linked function
            if VirtualMemoryPointer(x0.value) in analyzer.imported_symbols_to_symbol_names:
                symbol_name = analyzer.imported_symbols_to_symbol_names[VirtualMemoryPointer(x0.value)]
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
            else:
                # It could be a string
                # ?? function = analyzer.exported_symbol_name_for_address(x0.value)
                symbol_name = read_string_from_register(function_analyzer, "x0", parsed_instructions)
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
            new_routine_name = f"%hookf {symbol_name}()"
            found_calls.append(
                HookMapping(hooked_function_name=new_routine_name, replacement_hook_function_address=x1.value)
            )
        else:
            # x0 isn't a recognizable address, try looking for a nearby call to dlsym or MSFindSymbol
            for lookup_func in ["MSFindSymbol", "dlsym"]:
                lookup_func_invocation = last_invocation_of_function(
                    function_analyzer, lookup_func, invocation.caller_addr
                )
                if not lookup_func_invocation:
                    continue

                # Found it, x1 should be a string that is the class name
                symbol_name = read_string_from_register(function_analyzer, "x1", lookup_func_invocation)
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
                new_routine_name = f"%hookf {symbol_name}()"
                found_calls.append(
                    HookMapping(hooked_function_name=new_routine_name, replacement_hook_function_address=x1.value)
                )
                break

    return found_calls


def does_call_setuid0(executable) -> bool:
    """Find invocations of setuid(0)"""
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    setuid = analyzer.callable_symbol_for_symbol_name("_setuid")
    if setuid:
        invocations = analyzer.calls_to(setuid.address)
        for invocation in invocations:
            function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
                executable.binary, invocation.caller_func_start_address
            )
            instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
            parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)

            # The first arg is the id to set
            x0 = function_analyzer.get_register_contents_at_instruction("x0", parsed_instructions)
            # If the immediate value is 0
            if x0.type is RegisterContentsType.IMMEDIATE and x0.value == 0:
                # This is a call to setuid(0)
                return True
    return False


def does_call_setgid0(executable) -> bool:
    """Find invocations of setgid(0)"""
    analyzer = MachoAnalyzer.get_analyzer(executable.binary)
    setgid = analyzer.callable_symbol_for_symbol_name("_setgid")
    if setgid:
        invocations = analyzer.calls_to(setgid.address)
        for invocation in invocations:
            function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
                executable.binary, invocation.caller_func_start_address
            )
            instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
            parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)

            # The first arg is the id to set
            x0 = function_analyzer.get_register_contents_at_instruction("x0", parsed_instructions)
            # If the immediate value is 0
            if x0.type is RegisterContentsType.IMMEDIATE and x0.value == 0:
                # This is a call to setgid(0)
                return True
    return False


def print_executable_info(executable) -> None:
    does_escalate = executable.does_escalate_to_root()
    print(f"setuid0/setgid0: {does_escalate}")
    print("hooks:")
    for hook in executable.get_hooks():
        print(f" {hook}")
    print(f"entitlements: {executable.get_entitlements()}")


if __name__ == "__main__":
    pass
    # provided_file = Path(sys.argv[1])
    # if provided_file.suffix == ".deb":
    #     debfile = DebFile(provided_file)
    #     for executable in debfile.get_executables():
    #         print_executable_info(executable)
    #         executable.cleanup()
    # else:
    #     dylib = Executable(original_file_name=provided_file, file_bytes=provided_file.read_bytes())
    #     print_executable_info(dylib)
    #     dylib.cleanup()
