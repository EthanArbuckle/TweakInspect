import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from capstone import CsInsn
from capstone.arm64 import ARM64_OP_IMM, ARM64_REG_SP
from strongarm.macho import MachoAnalyzer, ObjcSelector
from strongarm.objc import ObjcFunctionAnalyzer, ObjcInstruction, RegisterContents, RegisterContentsType

from tweakinspect.models import Hook
from tweakinspect.registers import capstone_enum_for_register, register_name_for_capstone_enum

if TYPE_CHECKING:
    from tweakinspect.executable import Executable


class FunctionHookCodeSearchOperation(ABC):

    def __init__(self, executable: "Executable") -> None:
        self.executable = executable
        self.macho_analyzer = MachoAnalyzer(executable.binary)

    @abstractmethod
    def analyze(self) -> list[Hook]:
        pass

    def address_for_symbol_name_in_executable(self, symbol_name: str) -> int | None:
        symbol = self.macho_analyzer.callable_symbol_for_symbol_name(symbol_name)
        if symbol:
            return symbol.address
        return None

    def last_invocation_of_function(
        self, function_analyzer: ObjcFunctionAnalyzer, function_name: str, current_address: int
    ) -> ObjcInstruction | None:
        """The invocation of function_name in closest proximity (and preceding) to current_address"""
        function_calls = self.find_calls_to_function_before_address(function_analyzer, function_name, current_address)
        if len(function_calls) > 0:
            # The last function call will be closest to current_address
            return function_calls[-1]
        return None

    def find_calls_to_function_before_address(
        self, function_analyzer: ObjcFunctionAnalyzer, function_name: str, end_address: int
    ) -> list[ObjcInstruction]:
        """Invocations of function_name within the current function scope, from start of function to end_address"""
        function_calls = []
        for call_target in function_analyzer.call_targets:
            # Add functions that match the specified name, and are before end_address
            if call_target.symbol and function_name in call_target.symbol and call_target.address < end_address:
                function_calls.append(call_target)
        return function_calls

    def read_string_from_register(
        self, function_analyzer: ObjcFunctionAnalyzer, register: str, callsite: ObjcInstruction
    ) -> str | None:
        """Get the string that used in a objc_getClass() invocation"""
        # The previous instruction dealing with the target register
        reg_contents = self.get_register_contents_at_instruction(function_analyzer, register, callsite)
        return function_analyzer.binary.read_string_at_address(reg_contents.value)

    def string_from_literal_or_selref_address(self, address: int) -> str | None:
        def _string_from_literal_or_selref_address(_address: int) -> str | None:
            analyzer = self.macho_analyzer
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
                except Exception as exc:
                    logging.error(f"Error reading string from address {_address}: {exc}")
            return None

        # TODO:
        # Sometimes there is a selector address without virtual base
        return _string_from_literal_or_selref_address(address) or _string_from_literal_or_selref_address(
            address + 0x100000000
        )

    def get_register_contents_at_instruction(
        self, function_analyzer: ObjcFunctionAnalyzer, register: str, start_instr: CsInsn, strongarm: bool = True
    ) -> RegisterContents:
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

    def resolve_block_imp(self, imp_address: int) -> int:
        # When an IMP is created using imp_implementationWithBlock(), the address points to
        # a block structure in CONST __DATA that contains the real function pointer

        # If the address is not in __DATA, it's likely a non-block IMP
        section = self.macho_analyzer.binary.section_for_address(imp_address)
        if not section or not section.segment_name.startswith("__DATA"):
            return imp_address

        try:
            # The block structure is 24 bytes long, with the function pointer at offset 16
            block_struct = self.macho_analyzer.binary.get_contents_from_address(imp_address, 24)
            function_ptr = int.from_bytes(block_struct[16:24], "little")

            # The function pointer should be in __TEXT
            section = self.macho_analyzer.binary.section_for_address(function_ptr)
            if not section or not section.segment_name.startswith("__TEXT"):
                return imp_address

            # If there's symbols, the name of this is expected to contain "_block_invoke"
            func_sym_name = self.macho_analyzer.exported_symbol_name_for_address(function_ptr)
            if func_sym_name and "_block_invoke" not in func_sym_name:
                logging.error(
                    f"Assumed block-IMP at {hex(imp_address)} resolved to function {hex(function_ptr)}"
                    " but its symbol name is not block-like: {func_sym_name}"
                )
                return imp_address
            return function_ptr
        except Exception as exc:
            logging.error(f"Error resolving block IMP at {hex(imp_address)}: {exc}")
            return imp_address
