import logging

from strongarm.macho import CallerXRef, VirtualMemoryPointer
from strongarm.objc import ObjcFunctionAnalyzer, ObjcInstruction, RegisterContentsType

from tweakinspect.codesearch import FunctionHookCodeSearchOperation
from tweakinspect.models import FunctionTarget, Hook


class MSHookFunctionCodeSearchOperation(FunctionHookCodeSearchOperation):

    FUNCTION_TO_FIND = "_MSHookFunction"

    def analyze_invocation(self, invocation: CallerXRef) -> Hook | None:
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            self.executable.binary, invocation.caller_func_start_address
        )

        instructions = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        parsed_instructions = ObjcInstruction.parse_instruction(function_analyzer, instructions)

        # x2 may hold the address of orig
        orig_address = 0
        x2 = self.get_register_contents_at_instruction(function_analyzer, "x2", instructions)
        if x2.value and x2.type == RegisterContentsType.IMMEDIATE:
            orig_address = x2.value

        # The first arg is the function to hook.
        # First, see if its an address that correlates with a known function
        x0 = self.get_register_contents_at_instruction(function_analyzer, "x0", instructions, strongarm=False)
        if not x0 or x0.type != RegisterContentsType.IMMEDIATE:
            logging.debug(f"Unexpected x0 value for invocation {invocation}: {x0}")
            return None

        x1 = self.get_register_contents_at_instruction(function_analyzer, "x1", instructions)
        if not x1 or x1.type != RegisterContentsType.IMMEDIATE:
            logging.debug(f"Unexpected x1 value for invocation {invocation}: {x1}")
            return None

        if x0.value:
            # This could be a linked function
            if VirtualMemoryPointer(x0.value) in self.macho_analyzer.imported_symbols_to_symbol_names:
                symbol_name = self.macho_analyzer.imported_symbols_to_symbol_names[VirtualMemoryPointer(x0.value)]
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name
            else:
                # It could be a string
                # ?? function = analyzer.exported_symbol_name_for_address(x0.value)
                symbol_name = self.read_string_from_register(function_analyzer, "x0", parsed_instructions)
                if symbol_name:
                    symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name

                # If the string is a path, it's not a symbol name
                if "/" in symbol_name:
                    symbol_name = None

            if symbol_name:
                return Hook(
                    target=FunctionTarget(
                        target_function_address=None,
                        target_function_name=symbol_name,
                    ),
                    replacement_address=x1.value,
                    original_address=orig_address,
                    callsite_address=int(invocation.caller_addr),
                )
        # x0 isn't a recognizable address, try looking for a nearby call to dlsym or MSFindSymbol
        closest_resolver_inv = None
        for resolver_func_name in ["MSFindSymbol", "dlsym"]:
            resolver_inv = self.last_invocation_of_function(
                function_analyzer, resolver_func_name, invocation.caller_addr
            )
            if not resolver_inv:
                continue

            if closest_resolver_inv is None or resolver_inv.address > closest_resolver_inv.address:
                closest_resolver_inv = resolver_inv

        if closest_resolver_inv:
            # Found it, x1 should be a string that is the class name
            symbol_name = self.read_string_from_register(function_analyzer, "x1", closest_resolver_inv)
            if symbol_name:
                symbol_name = symbol_name[1:] if symbol_name.startswith("_") else symbol_name

            return Hook(
                target=FunctionTarget(
                    target_function_address=None,
                    target_function_name=symbol_name,
                ),
                replacement_address=x1.value,
                original_address=orig_address,
                callsite_address=int(invocation.caller_addr),
            )

        return None
