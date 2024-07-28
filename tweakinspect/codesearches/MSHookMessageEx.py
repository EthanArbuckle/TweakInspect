import logging

from strongarm.macho import CallerXRef
from strongarm.objc import ObjcFunctionAnalyzer, RegisterContentsType

from tweakinspect.codesearch import FunctionHookCodeSearchOperation
from tweakinspect.models import Hook, ObjectiveCTarget


class MSHookMessageExCodeSearchOperation(FunctionHookCodeSearchOperation):
    def analyze(self) -> list[Hook]:

        # Find the address of MSHookMessageEx()
        MSHookMessageEx_addr = self.address_for_symbol_name_in_executable("_MSHookMessageEx")
        if not MSHookMessageEx_addr:
            # The binary does not use MSHookMessageEx()
            return []

        # Analyze every invocation of MSHookMessageEx()
        invocations = self.macho_analyzer.calls_to(MSHookMessageEx_addr)
        results: list[Hook] = []
        for invocation in invocations:
            result = self.analyze_invocation(invocation)
            if result:
                results.append(result)
        return results

    def analyze_invocation(self, invocation: CallerXRef) -> Hook | None:
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            self.executable.binary, invocation.caller_func_start_address
        )

        # Look for an objc_getClass() call before MSHookMessageEx()
        getClass_invocation = self.last_invocation_of_function(
            function_analyzer, "objc_getClass", invocation.caller_addr
        )
        if not getClass_invocation:
            logging.debug(f"Did not find objc_getClass() before for invocation {invocation}")
            return None

        # Get the value of x0 at the invocation of objc_getClass().
        # It will be the class name
        class_name = self.read_string_from_register(function_analyzer, "x0", getClass_invocation)
        if not class_name:
            logging.debug(f"Failed to read the class name at {getClass_invocation} for {invocation}")
            return None

        # Get the value of x1 at the invocation of MSHookMessageEx().
        # It will be the selector name
        invocation_instr = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        sel_value = self.get_register_contents_at_instruction(
            function_analyzer, "x1", invocation_instr, strongarm=False
        )
        if not sel_value or sel_value.type != RegisterContentsType.IMMEDIATE:
            logging.debug(f"Selector not found in x1 for {class_name} for {invocation}")
            return None

        # Get the selector name string
        selector_name = self.string_from_literal_or_selref_address(sel_value.value)
        if not selector_name:
            logging.debug(f"Failed to read the selector name at {sel_value.value} for {class_name} / {invocation}")
            return None

        # Get the replacement function provided in arg 3
        # It will be in x2 at the invocation of MSHookMessageEx()
        replacement_func_reg = self.get_register_contents_at_instruction(
            function_analyzer,
            "x2",
            invocation_instr,
            strongarm=False,
        )
        if not replacement_func_reg or replacement_func_reg.type != RegisterContentsType.IMMEDIATE:
            logging.debug(f"Replacement function not found in x1 for {class_name} {selector_name}")
            return None

        # Get the ptr to the original IMP provided in arg 4
        original_func_reg = self.get_register_contents_at_instruction(
            function_analyzer,
            "x3",
            invocation_instr,
            strongarm=False,
        )

        original_func_addr = 0
        if original_func_reg and original_func_reg.type == RegisterContentsType.IMMEDIATE:
            original_func_addr = original_func_reg.value
        else:
            logging.debug(f"Original function not found in x1 for {class_name} {selector_name}")

        return Hook(
            target=ObjectiveCTarget(
                class_name=class_name,
                method_name=selector_name,
            ),
            replacement_address=replacement_func_reg.value,
            original_address=original_func_addr,
            callsite_address=int(invocation.caller_addr),
        )
