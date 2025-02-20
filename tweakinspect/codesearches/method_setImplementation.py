import logging

from strongarm.macho import CallerXRef
from strongarm.objc import ObjcFunctionAnalyzer, ObjcInstruction, RegisterContentsType

from tweakinspect.codesearch import FunctionHookCodeSearchOperation
from tweakinspect.models import Hook, ObjectiveCTarget


class MethodSetImpCodeSearchOperation(FunctionHookCodeSearchOperation):
    def analyze(self) -> list[Hook]:

        # Find the address of method_setImplementation()
        method_setImplementation_addr = self.address_for_symbol_name_in_executable("_method_setImplementation")
        if not method_setImplementation_addr:
            # The binary does not use method_setImplementation()
            return []

        # Analyze every invocation of method_setImplementation()
        invocations = self.macho_analyzer.calls_to(method_setImplementation_addr)
        results: list[Hook] = []
        for invocation_idx, invocation in enumerate(invocations):
            result = self.analyze_invocation(invocation, invocation_idx)
            if result:
                results.append(result)
        return results

    def analyze_invocation(self, invocation: CallerXRef, invocation_idx: int) -> Hook | None:
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            self.executable.binary, invocation.caller_func_start_address
        )

        # Look for an objc_getClass() call before method_setImplementation()
        getClass_invocation = self.last_invocation_of_function(
            function_analyzer, "objc_getClass", invocation.caller_addr
        )
        if not getClass_invocation:
            logging.info(f"Did not find objc_getClass() before for invocation {invocation}")
            return None

        # Get the value of x0 at the invocation of objc_getClass().
        # It will be the class name
        class_name = self.read_string_from_register(function_analyzer, "x0", getClass_invocation)
        if not class_name:
            logging.info(f"Failed to read the class name at {getClass_invocation} for {invocation}")
            return None

        # The second arg is a Method. Look for calls to getInstanceMethod/getClassMethod
        getMethod_invocations = self.find_calls_to_function_before_address(
            function_analyzer, "class_getInstanceMethod", invocation.caller_addr
        )
        getMethod_invocations += self.find_calls_to_function_before_address(
            function_analyzer, "class_getClassMethod", invocation.caller_addr
        )
        if not len(getMethod_invocations):
            logging.debug(f"Did not find calls to class_getInstanceMethod or class_getClassMethod for {invocation}")
            return None

        # Find the class_get*Method() call that is closest (but not after) the method_setImplementation() call
        closest_getMethod_invocation: ObjcInstruction | None = None
        shorted_distance_to_invocation = 0xFFFFFFFF
        for getMethod_invocation in getMethod_invocations:
            if getMethod_invocation.address < invocation.caller_addr:
                distance = invocation.caller_addr - getMethod_invocation.address
                if distance < shorted_distance_to_invocation:
                    shorted_distance_to_invocation = distance
                    closest_getMethod_invocation = getMethod_invocation

        if not closest_getMethod_invocation:
            logging.debug(f"Could not find a getMethod call before method_setImplementation for {class_name}")
            return None

        # Get the value of x1 at the invocation of class_getInstanceMethod().
        # It will be the selector name
        sel_value = self.get_register_contents_at_instruction(
            function_analyzer, "x1", closest_getMethod_invocation.raw_instr, strongarm=False
        )
        if not sel_value or sel_value.type != RegisterContentsType.IMMEDIATE:
            return None

        # Get the selector name string
        selector_name = self.string_from_literal_or_selref_address(sel_value.value)
        if not selector_name:
            return None

        # Get the replacement IMP provided in arg 2.
        # It will be in x1 at the invocation of method_setImplementation()
        invocation_instr = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        replacement_imp_reg = self.get_register_contents_at_instruction(
            function_analyzer,
            "x1",
            invocation_instr,
            strongarm=False,
        )
        if not replacement_imp_reg or replacement_imp_reg.type != RegisterContentsType.IMMEDIATE:
            logging.debug(f"Replacement imp not found in x1 register for {class_name} {selector_name}")
            return None

        replacement_imp_address = self.resolve_block_imp(replacement_imp_reg.value)
        return Hook(
            target=ObjectiveCTarget(
                class_name=class_name,
                method_name=selector_name,
            ),
            replacement_address=replacement_imp_address,
            original_address=0,
            callsite_address=int(invocation.caller_addr),
        )
