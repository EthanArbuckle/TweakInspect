import logging

from strongarm.macho import CallerXRef
from strongarm.objc import ObjcFunctionAnalyzer, RegisterContentsType

from tweakinspect.codesearch import FunctionHookCodeSearchOperation
from tweakinspect.models import Hook, ObjectiveCTarget


class ClassReplaceMethodCodeSearchOperation(FunctionHookCodeSearchOperation):

    FUNCTION_TO_FIND = "_class_replaceMethod"

    def analyze_invocation(self, invocation: CallerXRef) -> Hook | None:
        function_analyzer = ObjcFunctionAnalyzer.get_function_analyzer(
            self.executable.binary, invocation.caller_func_start_address
        )

        # Look for an objc_getClass() call before the invocation site
        getClass_invocation = self.last_invocation_of_function(
            function_analyzer, "objc_getClass", invocation.caller_addr
        )
        if not getClass_invocation:
            logging.debug(f"Did not find objc_getClass() before for invocation {invocation}")
            return None

        # Get the class from from x0
        class_name = self.read_string_from_register(function_analyzer, "x0", getClass_invocation)
        if not class_name:
            logging.debug(f"Failed to read the class name at {getClass_invocation} for {invocation}")
            return None

        # Get the selector name from x1
        invocation_instr = function_analyzer.get_instruction_at_address(invocation.caller_addr)
        sel_value = self.get_register_contents_at_instruction(
            function_analyzer, "x1", invocation_instr, strongarm=False
        )
        if not sel_value or sel_value.type != RegisterContentsType.IMMEDIATE:
            logging.debug(f"Selector not found in x1 for {class_name} for {invocation}")
            return None

        # Get the selref's string
        selector_name = self.string_from_literal_or_selref_address(sel_value.value)
        if not selector_name:
            logging.debug(f"Failed to read the selector name at {sel_value.value} for {class_name} / {invocation}")
            return None

        # Get the replacement IMP in x2
        replacement_func_reg = self.get_register_contents_at_instruction(
            function_analyzer,
            "x2",
            invocation_instr,
            strongarm=False,
        )
        if not replacement_func_reg or replacement_func_reg.type != RegisterContentsType.IMMEDIATE:
            logging.debug(f"Replacement function not found in x2 for {class_name} {selector_name}")
            return None

        return Hook(
            target=ObjectiveCTarget(
                class_name=class_name,
                method_name=selector_name,
            ),
            replacement_address=replacement_func_reg.value,
            original_address=0,
            callsite_address=int(invocation.caller_addr),
        )
