from tests.compiler import SnippetCompiler
from tweakinspect.models import Hook, ObjectiveCTarget


class TestInternalLogosHooks:
    def test_one_hook_no_args(self) -> None:
        source_code = """
        %hook SBUIController
        - (void)_handleEvent:(id)event {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SBUIController"
            assert hook.target.method_name == "_handleEvent:"
            assert executable.symbol_contains_address("__logosLocalInit", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol(
                "__logos_method$_ungrouped$SBUIController$_handleEvent$"
            )
            assert hook.original_address == executable.address_of_symbol(
                "__logos_orig$_ungrouped$SBUIController$_handleEvent$"
            )
            assert str(hook) == "%hook -[SBUIController _handleEvent:]"

    def test_one_hook_with_args(self) -> None:
        source_code = """
        %hook UIView
        - (void)addSubview:(UIView *)view {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "UIView"
            assert hook.target.method_name == "addSubview:"
            assert executable.symbol_contains_address("__logosLocalInit", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol(
                "__logos_method$_ungrouped$UIView$addSubview$"
            )
            assert hook.original_address == executable.address_of_symbol("__logos_orig$_ungrouped$UIView$addSubview$")
            assert str(hook) == "%hook -[UIView addSubview:]"

    def test_multiple_hooks_no_args(self) -> None:
        source_code = """
        %hook UIApplication
        - (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(id)launchOptions { return YES; }
        %end

        %hook UIWindow
        - (void)_rotateWindowToOrientation:(int)orientation updateStatusBar:(BOOL)updateStatusBar {}
        %end

        %hook backboardd
        - (void)reboot {}
        %end
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code, generator="internal") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "UIApplication"
            assert hook1.target.method_name == "application:didFinishLaunchingWithOptions:"
            assert executable.symbol_contains_address("__logosLocalInit", hook1.callsite_address)
            assert hook1.replacement_address == executable.address_of_symbol(
                "__logos_method$_ungrouped$UIApplication$application$didFinishLaunchingWithOptions$"
            )
            assert hook1.original_address == executable.address_of_symbol(
                "__logos_orig$_ungrouped$UIApplication$application$didFinishLaunchingWithOptions$"
            )
            assert str(hook1) == "%hook -[UIApplication application:didFinishLaunchingWithOptions:]"

            hook2 = hooks[1]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "UIWindow"
            assert hook2.target.method_name == "_rotateWindowToOrientation:updateStatusBar:"
            assert executable.symbol_contains_address("__logosLocalInit", hook2.callsite_address)
            assert hook2.replacement_address == executable.address_of_symbol(
                "__logos_method$_ungrouped$UIWindow$_rotateWindowToOrientation$updateStatusBar$"
            )
            assert hook2.original_address == executable.address_of_symbol(
                "__logos_orig$_ungrouped$UIWindow$_rotateWindowToOrientation$updateStatusBar$"
            )
            assert str(hook2) == "%hook -[UIWindow _rotateWindowToOrientation:updateStatusBar:]"

            hook3 = hooks[2]
            assert isinstance(hook3.target, ObjectiveCTarget)
            assert hook3.target.class_name == "backboardd"
            assert hook3.target.method_name == "reboot"
            assert executable.symbol_contains_address("__logosLocalInit", hook3.callsite_address)
            assert hook3.replacement_address == executable.address_of_symbol(
                "__logos_method$_ungrouped$backboardd$reboot"
            )
            assert hook3.original_address == executable.address_of_symbol("__logos_orig$_ungrouped$backboardd$reboot")
            assert str(hook3) == "%hook -[backboardd reboot]"
