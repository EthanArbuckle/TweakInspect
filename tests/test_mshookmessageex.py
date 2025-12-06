from tests.compiler import SnippetCompiler
from tweakinspect.models import Hook, ObjectiveCTarget


class TestMSHookMessageEx:
    def test_mshookmessageex_hook_no_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)test {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SpringBoard"
            assert hook.target.method_name == "test"
            assert executable.symbol_contains_address("__logosLocalInit", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol(
                "__logos_method$_ungrouped$SpringBoard$test"
            )
            assert hook.original_address == executable.address_of_symbol("__logos_orig$_ungrouped$SpringBoard$test")
            assert str(hook) == "%hook -[SpringBoard test]"

    def test_mshookmessageex_one_hook_with_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)initWithStuff:(id)stuff andThings:(id)things {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SpringBoard"
            assert hook.target.method_name == "initWithStuff:andThings:"
            assert executable.symbol_contains_address("__logosLocalInit", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol(
                "__logos_method$_ungrouped$SpringBoard$initWithStuff$andThings$"
            )
            assert hook.original_address == executable.address_of_symbol(
                "__logos_orig$_ungrouped$SpringBoard$initWithStuff$andThings$"
            )
            assert str(hook) == "%hook -[SpringBoard initWithStuff:andThings:]"

    def test_mshookmessageex_multiple_hooks_no_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)launchHomescreen {}
        %end
        %hook CarPlay
        - (void)setupDock {}
        %end
        %hook backboardd
        - (void)reboot {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "CarPlay"
            assert hook1.target.method_name == "setupDock"
            assert executable.symbol_contains_address("__logosLocalInit", hook1.callsite_address)
            assert hook1.replacement_address == executable.address_of_symbol(
                "__logos_method$_ungrouped$CarPlay$setupDock"
            )
            assert hook1.original_address == executable.address_of_symbol("__logos_orig$_ungrouped$CarPlay$setupDock")
            assert str(hook1) == "%hook -[CarPlay setupDock]"

            hook2 = hooks[1]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "SpringBoard"
            assert hook2.target.method_name == "launchHomescreen"
            assert executable.symbol_contains_address("__logosLocalInit", hook2.callsite_address)
            assert hook2.replacement_address == executable.address_of_symbol(
                "__logos_method$_ungrouped$SpringBoard$launchHomescreen"
            )
            assert hook2.original_address == executable.address_of_symbol(
                "__logos_orig$_ungrouped$SpringBoard$launchHomescreen"
            )
            assert str(hook2) == "%hook -[SpringBoard launchHomescreen]"

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

    def test_dlsym_mshookmessageex(self) -> None:
        source_code = """
            #include <dlfcn.h>
            #include <objc/runtime.h>

            IMP orig_layoutIcons = NULL;
            void new_layoutIcons(id self, SEL _cmd) {
                return;
            }

            __attribute__((constructor)) void tweak_init(void) {
                void *substrate = dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY);
                void *_MSHookMessageEx = dlsym(substrate, "MSHookMessageEx");
                if (_MSHookMessageEx) {
                    Class targetClass = objc_getClass("SBHomeScreenView");
                    SEL targetSel = sel_registerName("layoutIcons");
                    ((void (*)(Class, SEL, IMP, IMP *))_MSHookMessageEx)(targetClass, targetSel, (IMP)new_layoutIcons, &orig_layoutIcons);
                }
            }
            """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SBHomeScreenView"
            assert hook.target.method_name == "layoutIcons"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_new_layoutIcons")
            assert hook.original_address == executable.address_of_symbol("_orig_layoutIcons")
            assert str(hook) == "%hook -[SBHomeScreenView layoutIcons]"
