from tests.compiler import SnippetCompiler
from tweakinspect.executable import Executable
from tweakinspect.models import Hook, ObjectiveCTarget


class TestMsHookMessageEx:
    def test_one_hook_no_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)test {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SpringBoard"
            assert hook.target.method_name == "test"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address >= 0x4000
            assert str(hook) == "%hook -[SpringBoard test]"

    def test_one_hook_with_args(self) -> None:
        source_code = """
        %hook SpringBoard
        - (void)initWithStuff:(id)stuff andThings:(id)things {}
        %end
        """
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SpringBoard"
            assert hook.target.method_name == "initWithStuff:andThings:"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address >= 0x4000
            assert str(hook) == "%hook -[SpringBoard initWithStuff:andThings:]"

    def test_multiple_hooks_no_args(self) -> None:
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
        with SnippetCompiler(source_code=source_code, generator="MobileSubstrate") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "CarPlay"
            assert hook1.target.method_name == "setupDock"
            assert hook1.callsite_address >= 0x4000
            assert hook1.replacement_address >= 0x4000
            assert hook1.original_address >= 0x4000
            assert str(hook1) == "%hook -[CarPlay setupDock]"

            hook2 = hooks[1]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "SpringBoard"
            assert hook2.target.method_name == "launchHomescreen"
            assert hook2.callsite_address >= 0x4000
            assert hook2.replacement_address >= 0x4000
            assert hook2.original_address >= 0x4000
            assert str(hook2) == "%hook -[SpringBoard launchHomescreen]"

            hook3 = hooks[2]
            assert isinstance(hook3.target, ObjectiveCTarget)
            assert hook3.target.class_name == "backboardd"
            assert hook3.target.method_name == "reboot"
            assert hook3.callsite_address >= 0x4000
            assert hook3.replacement_address >= 0x4000
            assert hook3.original_address >= 0x4000
            assert str(hook3) == "%hook -[backboardd reboot]"

    def test_dlsym_mshookmessageex(self) -> None:
        source_code = """
            #include <dlfcn.h>
            #include <objc/runtime.h>
            #import <Foundation/Foundation.h>

            static IMP orig_layoutIcons;

            void new_layoutIcons(id self, SEL _cmd) {
                return;
            }

            %ctor {
                void *substrate = dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY);
                void *_MSHookMessageEx = dlsym(substrate, "MSHookMessageEx");
                if (_MSHookMessageEx) {
                    Class targetClass = objc_getClass("SBHomeScreenView");
                    SEL targetSel = sel_registerName("layoutIcons");
                    ((void (*)(Class, SEL, IMP, IMP *))_MSHookMessageEx)(targetClass, targetSel, (IMP)new_layoutIcons, &orig_layoutIcons);
                }
            }
            """  # noqa E501
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SBHomeScreenView"
            assert hook.target.method_name == "layoutIcons"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address >= 0x4000
            assert str(hook) == "%hook -[SBHomeScreenView layoutIcons]"
