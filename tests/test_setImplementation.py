from pathlib import Path

from tests.compiler import SnippetCompiler
from tweakinspect.executable import Executable
from tweakinspect.models import Hook, ObjectiveCTarget


class TestSetImplementation:
    def test_one_hook_no_args_nsselectorfromstring(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        void new_viewDidLoad(id _self, SEL __cmd) {}
        %ctor {
            Class viewClass = objc_getClass("UIView");
            Method methodToHook = class_getInstanceMethod(viewClass, NSSelectorFromString(@"viewDidLoad"));
            method_setImplementation(methodToHook, (IMP)new_viewDidLoad);
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "UIView"
            assert hook.target.method_name == "viewDidLoad"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address == 0
            assert str(hook) == "%hook -[UIView viewDidLoad]"

    def test_one_hook_no_args_sel_registername(self) -> None:
        source_code = """
        void new_method(id _self, SEL __cmd) {}
        %ctor {
            Class viewClass = objc_getClass("UIView");
            Method methodToHook = class_getInstanceMethod(viewClass, sel_registerName("removeFromSuperview"));
            method_setImplementation(methodToHook, (IMP)new_method);
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "UIView"
            assert hook.target.method_name == "removeFromSuperview"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address == 0
            assert str(hook) == "%hook -[UIView removeFromSuperview]"

    def test_multiple_hooks_no_args_nsselectorfromstring(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        void new_viewDidLoad(id _self, SEL __cmd) {}
        void new_removeFromSuperview(id _self, SEL __cmd) {}
        %ctor {
            Class viewClass = objc_getClass("UIView");
            Method methodToHook = class_getInstanceMethod(viewClass, NSSelectorFromString(@"viewDidLoad"));
            method_setImplementation(methodToHook, (IMP)new_viewDidLoad);

            Method methodToHook2 = class_getInstanceMethod(viewClass, NSSelectorFromString(@"removeFromSuperview"));
            method_setImplementation(methodToHook2, (IMP)new_removeFromSuperview);

            Class SBClass = objc_getClass("SpringBoard");
            methodToHook = class_getInstanceMethod(SBClass, NSSelectorFromString(@"init"));
            method_setImplementation(methodToHook, (IMP)new_removeFromSuperview);
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "SpringBoard"
            assert hook1.target.method_name == "init"
            assert hook1.callsite_address >= 0x4000
            assert hook1.replacement_address >= 0x4000
            assert hook1.original_address == 0
            assert str(hook1) == "%hook -[SpringBoard init]"

            hook2 = hooks[1]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "UIView"
            assert hook2.target.method_name == "removeFromSuperview"
            assert hook2.callsite_address >= 0x4000
            assert hook2.replacement_address >= 0x4000
            assert hook2.original_address >= 0x4000
            assert str(hook2) == "%hook -[UIView removeFromSuperview]"

            hook3 = hooks[2]
            assert isinstance(hook3.target, ObjectiveCTarget)
            assert hook3.target.class_name == "UIView"
            assert hook3.target.method_name == "viewDidLoad"
            assert hook3.callsite_address >= 0x4000
            assert hook3.replacement_address >= 0x4000
            assert hook3.original_address >= 0x4000
            assert str(hook3) == "%hook -[UIView viewDidLoad]"

    def test_multiple_hooks_no_args_selregistername(self) -> None:
        source_code = """
        void new_viewDidLoad(id _self, SEL __cmd) {}
        void new_removeFromSuperview(id _self, SEL __cmd) {}
        %ctor {
            Class viewClass = objc_getClass("UIView");
            Method methodToHook = class_getInstanceMethod(viewClass, sel_registerName("viewDidLoad"));
            method_setImplementation(methodToHook, (IMP)new_viewDidLoad);

            Method methodToHook2 = class_getInstanceMethod(viewClass, sel_registerName("removeFromSuperview"));
            method_setImplementation(methodToHook2, (IMP)new_removeFromSuperview);

            Class SBClass = objc_getClass("SpringBoard");
            methodToHook = class_getInstanceMethod(SBClass, sel_registerName("init"));
            method_setImplementation(methodToHook, (IMP)new_removeFromSuperview);
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "SpringBoard"
            assert hook1.target.method_name == "init"
            assert hook1.callsite_address >= 0x4000
            assert hook1.replacement_address >= 0x4000
            assert hook1.original_address == 0
            assert str(hook1) == "%hook -[SpringBoard init]"

            hook2 = hooks[1]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "UIView"
            assert hook2.target.method_name == "removeFromSuperview"
            assert hook2.callsite_address >= 0x4000
            assert hook2.replacement_address >= 0x4000
            assert hook2.original_address >= 0x4000
            assert str(hook2) == "%hook -[UIView removeFromSuperview]"

            hook3 = hooks[2]
            assert isinstance(hook3.target, ObjectiveCTarget)
            assert hook3.target.class_name == "UIView"
            assert hook3.target.method_name == "viewDidLoad"
            assert hook3.callsite_address >= 0x4000
            assert hook3.replacement_address >= 0x4000
            assert hook3.original_address >= 0x4000
            assert str(hook3) == "%hook -[UIView viewDidLoad]"

    def test_setimp_using_block_imp(self) -> None:
        exec = Executable(file_path=Path(__file__).parent / "bin" / "test_setimp_using_block_imp.dylib")
        hooks: list[Hook] = sorted(exec.get_hooks())
        assert len(hooks) == 3

        hooks_as_dicts = [hook.to_dict() for hook in hooks]
        assert hooks_as_dicts == [
            {
                "type": "Hook",
                "target": {"type": "ObjectiveCTarget", "class_name": "RDKClient", "method_name": "userAgent"},
                "replacement_address": 0x47E8,
                "original_address": 0x7DA8,
                "callsite_address": 0x4304,
            },
            {
                "type": "Hook",
                "target": {
                    "type": "ObjectiveCTarget",
                    "class_name": "RDKOAuthCredential",
                    "method_name": "clientIdentifier",
                },
                "replacement_address": 0x4754,
                "original_address": 0x7D94,
                "callsite_address": 0x4280,
            },
            {
                "type": "Hook",
                "target": {
                    "type": "ObjectiveCTarget",
                    "class_name": "__NSCFLocalSessionTask",
                    "method_name": "_onqueue_resume",
                },
                "replacement_address": 0x7DA8,
                "original_address": 0,
                "callsite_address": 0x43B4,
            },
        ]

    def test_dlsym_method_setimplementation(self) -> None:
        source_code = """
            #include <dlfcn.h>
            #include <objc/runtime.h>
            #import <Foundation/Foundation.h>

            static IMP orig_lockDevice;

            void new_lockDevice(id self, SEL _cmd) {
                return;
            }

            %ctor {
                void *libobjc = dlopen("/usr/lib/libobjc.A.dylib", RTLD_LAZY);
                void *_method_setImplementation = dlsym(libobjc, "method_setImplementation");
                if (_method_setImplementation) {
                    Class targetClass = objc_getClass("SBLockScreenController");
                    SEL targetSel = sel_registerName("lockDevice");
                    Method method = class_getInstanceMethod(targetClass, targetSel);
                    orig_lockDevice = ((IMP (*)(Method, IMP))_method_setImplementation)(method, (IMP)new_lockDevice);
                }
            }
            """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SBLockScreenController"
            assert hook.target.method_name == "lockDevice"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address >= 0x4000
            assert str(hook) == "%hook -[SBLockScreenController lockDevice]"
