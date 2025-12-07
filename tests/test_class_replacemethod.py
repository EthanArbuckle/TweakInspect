from tests.compiler import SnippetCompiler
from tweakinspect.models import Hook, ObjectiveCTarget


class TestClassReplaceMethod:
    def test_one_hook_no_args(self) -> None:
        source_code = """
        #import <objc/runtime.h>

        @interface SpringBoard : NSObject
        - (void)test;
        @end

        void newTest(id self, SEL _cmd) { }

        __attribute__((constructor)) void initialize(void) {
            Class cls = objc_getClass("SpringBoard");
            class_replaceMethod(cls, @selector(test), (IMP)newTest, "v@:");
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SpringBoard"
            assert hook.target.method_name == "test"
            assert executable.symbol_contains_address("_initialize", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_newTest")
            assert hook.original_address == 0
            assert str(hook) == "%hook -[SpringBoard test]"

    def test_one_hook_with_args(self) -> None:
        source_code = """
        #import <objc/runtime.h>

        @interface SpringBoard : NSObject
        - (void)initWithStuff:(id)stuff andThings:(id)things;
        @end

        void newInit(id self, SEL _cmd, id stuff, id things) { }

        __attribute__((constructor)) void initialize(void) {
            Class cls = objc_getClass("SpringBoard");
            class_replaceMethod(cls, @selector(initWithObject1:andObject2:), (IMP)newInit, "v@:@@");
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SpringBoard"
            assert hook.target.method_name == "initWithObject1:andObject2:"
            assert executable.symbol_contains_address("_initialize", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_newInit")
            assert hook.original_address == 0
            assert str(hook) == "%hook -[SpringBoard initWithObject1:andObject2:]"

    def test_multiple_hooks(self) -> None:
        source_code = """
        #import <objc/runtime.h>

        @interface NotificationCenter : NSObject
        - (void)removeAllObservers;
        @end

        @interface CarPlay : NSObject
        - (void)setupDock;
        @end

        @interface backboardd : NSObject
        - (void)reboot;
        @end

        void newRemoveAllObservers(id self, SEL _cmd) {}
        void newSetupDock(id self, SEL _cmd) {}
        void newReboot(id self, SEL _cmd) {}

        __attribute__((constructor)) void initialize(void) {
            class_replaceMethod(objc_getClass("NotificationCenter"), @selector(removeAllObservers), (IMP)newRemoveAllObservers, "v@:");
            class_replaceMethod(objc_getClass("CarPlay"), @selector(setupDock), (IMP)newSetupDock, "v@:");
            class_replaceMethod(objc_getClass("backboardd"), @selector(reboot), (IMP)newReboot, "v@:");
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code, generator="internal") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "CarPlay"
            assert hook1.target.method_name == "setupDock"
            assert executable.symbol_contains_address("_initialize", hook1.callsite_address)
            assert hook1.replacement_address == executable.address_of_symbol("_newSetupDock")
            assert hook1.original_address == 0
            assert str(hook1) == "%hook -[CarPlay setupDock]"

            hook2 = hooks[1]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "NotificationCenter"
            assert hook2.target.method_name == "removeAllObservers"
            assert executable.symbol_contains_address("_initialize", hook2.callsite_address)
            assert hook2.replacement_address == executable.address_of_symbol("_newRemoveAllObservers")
            assert hook2.original_address == 0
            assert str(hook2) == "%hook -[NotificationCenter removeAllObservers]"

            hook3 = hooks[2]
            assert isinstance(hook3.target, ObjectiveCTarget)
            assert hook3.target.class_name == "backboardd"
            assert hook3.target.method_name == "reboot"
            assert executable.symbol_contains_address("_initialize", hook3.callsite_address)
            assert hook3.replacement_address == executable.address_of_symbol("_newReboot")
            assert hook3.original_address == 0
            assert str(hook3) == "%hook -[backboardd reboot]"

    def test_dlsym_class_replacemethod(self) -> None:
        source_code = """
            #include <dlfcn.h>
            #include <objc/runtime.h>

            @interface SBIconController : NSObject
            - (void)reloadIcons;
            @end

            void hooked_reloadIcons(id self, SEL _cmd) { }

            __attribute__((constructor)) void tweak_init(void) {
                void *libobjc = dlopen("/usr/lib/libobjc.A.dylib", RTLD_LAZY);
                void *_class_replaceMethod = dlsym(libobjc, "class_replaceMethod");
                if (_class_replaceMethod) {
                    Class cls = objc_getClass("SBIconController");
                    SEL selector = sel_registerName("reloadIcons");
                    ((IMP (*)(Class, SEL, IMP, const char *))_class_replaceMethod)(cls, selector, (IMP)hooked_reloadIcons, "v@:");
                }
            }
            """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SBIconController"
            assert hook.target.method_name == "reloadIcons"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_hooked_reloadIcons")
            assert hook.original_address == 0
            assert str(hook) == "%hook -[SBIconController reloadIcons]"

    def test_MSFindSymbol_class_replacemethod(self) -> None:
        source_code = """
            #include <objc/runtime.h>

            @interface SBIconController : NSObject
            - (void)reloadIcons;
            @end

            void hooked_reloadIcons(id self, SEL _cmd) { }

            __attribute__((constructor)) void tweak_init(void) {
                MSImageRef libobjc = MSGetImageByName("/usr/lib/libobjc.A.dylib");
                void *_class_replaceMethod = MSFindSymbol(libobjc, "class_replaceMethod");
                if (_class_replaceMethod) {
                    Class cls = objc_getClass("SBIconController");
                    SEL selector = sel_registerName("reloadIcons");
                    ((IMP (*)(Class, SEL, IMP, const char *))_class_replaceMethod)(cls, selector, (IMP)hooked_reloadIcons, "v@:");
                }
            }
            """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SBIconController"
            assert hook.target.method_name == "reloadIcons"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_hooked_reloadIcons")
            assert hook.original_address == 0
            assert str(hook) == "%hook -[SBIconController reloadIcons]"

    def test_class_replacemethod_save_original(self) -> None:
        source_code = """
        #import <objc/runtime.h>

        @interface SpringBoard : NSObject
        - (void)test;
        @end

        IMP original_test_imp = NULL;
        void newTest(id self, SEL _cmd) { }

        __attribute__((constructor)) void initialize(void) {
            Class cls = objc_getClass("SpringBoard");
            original_test_imp = class_replaceMethod(cls, @selector(test), (IMP)newTest, "v@:");
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "SpringBoard"
            assert hook.target.method_name == "test"
            assert executable.symbol_contains_address("_initialize", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_newTest")
            assert hook.original_address == executable.address_of_symbol("_original_test_imp")
            assert str(hook) == "%hook -[SpringBoard test]"
