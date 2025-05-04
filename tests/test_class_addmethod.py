from tests.compiler import SnippetCompiler
from tweakinspect.executable import Executable
from tweakinspect.models import Hook, ObjectiveCTarget


class TestClassAddMethod:
    def test_one_method_no_args(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        #import <objc/runtime.h>

        @interface CustomViewController : NSObject
        @end

        void newCustomMethod(id self, SEL _cmd) { }

        __attribute__((constructor)) static void initialize(void) {
            Class cls = objc_getClass("CustomViewController");
            class_addMethod(cls, @selector(customMethod), (IMP)newCustomMethod, "v@:");
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "CustomViewController"
            assert hook.target.method_name == "customMethod"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address == 0
            assert str(hook) == "%new -[CustomViewController customMethod]"

    def test_one_method_with_args(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        #import <objc/runtime.h>

        @interface CustomTableView : NSObject
        @end

        void newCustomCellForRow(id self, SEL _cmd, NSIndexPath *indexPath, id tableView) { }

        __attribute__((constructor)) static void initialize(void) {
            Class cls = objc_getClass("CustomTableView");
            SEL selector = @selector(customCellForRowAtIndexPath:inTableView:);
            class_addMethod(cls, selector, (IMP)newCustomCellForRow, "v@:@@");
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, ObjectiveCTarget)
            assert hook.target.class_name == "CustomTableView"
            assert hook.target.method_name == "customCellForRowAtIndexPath:inTableView:"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address == 0
            assert str(hook) == "%new -[CustomTableView customCellForRowAtIndexPath:inTableView:]"

    def test_multiple_methods(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        #import <objc/runtime.h>

        @interface CustomNetworkManager : NSObject
        @end

        @interface CustomAnimator : NSObject
        @end

        @interface CustomLocationManager : NSObject
        @end

        void newFetchData(id self, SEL _cmd) {}
        void newAnimateView(id self, SEL _cmd, id view, CGFloat duration) {}
        void newUpdateLocation(id self, SEL _cmd, id location) {}

        __attribute__((constructor)) static void initialize(void) {
            class_addMethod(objc_getClass("CustomNetworkManager"), @selector(fetchDataFromAPI), (IMP)newFetchData, "v@:");
            class_addMethod(objc_getClass("CustomAnimator"), @selector(animateView:withDuration:), (IMP)newAnimateView, "v@:@d");
            class_addMethod(objc_getClass("CustomLocationManager"), @selector(updateWithLocation:), (IMP)newUpdateLocation, "v@:@");            
        }
        """
        with SnippetCompiler(source_code=source_code, generator="internal") as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, ObjectiveCTarget)
            assert hook1.target.class_name == "CustomAnimator"
            assert hook1.target.method_name == "animateView:withDuration:"
            assert hook1.callsite_address >= 0x4000
            assert hook1.replacement_address >= 0x4000
            assert hook1.original_address == 0
            assert str(hook1) == "%new -[CustomAnimator animateView:withDuration:]"

            hook2 = hooks[1]
            assert isinstance(hook2.target, ObjectiveCTarget)
            assert hook2.target.class_name == "CustomLocationManager"
            assert hook2.target.method_name == "updateWithLocation:"
            assert hook2.callsite_address >= 0x4000
            assert hook2.replacement_address >= 0x4000
            assert hook2.original_address == 0
            assert str(hook2) == "%new -[CustomLocationManager updateWithLocation:]"

            hook3 = hooks[2]
            assert isinstance(hook3.target, ObjectiveCTarget)
            assert hook3.target.class_name == "CustomNetworkManager"
            assert hook3.target.method_name == "fetchDataFromAPI"
            assert hook3.callsite_address >= 0x4000
            assert hook3.replacement_address >= 0x4000
            assert hook3.original_address == 0
            assert str(hook3) == "%new -[CustomNetworkManager fetchDataFromAPI]"
