from tests.compiler import SnippetCompiler
from tweakinspect.executable import Executable
from tweakinspect.models import FunctionTarget, Hook


class TestMsHookFunction:
    def test_hookf_linked_function(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        %hookf(FILE *, fopen, const char *path, const char *mode) {
            return NULL;
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "fopen"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address == 0
            assert str(hook) == "%hookf fopen()"

    def test_multiple_hookf_linked_functions(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        %hookf(FILE *, fopen, const char *path, const char *mode) {
            return NULL;
        }
        %hookf(int, fclose, FILE *file) {
            return 0;
        }
        %hookf(int, fseek, FILE *file, int offset, int position) {
            return 0;
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "fclose"
            assert hook1.callsite_address >= 0x4000
            assert hook1.replacement_address >= 0x4000
            assert hook1.original_address == 0
            assert str(hook1) == "%hookf fclose()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "fopen"
            assert hook2.callsite_address >= 0x4000
            assert hook2.replacement_address >= 0x4000
            assert hook2.original_address == 0
            assert str(hook2) == "%hookf fopen()"

            hook3 = hooks[2]
            assert isinstance(hook3.target, FunctionTarget)
            assert hook3.target.target_function_name == "fseek"
            assert hook3.callsite_address >= 0x4000
            assert hook3.replacement_address >= 0x4000
            assert hook3.original_address == 0
            assert str(hook3) == "%hookf fseek()"

    # def test_hookf_dynamic_lookup(self) -> None:
    #     source_code = """
    #     #import <Foundation/Foundation.h>
    #     %hookf(FILE *, "dynamicSymbol", const char *path, const char *mode) {
    #         return NULL;
    #     }
    #     """
    #     with SnippetCompiler(source_code=source_code) as compiled_binary:
    #         exec = Executable(file_path=compiled_binary)
    #         assert exec.get_hooks() == ["%hookf dynamicSymbol()"]

    # def test_multiple_hookf_dynamic_lookups(self) -> None:
    #     source_code = """
    #     #import <Foundation/Foundation.h>
    #     %hookf(int, "add", int a, int b) {
    #         return 0;
    #     }
    #     %hookf(int, "sub", int a, int b) {
    #         return 0;
    #     }
    #     %hookf(int, "mult", int a, int b) {
    #         return 0;
    #     }
    #     """
    #     with SnippetCompiler(source_code=source_code) as compiled_binary:
    #         exec = Executable(file_path=compiled_binary)
    #         assert exec.get_hooks() == ["%hookf add()", "%hookf sub()", "%hookf mult()"]

    def test_mshookfunction_linked_function(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        int hooked_close(int fd) {
            return 0;
        }
        %ctor {
            MSHookFunction((void *)close, (void *)hooked_close, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "close"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address == 0
            assert str(hook) == "%hookf close()"

    def test_multiple_mshookfunction_linked_functions(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        int hooked_open(int fd) {
            return 0;
        }
        %ctor {
            MSHookFunction((void *)open, (void *)hooked_open, NULL);
        }
        int hooked_close(int fd) {
            return 0;
        }
        %ctor {
            MSHookFunction((void *)close, (void *)hooked_close, NULL);
        }
        int hooked_lseek(int fd) {
            return 0;
        }
        %ctor {
            MSHookFunction((void *)lseek, (void *)hooked_lseek, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "close"
            assert hook1.callsite_address >= 0x4000
            assert hook1.replacement_address >= 0x4000
            assert hook1.original_address == 0
            assert str(hook1) == "%hookf close()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "lseek"
            assert hook2.callsite_address >= 0x4000
            assert hook2.replacement_address >= 0x4000
            assert hook2.original_address == 0
            assert str(hook2) == "%hookf lseek()"

            hook3 = hooks[2]
            assert isinstance(hook3.target, FunctionTarget)
            assert hook3.target.target_function_name == "open"
            assert hook3.callsite_address >= 0x4000
            assert hook3.replacement_address >= 0x4000
            assert hook3.original_address == 0
            assert str(hook3) == "%hookf open()"

    def test_mshookfunction_msfindsymbol(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        CFBooleanRef (*orig_MGGetBoolAnswer)(CFStringRef);
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return orig_MGGetBoolAnswer(string);
        }
        %ctor {
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, (void **)&orig_MGGetBoolAnswer);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "MGGetBoolAnswer"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address == 0
            assert str(hook) == "%hookf MGGetBoolAnswer()"

    def test_multiple_mshookfunction_msfindsymbol(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return kCFBooleanTrue;
        }
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return kCFBooleanFalse;
        }
        %ctor {
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, NULL);
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 2

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "MGCopyAnswer"
            assert hook1.callsite_address >= 0x4000
            assert hook1.replacement_address >= 0x4000
            assert hook1.original_address == 0
            assert str(hook1) == "%hookf MGCopyAnswer()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "MGGetBoolAnswer"
            assert hook2.callsite_address >= 0x4000
            assert hook2.replacement_address >= 0x4000
            assert hook2.original_address == 0
            assert str(hook2) == "%hookf MGGetBoolAnswer()"

    def test_mshookfunction_dlsym(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        #include <dlfcn.h>
        CFBooleanRef (*orig_MGCopyAnswer)(CFStringRef);
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return orig_MGCopyAnswer(string);
        }
        %ctor {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "MGCopyAnswer"
            assert hook.callsite_address >= 0x4000
            assert hook.replacement_address >= 0x4000
            assert hook.original_address == 0
            assert str(hook) == "%hookf MGCopyAnswer()"

    def test_multiple_mshookfunction_dlsym(self) -> None:
        source_code = """
        #import <Foundation/Foundation.h>
        #include <dlfcn.h>
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return kCFBooleanTrue;
        }
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return kCFBooleanFalse;
        }
        %ctor {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, NULL);
            MSHookFunction(((void *)dlsym(handle, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 2

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "MGCopyAnswer"
            assert hook1.callsite_address >= 0x4000
            assert hook1.replacement_address >= 0x4000
            assert hook1.original_address == 0
            assert str(hook1) == "%hookf MGCopyAnswer()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "MGGetBoolAnswer"
            assert hook2.callsite_address >= 0x4000
            assert hook2.replacement_address >= 0x4000
            assert hook2.original_address == 0
            assert str(hook2) == "%hookf MGGetBoolAnswer()"

    def test_hookf_mshookfunction_dlsym_msfindsymbol(self) -> None:
        source_code = """
        #include <dlfcn.h>
        #import <Foundation/Foundation.h>
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return kCFBooleanTrue;
        }
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return kCFBooleanFalse;
        }
        %hookf(int, fclose, FILE *file) {
            return 0;
        }
        %ctor {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, NULL);
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as compiled_binary:
            exec = Executable(file_path=compiled_binary)
            hooks: list[Hook] = sorted(exec.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "MGCopyAnswer"
            assert hook1.callsite_address >= 0x4000
            assert hook1.replacement_address >= 0x4000
            assert hook1.original_address == 0
            assert str(hook1) == "%hookf MGCopyAnswer()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "MGGetBoolAnswer"
            assert hook2.callsite_address >= 0x4000
            assert hook2.replacement_address >= 0x4000
            assert hook2.original_address == 0
            assert str(hook2) == "%hookf MGGetBoolAnswer()"

            hook3 = hooks[2]
            assert isinstance(hook3.target, FunctionTarget)
            assert hook3.target.target_function_name == "fclose"
            assert hook3.callsite_address >= 0x4000
            assert hook3.replacement_address >= 0x4000
            assert hook3.original_address == 0
            assert str(hook3) == "%hookf fclose()"
