from tests.compiler import SnippetCompiler
from tweakinspect.models import FunctionTarget, Hook


class TestMSHookFunction:
    def test_hookf_linked_function(self) -> None:
        source_code = """
        %hookf(FILE *, fopen, const char *path, const char *mode) {
            return NULL;
        }
        """
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "fopen"
            assert executable.symbol_contains_address("__logosLocalInit", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("__logos_function$_ungrouped$fopen")
            assert hook.original_address == executable.address_of_symbol("__logos_orig$_ungrouped$fopen")
            assert str(hook) == "%hookf fopen()"

    def test_multiple_hookf_linked_functions(self) -> None:
        source_code = """
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
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "fclose"
            assert executable.symbol_contains_address("__logosLocalInit", hook1.callsite_address)
            assert hook1.replacement_address == executable.address_of_symbol("__logos_function$_ungrouped$fclose")
            assert hook1.original_address == executable.address_of_symbol("__logos_orig$_ungrouped$fclose")
            assert str(hook1) == "%hookf fclose()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "fopen"
            assert executable.symbol_contains_address("__logosLocalInit", hook2.callsite_address)
            assert hook2.replacement_address == executable.address_of_symbol("__logos_function$_ungrouped$fopen")
            assert hook2.original_address == executable.address_of_symbol("__logos_orig$_ungrouped$fopen")
            assert str(hook2) == "%hookf fopen()"

            hook3 = hooks[2]
            assert isinstance(hook3.target, FunctionTarget)
            assert hook3.target.target_function_name == "fseek"
            assert executable.symbol_contains_address("__logosLocalInit", hook3.callsite_address)
            assert hook3.replacement_address == executable.address_of_symbol("__logos_function$_ungrouped$fseek")
            assert hook3.original_address == executable.address_of_symbol("__logos_orig$_ungrouped$fseek")
            assert str(hook3) == "%hookf fseek()"

    # def test_hookf_dynamic_lookup(self) -> None:
    #     source_code = """
    #     %hookf(FILE *, "dynamicSymbol", const char *path, const char *mode) {
    #         return NULL;
    #     }
    #     """
    #     with SnippetCompiler(source_code=source_code) as compiled_binary:
    #         exec = Executable(file_path=compiled_binary)
    #         assert exec.get_hooks() == ["%hookf dynamicSymbol()"]

    # def test_multiple_hookf_dynamic_lookups(self) -> None:
    #     source_code = """
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

    def test_mshookfunction_linked_function__no_orig(self) -> None:
        source_code = """
        int hooked_close(int fd) {
            return 0;
        }

        __attribute__((constructor)) void tweak_init(void) {
            MSHookFunction((void *)close, (void *)hooked_close, NULL);
        }
        """
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "close"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_hooked_close")
            assert hook.original_address == 0
            assert str(hook) == "%hookf close()"

    def test_multiple_mshookfunction_linked_functions(self) -> None:
        source_code = """
        int hooked_open(int fd) {
            return 0;
        }

        void *orig_close = NULL;
        int hooked_close(int fd) {
            return 0;
        }

        int hooked_lseek(int fd) {
            return 0;
        }

        __attribute__((constructor)) void tweak_init1(void) {
            MSHookFunction((void *)lseek, (void *)hooked_lseek, NULL);
        }

        __attribute__((constructor)) void tweak_init2(void) {
            MSHookFunction((void *)open, (void *)hooked_open, NULL);
            MSHookFunction((void *)close, (void *)hooked_close, &orig_close);
        }
        """
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "close"
            assert executable.symbol_contains_address("_tweak_init2", hook1.callsite_address)
            assert hook1.replacement_address == executable.address_of_symbol("_hooked_close")
            assert hook1.original_address == executable.address_of_symbol("_orig_close")
            assert str(hook1) == "%hookf close()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "lseek"
            assert executable.symbol_contains_address("_tweak_init1", hook2.callsite_address)
            assert hook2.replacement_address == executable.address_of_symbol("_hooked_lseek")
            assert hook2.original_address == 0
            assert str(hook2) == "%hookf lseek()"

            hook3 = hooks[2]

            assert isinstance(hook3.target, FunctionTarget)
            assert hook3.target.target_function_name == "open"
            assert executable.symbol_contains_address("_tweak_init2", hook3.callsite_address)
            assert hook3.replacement_address == executable.address_of_symbol("_hooked_open")
            assert hook3.original_address == 0
            assert str(hook3) == "%hookf open()"

    def test_mshookfunction_msfindsymbol(self) -> None:
        source_code = """
        CFBooleanRef (*orig_MGGetBoolAnswer)(CFStringRef) = NULL;
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return orig_MGGetBoolAnswer(string);
        }

        __attribute__((constructor)) void tweak_init(void) {
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, (void **)&orig_MGGetBoolAnswer);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "MGGetBoolAnswer"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_fixed_MGGetBoolAnswer")
            assert hook.original_address == executable.address_of_symbol("_orig_MGGetBoolAnswer")
            assert str(hook) == "%hookf MGGetBoolAnswer()"

    def test_multiple_mshookfunction_msfindsymbol(self) -> None:
        source_code = """
        void *orig_MGGetBoolAnswer = NULL;
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return kCFBooleanTrue;
        }

        void *orig_MGCopyAnswer = NULL;
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return kCFBooleanFalse;
        }

        __attribute__((constructor)) void tweak_init(void) {
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, &orig_MGGetBoolAnswer);
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, &orig_MGCopyAnswer);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 2

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "MGCopyAnswer"
            assert executable.symbol_contains_address("_tweak_init", hook1.callsite_address)
            assert hook1.replacement_address == executable.address_of_symbol("_fixed_MGCopyAnswer")
            assert hook1.original_address == executable.address_of_symbol("_orig_MGCopyAnswer")
            assert str(hook1) == "%hookf MGCopyAnswer()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "MGGetBoolAnswer"
            assert executable.symbol_contains_address("_tweak_init", hook2.callsite_address)
            assert hook2.replacement_address == executable.address_of_symbol("_fixed_MGGetBoolAnswer")
            assert hook2.original_address == executable.address_of_symbol("_orig_MGGetBoolAnswer")
            assert str(hook2) == "%hookf MGGetBoolAnswer()"

    def test_mshookfunction_dlsym(self) -> None:
        source_code = """
        #include <dlfcn.h>

        CFBooleanRef (*orig_MGCopyAnswer)(CFStringRef) = NULL;
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return orig_MGCopyAnswer(string);
        }

        __attribute__((constructor)) void tweak_init(void) {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, (void **)&orig_MGCopyAnswer);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "MGCopyAnswer"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_fixed_MGCopyAnswer")
            assert hook.original_address == executable.address_of_symbol("_orig_MGCopyAnswer")
            assert str(hook) == "%hookf MGCopyAnswer()"

    def test_multiple_mshookfunction_dlsym(self) -> None:
        source_code = """
        #include <dlfcn.h>

        void *orig_MGGetBoolAnswer = NULL;
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return kCFBooleanTrue;
        }

        void *orig_MGCopyAnswer = NULL;
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return kCFBooleanFalse;
        }

        __attribute__((constructor)) void tweak_init(void) {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, &orig_MGGetBoolAnswer);
            MSHookFunction(((void *)dlsym(handle, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, &orig_MGCopyAnswer);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 2

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "MGCopyAnswer"
            assert executable.symbol_contains_address("_tweak_init", hook1.callsite_address)
            assert hook1.replacement_address == executable.address_of_symbol("_fixed_MGCopyAnswer")
            assert hook1.original_address == executable.address_of_symbol("_orig_MGCopyAnswer")
            assert str(hook1) == "%hookf MGCopyAnswer()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "MGGetBoolAnswer"
            assert executable.symbol_contains_address("_tweak_init", hook2.callsite_address)
            assert hook2.replacement_address == executable.address_of_symbol("_fixed_MGGetBoolAnswer")
            assert hook2.original_address == executable.address_of_symbol("_orig_MGGetBoolAnswer")
            assert str(hook2) == "%hookf MGGetBoolAnswer()"

    def test_hookf_mshookfunction_dlsym_msfindsymbol(self) -> None:
        # A tweak that uses both %hookf() and manual called to MSHookFunction()
        # And the calls to MSHookFunction() don't store orig
        source_code = """
        #include <dlfcn.h>

        void *orig_MGGetBoolAnswer = NULL;
        CFBooleanRef fixed_MGGetBoolAnswer(CFStringRef string) {
            return kCFBooleanTrue;
        }

        void *orig_MGCopyAnswer = NULL;
        CFBooleanRef fixed_MGCopyAnswer(CFStringRef string) {
            return kCFBooleanFalse;
        }

        %hookf(int, fclose, FILE *file) {
            return 0;
        }

        __attribute__((constructor)) void tweak_init(void) {
            void *handle = dlopen(NULL, 0);
            MSHookFunction(((void *)dlsym(handle, "_MGGetBoolAnswer")), (void *)fixed_MGGetBoolAnswer, &orig_MGGetBoolAnswer);
            MSHookFunction(((void *)MSFindSymbol(NULL, "_MGCopyAnswer")), (void *)fixed_MGCopyAnswer, &orig_MGCopyAnswer);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 3

            hook1 = hooks[0]
            assert isinstance(hook1.target, FunctionTarget)
            assert hook1.target.target_function_name == "MGCopyAnswer"
            assert executable.symbol_contains_address("_tweak_init", hook1.callsite_address)
            assert hook1.replacement_address == executable.address_of_symbol("_fixed_MGCopyAnswer")
            assert hook1.original_address == executable.address_of_symbol("_orig_MGCopyAnswer")
            assert str(hook1) == "%hookf MGCopyAnswer()"

            hook2 = hooks[1]
            assert isinstance(hook2.target, FunctionTarget)
            assert hook2.target.target_function_name == "MGGetBoolAnswer"
            assert executable.symbol_contains_address("_tweak_init", hook2.callsite_address)
            assert hook2.replacement_address == executable.address_of_symbol("_fixed_MGGetBoolAnswer")
            assert hook2.original_address == executable.address_of_symbol("_orig_MGGetBoolAnswer")
            assert str(hook2) == "%hookf MGGetBoolAnswer()"

            hook3 = hooks[2]
            assert isinstance(hook3.target, FunctionTarget)
            assert hook3.target.target_function_name == "fclose"
            assert executable.symbol_contains_address("__logosLocalInit", hook3.callsite_address)
            assert hook3.replacement_address == executable.address_of_symbol("__logos_function$_ungrouped$fclose")
            assert hook3.original_address == executable.address_of_symbol("__logos_orig$_ungrouped$fclose")
            assert str(hook3) == "%hookf fclose()"

    def test_linked_hook_dlsym_resolves_target(self) -> None:
        source_code = """
        #include <dlfcn.h>

        void *orig_CalculatePerformExpression = NULL;
        int hooked_CalculatePerformExpression(char *expression, int a, int b, char *c) {
            return 1;
        }

        __attribute__((constructor)) void tweak_init(void) {
            void *handle = dlopen("/System/Library/PrivateFrameworks/Calculate.framework/Calculate", RTLD_LAZY);
            void *CalculatePerformExpression = dlsym(handle, "CalculatePerformExpression");
            MSHookFunction((void *)CalculatePerformExpression, (void *)hooked_CalculatePerformExpression, &orig_CalculatePerformExpression);
        }
        """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "CalculatePerformExpression"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_hooked_CalculatePerformExpression")
            assert hook.original_address == executable.address_of_symbol("_orig_CalculatePerformExpression")
            assert str(hook) == "%hookf CalculatePerformExpression()"

    def test_dlsym_resolves_both_hook_and_target(self) -> None:
        source_code = """
            #include <dlfcn.h>

            void *orig_CalculatePerformExpression = NULL;
            int hooked_CalculatePerformExpression(char *expression, int a, int b, char *c) {
                return 1;
            }

            __attribute__((constructor)) void tweak_init(void) {
                void *substrate = dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY);
                void *_MSHookFunction = dlsym(substrate, "MSHookFunction");
                if (_MSHookFunction) {
                    void *handle = dlopen("/System/Library/PrivateFrameworks/Calculate.framework/Calculate", RTLD_LAZY);
                    void *CalculatePerformExpression = dlsym(handle, "CalculatePerformExpression");

                    ((void (*)(void *, void *, void *))_MSHookFunction)((void *)CalculatePerformExpression, (void *)hooked_CalculatePerformExpression, &orig_CalculatePerformExpression);
                }
            }
            """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "CalculatePerformExpression"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_hooked_CalculatePerformExpression")
            assert hook.original_address == executable.address_of_symbol("_orig_CalculatePerformExpression")
            assert str(hook) == "%hookf CalculatePerformExpression()"

    def test_msfindsymbol_resolves_both_hook_and_target(self) -> None:
        # A tweak that uses MSFindSymbol to dynamically resolve MSHookFunction
        # And uses MSFindSymbol to dynamically resolve the function to be hooked
        source_code = """
            void *orig_CalculatePerformExpression = NULL;
            int hooked_CalculatePerformExpression(char *expression, int a, int b, char *c) {
                return 1;
            }

            __attribute__((constructor)) void tweak_init(void) {
                MSImageRef substrate = MSGetImageByName("/usr/lib/libsubstrate.dylib");
                void *_MSHookFunction = MSFindSymbol(substrate, "_MSHookFunction");
                if (_MSHookFunction) {
                    MSImageRef calculator = MSGetImageByName("/System/Library/PrivateFrameworks/Calculate.framework/Calculate");
                    void *CalculatePerformExpression = MSFindSymbol(calculator, "_CalculatePerformExpression");

                    ((void (*)(void *, void *, void *))_MSHookFunction)(CalculatePerformExpression, (void *)hooked_CalculatePerformExpression, &orig_CalculatePerformExpression);
                }
            }
            """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "CalculatePerformExpression"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_hooked_CalculatePerformExpression")
            assert hook.original_address == executable.address_of_symbol("_orig_CalculatePerformExpression")
            assert str(hook) == "%hookf CalculatePerformExpression()"

    def test_msfindsymbol_resolves_hook_dlsym_resolves_target(self) -> None:
        # A tweak that uses MSFindSymbol to dynamically resolve MSHookFunction
        # And uses dlsym to dynamically resolve the function to be hooked
        source_code = """
            #include <dlfcn.h>

            void *orig_CalculatePerformExpression = NULL;
            int hooked_CalculatePerformExpression(char *expression, int a, int b, char *c) {
                return 1;
            }

            __attribute__((constructor)) void tweak_init(void) {
                MSImageRef substrate = MSGetImageByName("/usr/lib/libsubstrate.dylib");
                void *_MSHookFunction = MSFindSymbol(substrate, "_MSHookFunction");
                if (_MSHookFunction) {
                    void *handle = dlopen("/System/Library/PrivateFrameworks/Calculate.framework/Calculate", RTLD_LAZY);
                    void *CalculatePerformExpression = dlsym(handle, "CalculatePerformExpression");

                    ((void (*)(void *, void *, void *))_MSHookFunction)(CalculatePerformExpression, (void *)hooked_CalculatePerformExpression, &orig_CalculatePerformExpression);
                }
            }
            """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "CalculatePerformExpression"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_hooked_CalculatePerformExpression")
            assert hook.original_address == executable.address_of_symbol("_orig_CalculatePerformExpression")
            assert str(hook) == "%hookf CalculatePerformExpression()"

    def test_dlsym_resolves_hook_msfindsymbol_resolves_target(self) -> None:
        # A tweak that uses dlsym to dynamically resolve MSHookFunction
        # And uses MSFindSymbol to dynamically resolve the function to be hooked
        source_code = """
            #include <dlfcn.h>

            void *orig_CalculatePerformExpression = NULL;
            int hooked_CalculatePerformExpression(char *expression, int a, int b, char *c) {
                return 1;
            }

            __attribute__((constructor)) void tweak_init(void) {
                void *substrate = dlopen("/usr/lib/libsubstrate.dylib", RTLD_LAZY);
                void *_MSHookFunction = dlsym(substrate, "MSHookFunction");
                if (_MSHookFunction) {
                    MSImageRef calculator = MSGetImageByName("/System/Library/PrivateFrameworks/Calculate.framework/Calculate");
                    void *CalculatePerformExpression = MSFindSymbol(calculator, "_CalculatePerformExpression");

                    ((void (*)(void *, void *, void *))_MSHookFunction)(CalculatePerformExpression, (void *)hooked_CalculatePerformExpression, &orig_CalculatePerformExpression);
                }
            }
            """  # noqa: E501
        with SnippetCompiler(source_code=source_code) as executable:
            hooks: list[Hook] = sorted(executable.get_hooks())
            assert len(hooks) == 1

            hook = hooks[0]
            assert isinstance(hook.target, FunctionTarget)
            assert hook.target.target_function_name == "CalculatePerformExpression"
            assert executable.symbol_contains_address("_tweak_init", hook.callsite_address)
            assert hook.replacement_address == executable.address_of_symbol("_hooked_CalculatePerformExpression")
            assert hook.original_address == executable.address_of_symbol("_orig_CalculatePerformExpression")
            assert str(hook) == "%hookf CalculatePerformExpression()"
