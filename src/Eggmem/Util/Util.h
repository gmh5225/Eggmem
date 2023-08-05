#pragma once
#include <string_view>
#include <vector>
#include <iostream>
#include "winapi.h"
#define EGG_ASSERT(condition, message) do { if(!(condition)) { eggError(__func__, message); } } while(false)
#define ASSERT_MAIN(Result, Message) \
if (!(Result)) { \
    std::cerr << '\n' << std::string_view(__FILE__) << ": In function '" << std::string_view(__FUNCTION__) << "'\n"; \
    std::cerr << std::string_view(__FILE__) << ':' << std::to_string(__LINE__) << ": error: '" << (Message) << "' returned false\n"; \
    return -1; \
}

#define ASSERT_WIN(Result, Message) \
if ((Result) < 0) { \
    std::cerr << '\n' << std::string_view(__FILE__) << ": In function '" << std::string_view(__FUNCTION__) << "'\n"; \
    std::cerr << std::string_view(__FILE__) << ':' << std::to_string(__LINE__) << ": error: '" << (Message) << "' returned " << (Result) << '\n'; \
    return false; \
}
#define EGG_ERROR(message) do { eggError(__func__, message); } while(false)
#define SeDebugPriv 20
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ( (HANDLE)(LONG_PTR) -1 ) 
#define ProcessHandleType 0x7

extern void eggError(const std::string_view funcName, const std::string_view errorMessage);

extern std::vector<DWORD> GetChildProcesses(DWORD parentProcessID);

constexpr OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security);
constexpr CLIENT_ID InitClientId(HANDLE hProcess, HANDLE hThread);
constexpr UNICODE_STRING InitUnicodeString(const wchar_t* str, USHORT length);

bool Contains(const std::wstring_view& str, const std::wstring_view& substring);
bool Contains(const std::string_view& str, const std::string_view& substring);

LONG CALLBACK VEHHandler(EXCEPTION_POINTERS* ExceptionInfo);
int SEHFilter(unsigned int code, struct _EXCEPTION_POINTERS* ep);

//template<typename Func, typename... Args>
//auto safeCallVEH(const char* funcName, Func&& func, Args&&... args) -> decltype(func(std::forward<Args>(args)...)) {
//    void* handler = AddVectoredExceptionHandler(1, VEHHandler);
//
//    try {
//        auto result = func(std::forward<Args>(args)...);
//        RemoveVectoredExceptionHandler(handler);
//        return result;
//    }
//    catch (...) {
//        RemoveVectoredExceptionHandler(handler);
//        std::cerr << "[VEH] -> exception in function: " << funcName << std::endl;
//        throw;
//    }
//}

class ScopedVEH {
    void* handler;
public:
    ScopedVEH(void* h) : handler(h) {}
    ~ScopedVEH() {
        if (handler) {
            RemoveVectoredExceptionHandler(handler);
        }
    }
};

template<typename Func, typename... Args>
auto safeCallVEH(const char* funcName, Func&& func, Args&&... args) -> std::invoke_result_t<Func, Args...> {
    static_assert(!std::is_nothrow_invocable_v<Func, Args...>,
        "safeCallVEH is not intended for noexcept functions");

    void* handler = AddVectoredExceptionHandler(1, VEHHandler);

    if (!handler) {
        throw std::runtime_error("Failed to add VEH handler");
    }

    ScopedVEH scopedHandler(handler);

    try {
        if constexpr (std::is_void_v<std::invoke_result_t<Func, Args...>>) {
            std::invoke(std::forward<Func>(func), std::forward<Args>(args)...);
        }
        else {
            return std::invoke(std::forward<Func>(func), std::forward<Args>(args)...);
        }
    }
    catch (...) {
        std::cerr << "[VEH] -> exception in function: " << funcName << std::endl;
        throw;
    }
}

template<typename Func, typename... Args>
auto safeCallSEH(const char* funcName, Func&& func, Args&&... args) -> std::invoke_result_t<Func, Args...> {
    try {
        if constexpr (std::is_void_v<std::invoke_result_t<Func, Args...>>) {
            __try {
                func(std::forward<Args>(args)...);
            }
            __except (SEHFilter(GetExceptionCode(), GetExceptionInformation())) {
                std::cerr << "[SEH] -> exception in function: " << funcName << std::endl;
                throw; 
            }
        }
        else {
            decltype(auto) result = decltype(func(std::forward<Args>(args)...))();
            __try {
                result = func(std::forward<Args>(args)...);
            }
            __except (SEHFilter(GetExceptionCode(), GetExceptionInformation())) {
                std::cerr << "[SEH] -> exception in function: " << funcName << std::endl;
                throw; 
            }
            return result;
        }
    }
    catch (...) {
        throw;
    }
}