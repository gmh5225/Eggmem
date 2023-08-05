#pragma once
#include "../Hook.h"
#include <unordered_map>
#ifdef _WIN64
#define XIP Rip
#else
#define XIP Eip
#endif
class BreakpointHook : public Hook {
public:
    BreakpointHook(uintptr_t targetAddress, uintptr_t functionAddress, DWORD targetThreadID)
        : Hook(),
        targetAddress(targetAddress),
        functionAddress(functionAddress),
        targetThreadID(targetThreadID) {}

    BYTE* install() override {
        if (GetCurrentThreadId() == targetThreadID) {
            originalByte = *(BYTE*)targetAddress;
            DWORD oldProtect;
            VirtualProtect((LPVOID)targetAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *(BYTE*)targetAddress = 0xCC; // int3
            VirtualProtect((LPVOID)targetAddress, 1, oldProtect, &oldProtect);
            _installed = true;
        }
        return &originalByte;
    }

    bool uninstall() override {
        if (_installed) {
            DWORD oldProtect;
            VirtualProtect((LPVOID)targetAddress, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
            *(BYTE*)targetAddress = originalByte;
            VirtualProtect((LPVOID)targetAddress, 1, oldProtect, &oldProtect);
            _installed = false;
            return true;
        }
        return false;
    }

    uintptr_t getOriginalFunction() const override {
        return targetAddress;
    }

    static LONG CALLBACK BreakpointHandler(EXCEPTION_POINTERS* ExceptionInfo) {
        auto it = globalHookMap.find(ExceptionInfo->ContextRecord->XIP);
        if (it != globalHookMap.end()) {
            auto hook = it->second;
            if (hook->targetThreadID == GetCurrentThreadId()) {
                ExceptionInfo->ContextRecord->XIP = hook->functionAddress;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }


private:
    BYTE originalByte;
    uintptr_t targetAddress;
    uintptr_t functionAddress;
    DWORD targetThreadID;
    static std::unordered_map<uintptr_t, BreakpointHook*> globalHookMap;
};
