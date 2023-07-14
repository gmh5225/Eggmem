
#pragma once
#include <variant>
#include <string_view>
#include "../util/structs.h"
#include <optional>

namespace eggmem {

    class Memory {

    public:

        HANDLE getProcHandle(uintptr_t pid, DWORD accessRights);

        std::variant<std::vector<Module>, Module, bool> GetModule(HANDLE hProcess, std::optional<std::wstring> moduleName);

        DWORD GetProcId(std::wstring processName);

        HANDLE hijackHandle(DWORD OwnerPid, DWORD desiredHandlePid, DWORD accessRights);

        static PPEB getPEB(HANDLE hProcess);

        //std::variant<std::vector<ExportInfo>, ExportInfo> getExports(uintptr_t baseAddress, std::optional<std::string_view> moduleExportName);

        std::variant<std::vector<ExportInfo>, ExportInfo> getExports(HANDLE hProcess, uintptr_t baseAddress, std::optional<const char*> moduleExportName);

        template <typename T>
        T read(uintptr_t address, HANDLE hProcess) {
            T buffer;
            //size_t oldProtect;
            //winapi::NtProtectVirtualMemory(hProcess, reinterpret_cast<void*>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect);
            if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, reinterpret_cast<void*>(address), &buffer, sizeof(T), nullptr))) {
                throw std::runtime_error("[read] -> NtReadVirtualMemory failed");
            }
            //winapi::NtProtectVirtualMemory(hProcess, reinterpret_cast<void*>(address), sizeof(T), oldProtect, nullptr);
            return buffer;
		}

        template<typename T>
        void write(uintptr_t address, T buffer, HANDLE hProcess) {
            //size_t oldProtect;
            //winapi::NtProtectVirtualMemory(hProcess, reinterpret_cast<void*>(address), sizeof(T), PAGE_EXECUTE_READWRITE, &oldProtect);
            if (!NT_SUCCESS(winapi::NtWriteVirtualMemory(hProcess, reinterpret_cast<void*>(address), &buffer, sizeof(T), nullptr))) {
                throw std::runtime_error("[write] -> NtWriteVirtualMemory failed");
            }
            //winapi::NtProtectVirtualMemory(hProcess, reinterpret_cast<void*>(address), sizeof(T), oldProtect, nullptr);
        }

    };
    
}

