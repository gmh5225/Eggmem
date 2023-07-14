#include "MemoryInternal.h"
#include "../globals/globals.h"
namespace eggmem {

    uint8_t* MemoryInternal::Scan(const char* module, const char* pattern)
    {
        const auto handle = ::GetModuleHandle((LPCWSTR)module);

        if (!handle)
            throw std::runtime_error("Failed to get " + std::string(module) + " module handle.");

        static auto patternToByte = [](const char* pattern)
        {
            auto bytes = std::vector<int>{};
            auto start = const_cast<char*>(pattern);
            auto end = const_cast<char*>(pattern) + std::strlen(pattern);

            for (auto current = start; current < end; ++current)
            {
                if (*current == '?')
                {
                    ++current;

                    if (*current == '?')
                        ++current;

                    bytes.push_back(-1);
                }
                else
                {
                    bytes.push_back(std::strtoul(current, &current, 16));
                }
            }
            return bytes;
        };
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(handle);
        auto ntHeaders =
            reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<std::uint8_t*>(handle) + dosHeader->e_lfanew);

        auto size = ntHeaders->OptionalHeader.SizeOfImage;
        auto bytes = patternToByte(pattern);
        auto scanBytes = reinterpret_cast<std::uint8_t*>(handle);

        auto s = bytes.size();
        auto d = bytes.data();

        for (auto i = 0ul; i < size - s; ++i)
        {
            bool found = true;

            for (auto j = 0ul; j < s; ++j)
            {
                if (scanBytes[i + j] != d[j] && d[j] != -1) {

                    found = false;
                    break;
                }
            }

            if (found)
                return &scanBytes[i];
        }

        throw std::runtime_error("Outdated pattern \"" + std::string(pattern) + "\"");
    }

    PPEB MemoryInternal::getPEB() {
#ifdef _WIN64
        return reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
        return reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif

    }

    DWORD MemoryInternal::GetProcId() {
        PROCESS_BASIC_INFORMATION pbi;
        if (!NT_SUCCESS(winapi::NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr))) {
            throw std::runtime_error("[GetProcId] -> NtQueryInformationProcess failed");
            return 0;
        }
        return (DWORD)pbi.UniqueProcessId;
    }
    
    
    


}