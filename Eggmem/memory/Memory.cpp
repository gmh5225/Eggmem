#include "Memory.h"
#include "../globals/globals.h"
#include <TlHelp32.h>
#include <thread>
#include <iostream>
#include <algorithm>
#include <cstdlib>

namespace eggmem {


    PPEB Memory::getPEB(HANDLE hProcess) {
        PROCESS_BASIC_INFORMATION pbi;
        ULONG returnLength;
        if (!NT_SUCCESS(winapi::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength))) {
            g_pUtil->eggError(__func__, "NtQueryInformationProcess failed");
        }

        PEB peb;
        SIZE_T bytesRead;
        if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), &bytesRead))) {

            g_pUtil->eggError(__func__, "NtReadVirtualMemory failed");
        }

        return &peb;
    }





    HANDLE Memory::getProcHandle(uintptr_t pid, DWORD accessRights) {
        HANDLE hProcess{};
        CLIENT_ID clientId{};
        OBJECT_ATTRIBUTES objectAttributes = g_pUtil->InitObjectAttributes(nullptr, 0, nullptr, nullptr);
        clientId.UniqueProcess = reinterpret_cast<HANDLE>(pid);
        if (!NT_SUCCESS(winapi::NtOpenProcess(&hProcess, accessRights, (OBJECT_ATTRIBUTES*)&objectAttributes, (CLIENT_ID*)&clientId))) {
            throw std::runtime_error("NtOpenProcess failed");
            return nullptr;
        }
        return hProcess;
    }



 
    std::variant<std::vector<Module>, Module, bool> Memory::GetModule(HANDLE hProcess, std::optional<std::wstring> moduleName) {

        Module module{};
        std::vector<Module> modules{};
        PROCESS_BASIC_INFORMATION pbi;
        PPEB peb = getPEB(hProcess);
        
        uintptr_t inMemoryOrderModuleListAddr = (uintptr_t)(peb->Ldr) + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);

        if (!NT_SUCCESS(winapi::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr))) {
            g_pUtil->eggError(__func__, "NtQueryInformationProcess failed");
            return false;
        }

        LIST_ENTRY ModuleList{};
        NTSTATUS ntret;
        if (!NT_SUCCESS(ntret = winapi::NtReadVirtualMemory(hProcess, (void*)inMemoryOrderModuleListAddr, &ModuleList, sizeof(LIST_ENTRY), nullptr))) {
            g_pUtil->eggError(__func__, "NtReadVirtualMemory 1 failed");
            return false;
        }

        LDR_DATA_TABLE_ENTRY currentModuleEntry{};

        if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, CONTAINING_RECORD(ModuleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &currentModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr))) {
            g_pUtil->eggError(__func__, "NtReadVirtualMemory 2 failed");
            return false;
        }


        do {
            USHORT length = (USHORT)currentModuleEntry.FullDllName.MaximumLength;
            WCHAR* buffer = new WCHAR[length / sizeof(WCHAR) + 1]();
            
            buffer[length / sizeof(WCHAR)] = '\0';
            ULONG_PTR FullDllNameBufferAddr = (ULONG_PTR)currentModuleEntry.FullDllName.Buffer;
            NTSTATUS status = winapi::NtReadVirtualMemory(hProcess, (void*)FullDllNameBufferAddr, buffer, length, nullptr);

            if (!NT_SUCCESS(status)) {
                g_pUtil->eggError(__func__, "NtReadVirtualMemory buffer failed");
                delete[] buffer;
                return false;
            }

            IMAGE_DOS_HEADER dosHeader;
            if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)currentModuleEntry.DllBase, &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr))) {
                g_pUtil->eggError(__func__, "NtReadVirtualMemory failed 1");
            }
            IMAGE_DOS_HEADER* pDosHeader = &dosHeader;
            IMAGE_NT_HEADERS ntHeaders;
            if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)((uintptr_t)currentModuleEntry.DllBase + pDosHeader->e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), nullptr))) {
                g_pUtil->eggError(__func__, "NtReadVirtualMemory failed 2");
            }
            IMAGE_NT_HEADERS* pNtHeaders = &ntHeaders;

            std::wstring text(buffer, length / sizeof(WCHAR));
            LDR_DATA_TABLE_ENTRY* currentModuleEntryBase = CONTAINING_RECORD(currentModuleEntry.InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            uintptr_t entryPoint = reinterpret_cast<ptrdiff_t>(currentModuleEntryBase) + 0x38;
            Module tempModule{
                .moduleName = text,
                .baseAddress = (uintptr_t)currentModuleEntry.DllBase,
                .entryPoint = pNtHeaders->OptionalHeader.AddressOfEntryPoint,
                .size = pNtHeaders->OptionalHeader.SizeOfImage,
                
                .flags = pNtHeaders->OptionalHeader.LoaderFlags,
                
                .checkSum = currentModuleEntry.CheckSum,
            };
            /*std::cout << currentModuleEntry.Reserved1 << "\n" << currentModuleEntry.Reserved2 << "\n" << currentModuleEntry.Reserved3 << "\n" << currentModuleEntry.Reserved4<<"\n" ;*/

            if (moduleName.has_value()) {
                std::wstring lowerModuleName(moduleName.value());
                std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::towlower);

                std::wstring lowerTempModuleName(tempModule.moduleName);
                std::transform(lowerTempModuleName.begin(), lowerTempModuleName.end(), lowerTempModuleName.begin(), ::towlower);

                if (lowerModuleName == lowerTempModuleName) {
                    return tempModule;
                }
            }

            modules.emplace_back(tempModule);
            delete[] buffer;

            if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, CONTAINING_RECORD(currentModuleEntry.InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &currentModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr))) {
                g_pUtil->eggError(__func__, "NtReadVirtualMemory 3 failed");
                return false;
            }

        } while (currentModuleEntry.InMemoryOrderLinks.Flink != ModuleList.Flink);
        return modules;
    }


    /*std::variant<std::vector<ImportInfo>, ImportInfo> Memory::getImports(uintptr_t baseAddress, std::string_view moduleImportName = "") {

    }*/

    //std::variant<std::vector<ExportInfo>, ExportInfo> Memory::getExports(uintptr_t baseAddress, std::optional<std::string_view> moduleExportName) {

    //    const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(baseAddress);
    //    const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(baseAddress + dosHeader->e_lfanew);

    //    const IMAGE_DATA_DIRECTORY* dataDirectory = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(&ntHeaders->OptionalHeader.DataDirectory[0]);
    //    const IMAGE_EXPORT_DIRECTORY* exportDirectory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(baseAddress + dataDirectory->VirtualAddress);

    //    const uintptr_t* functionAddressTable = reinterpret_cast<const uintptr_t*>(baseAddress + exportDirectory->AddressOfFunctions);
    //    const uintptr_t* nameAddressTable = reinterpret_cast<const uintptr_t*>(baseAddress + exportDirectory->AddressOfNames);
    //    const uint16_t* ordinalAddressTable = reinterpret_cast<const uint16_t*>(baseAddress + exportDirectory->AddressOfNameOrdinals);

    //    std::vector<ExportInfo> exports;

    //    if (exportDirectory) {
    //        for (size_t i = 0; i < exportDirectory->NumberOfNames; i++) {
    //            const char* exportName = reinterpret_cast<const char*>(baseAddress + nameAddressTable[i]);
    //            
    //            if (exportName) {
    //                const ExportAddresses exportAddresses{ .exportAddress = baseAddress + functionAddressTable[ordinalAddressTable[i]],
    //                    .absoluteAddress = baseAddress + functionAddressTable[ordinalAddressTable[i]] - ntHeaders->OptionalHeader.ImageBase,
    //                    .exportAddressOffset = baseAddress + functionAddressTable[ordinalAddressTable[i]] - ntHeaders->OptionalHeader.ImageBase };
    //                const ExportInfo exportInfo { .exportName = std::string(exportName), .exportAddresses = exportAddresses };

    //                if (!moduleExportName.empty()) {
    //                    if (moduleExportName.compare(exportName) == 0) {
    //                        return exportInfo;
    //                    }
    //                }
    //                else {
    //                    exports.emplace_back(exportInfo);
    //                }
    //            }
    //        }
    //    }
    //    if (exports.empty()) {
    //        if (!moduleExportName.empty()) {
    //            throw std::runtime_error("[GetExports] -> No exports found for module " + std::string(moduleExportName));
    //        }
    //        else {
    //            throw std::runtime_error("[GetExports] -> No exports found for DLL");
    //        }
    //    }
    //    return exports;
    //}

    /*std::variant<std::vector<ExportInfo>, ExportInfo> Memory::getExports(uintptr_t baseAddress, std::optional<std::string_view> moduleExportName) {

        const IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(baseAddress);
        const IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS*>(baseAddress + dosHeader->e_lfanew);

        const IMAGE_DATA_DIRECTORY* dataDirectory = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(&ntHeaders->OptionalHeader.DataDirectory[0]);
        const IMAGE_EXPORT_DIRECTORY* exportDirectory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(baseAddress + dataDirectory->VirtualAddress);

        const uintptr_t* functionAddressTable = reinterpret_cast<const uintptr_t*>(baseAddress + exportDirectory->AddressOfFunctions);
        const uintptr_t* nameAddressTable = reinterpret_cast<const uintptr_t*>(baseAddress + exportDirectory->AddressOfNames);
        const uint16_t* ordinalAddressTable = reinterpret_cast<const uint16_t*>(baseAddress + exportDirectory->AddressOfNameOrdinals);

        std::vector<ExportInfo> exports;

        if (exportDirectory) {
            for (size_t i = 0; i < exportDirectory->NumberOfNames; i++) {
                const char* exportName = reinterpret_cast<const char*>(baseAddress + nameAddressTable[i]);

                if (exportName) {
                    const ExportAddresses exportAddresses{ .exportAddress = baseAddress + functionAddressTable[ordinalAddressTable[i]],
                        .absoluteAddress = baseAddress + functionAddressTable[ordinalAddressTable[i]] - ntHeaders->OptionalHeader.ImageBase,
                        .exportAddressOffset = baseAddress + functionAddressTable[ordinalAddressTable[i]] - ntHeaders->OptionalHeader.ImageBase };
                    const ExportInfo exportInfo{ .exportName = std::string(exportName), .exportAddresses = exportAddresses };

                    if (moduleExportName && (moduleExportName.value() == exportName)) {
                        return exportInfo;
                    }
                    else if (!moduleExportName) {
                        exports.emplace_back(exportInfo);
                    }
                }
            }
        }

        if (exports.empty()) {
            if (moduleExportName) {
                throw std::runtime_error("[GetExports] -> No exports found for module " + std::string(moduleExportName.value()));
            }
            else {
                throw std::runtime_error("[GetExports] -> No exports found for DLL");
            }
        }
        return exports;
    }*/

    std::variant<std::vector<ExportInfo>, ExportInfo> Memory::getExports(HANDLE hProcess, uintptr_t baseAddress, std::optional<const char*> moduleExportName) {
            
        IMAGE_DOS_HEADER dosHeader{};
        if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)baseAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr))) {
            g_pUtil->eggError(__func__, "NtReadVirtualMemory failed 1");
        }
        IMAGE_DOS_HEADER* pDosHeader = &dosHeader;
        
        IMAGE_NT_HEADERS ntHeaders{};
        if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)(baseAddress + pDosHeader->e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), nullptr))) {
			g_pUtil->eggError(__func__, "NtReadVirtualMemory failed 2");
		}
        IMAGE_NT_HEADERS* pNtHeaders = &ntHeaders;

       

        IMAGE_DATA_DIRECTORY* pDataDirectory = &pNtHeaders->OptionalHeader.DataDirectory[0];

        IMAGE_EXPORT_DIRECTORY exportDirectory{};
        if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)(baseAddress + pDataDirectory->VirtualAddress), &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))) {
			g_pUtil->eggError(__func__, "NtReadVirtualMemory failed 4");
		}
        IMAGE_EXPORT_DIRECTORY* pExportDirectory = &exportDirectory;
        
        const ULONG_PTR NameTableAddr = baseAddress + pExportDirectory->AddressOfNames;
        const ULONG_PTR RVATableAddr = baseAddress + pExportDirectory->AddressOfFunctions;
        const ULONG_PTR OrdTableAddr = baseAddress + pExportDirectory->AddressOfNameOrdinals;

        uint32_t* NameTable =new uint32_t[pExportDirectory->NumberOfNames];
        uint32_t* RVATable = new uint32_t[pExportDirectory->NumberOfFunctions];
        uint32_t* OrdTable = new uint32_t[pExportDirectory->NumberOfNames];

        SIZE_T bytesRead;

        
        if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)NameTableAddr, NameTable, sizeof(unsigned long) * pExportDirectory->NumberOfNames, &bytesRead))) {
            delete[] NameTable;
            delete[] RVATable;
            delete[] OrdTable;
            g_pUtil->eggError(__func__, "NtReadVirtualMemory failed 2");
        }

        
        if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)RVATableAddr, RVATable, sizeof(unsigned long) * pExportDirectory->NumberOfFunctions, &bytesRead))) {
            delete[] NameTable;
            delete[] RVATable;
            delete[] OrdTable;
            g_pUtil->eggError(__func__, "NtReadVirtualMemory failed 3");
        }

        
        if (!NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)OrdTableAddr, OrdTable, sizeof(unsigned short) * pExportDirectory->NumberOfNames, &bytesRead))) {
            delete[] NameTable;
            delete[] RVATable;
            delete[] OrdTable;
            g_pUtil->eggError(__func__, "NtReadVirtualMemory failed 4");
        }

        std::vector<ExportInfo> exports;
        for (int i = 0; i < pExportDirectory->NumberOfNames; i++) {
            
            uint32_t* names = new uint32_t[pExportDirectory->NumberOfNames];
            winapi::NtReadVirtualMemory(hProcess, (PVOID)(baseAddress + pExportDirectory->AddressOfNames + i), names, pExportDirectory->NumberOfNames, nullptr);

            char name[256] = {};
            winapi::NtReadVirtualMemory(hProcess, (PVOID)(baseAddress + names[0]), &name, sizeof(name), nullptr);
           /* std::cout << "RAHHHHHHHHHHHHHHHHH MY COCK" << std::hex << pNtHeaders->OptionalHeader.DataDirectory[0].VirtualAddress << std::endl;*/
            if (name) 
            std::cout << name << std::endl;

            /*ExportInfo exportInfo{
                .exportName = exportNameBuffer,
                .exportAddresses = ExportAddresses{
                    .exportAddress = baseAddress + RVATable[i],
                    .absoluteAddress = baseAddress + RVATable[i] - pNtHeaders->OptionalHeader.ImageBase,
                    .exportAddressOffset = RVATable[i] - pNtHeaders->OptionalHeader.ImageBase
                }
            };*/

            //exports.push_back(exportInfo); // Don't forget to store the exportInfo object in your vector
        
        }

        return exports;
    }

    HANDLE Memory::hijackHandle(DWORD OwnerPid, DWORD desiredHandlePid, DWORD accessRights) {
        NTSTATUS ntret;
        OBJECT_ATTRIBUTES objectAttributes = g_pUtil->InitObjectAttributes(nullptr, 0, nullptr, nullptr);
        unsigned char oldpriv;
        ntret = winapi::RtlAdjustPrivilege(20, true, false, &oldpriv);
        winapistructs::SYSTEM_HANDLE_INFORMATION* handleInfo = nullptr;
        size_t handleInfoSize = sizeof(winapistructs::SYSTEM_HANDLE_INFORMATION);

        // Add OwnerPid to the child processes list to include it in the check
        std::vector<DWORD> processesToCheck = g_pUtil->GetChildProcesses(OwnerPid);
        processesToCheck.push_back(OwnerPid);

        do {
            try {
                delete[] handleInfo;
                handleInfo = new winapistructs::SYSTEM_HANDLE_INFORMATION[handleInfoSize];
                handleInfoSize *= 1.5;
            }
            catch (std::bad_alloc& e) {

                printf("[hijackHandle] -> Failed to allocate memory for handleInfo, error: %s\n", e.what());
                return nullptr;
            }
        } while ((ntret = winapi::NtQuerySystemInformation(16, handleInfo, handleInfoSize, nullptr)) == STATUS_INFO_LENGTH_MISMATCH);

        if (!NT_SUCCESS(ntret)) {
            throw std::runtime_error("[hijackHandle] -> NtQuerySystemInformation failed.\n");
        }

        for (size_t i = 0; i < handleInfo->NumberOfHandles; i++) {

            // check if the process owning the handle is among the processes we want to check
            if (std::find(processesToCheck.begin(), processesToCheck.end(), handleInfo->Handles[i].UniqueProcessId) != processesToCheck.end()) {

                if (handleInfo->Handles[i].ObjectTypeIndex != ProcessHandleType) {
                    /*printf("[hijackHandle] -> Handle %d is not a process handle, skipping.\n", handleInfo->Handles[i].HandleValue);*/
                    std::cout << "[hijackHandle] -> Handle " << (HANDLE)handleInfo->Handles[i].HandleValue << " is not a process handle, skipping." << std::endl;
                    continue;
                }
                std::cout << "[hijackHandle] -> Found handle owned by target process, PID: " << handleInfo->Handles[i].UniqueProcessId << ", Handle: " << (HANDLE)handleInfo->Handles[i].HandleValue << std::endl;
                HANDLE processHandle = nullptr;
                CLIENT_ID targetPid = { (PVOID)handleInfo->Handles[i].UniqueProcessId, 0 };
                ntret = winapi::NtOpenProcess(&processHandle, PROCESS_DUP_HANDLE, &objectAttributes, &targetPid);
                if (!NT_SUCCESS(ntret)) {
                    throw std::runtime_error("[hijackHandle] -> Failed to open target process.\n");
                }
                std::cout << "[hijackHandle] -> Target process handle: " << processHandle << std::endl;

                HANDLE duplicatedHandle = nullptr;

                ntret = winapi::NtDuplicateObject(processHandle, (HANDLE)handleInfo->Handles[i].HandleValue, GetCurrentProcess(), &duplicatedHandle, 0, 0, accessRights);
                if (!NT_SUCCESS(ntret)) {
                    CloseHandle(processHandle);
                    throw std::runtime_error("[hijackHandle] -> NtDuplicateObject failed.\n");
                }
                PROCESS_BASIC_INFORMATION pbi;
                ntret = winapi::NtQueryInformationProcess(duplicatedHandle, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), nullptr);
                if (!NT_SUCCESS(ntret)) {
                    CloseHandle(duplicatedHandle);
                    CloseHandle(processHandle);
                    throw std::runtime_error("[hijackHandle] -> NtQueryInformationProcess failed.\n");
                }
                if (pbi.UniqueProcessId == desiredHandlePid) {

                    std::cout << "[hijackHandle] -> Found desired handle, PID: " << pbi.UniqueProcessId << ", Handle: " << (HANDLE)handleInfo->Handles[i].HandleValue << std::endl;
                    CloseHandle(processHandle);
                    delete[] handleInfo;
                    return duplicatedHandle;
                }
                else {
                    CloseHandle(duplicatedHandle);
                    CloseHandle(processHandle);
                }
            }
        }
        delete[] handleInfo;
        return nullptr;
    }
    DWORD Memory::GetProcId(const std::wstring processName) {
        DWORD procId = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE)
        {
            PROCESSENTRY32 pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32);
            if (Process32First(hSnap, &pe32))
            {
                do
                {
                    
                    std::wstring currentProcName = pe32.szExeFile;

                    std::transform(currentProcName.begin(), currentProcName.end(), currentProcName.begin(), ::towlower);
                    std::wstring lowerProcessName = processName;
                    std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::towlower);
                    /*std::wcout << currentProcName << pe32.th32ProcessID << std::endl;*/
                    if (currentProcName.compare(lowerProcessName) == 0)
                    {
                        procId = pe32.th32ProcessID;
                        break;
                    }

                } while (Process32Next(hSnap, &pe32));
            }
        }
        CloseHandle(hSnap);
        return procId;
    }
}