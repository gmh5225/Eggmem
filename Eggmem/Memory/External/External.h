#pragma once
#include "../Memory.h"
#include "../Util/Util.h"

class External : public Memory {
public:

    External(std::wstring processName);

    PPEB getPEB() override;

    PROCESS_BASIC_INFORMATION getPBI() override;

    Module getModule(std::wstring moduleName);

    std::vector<Module> getModules();

    DWORD getPID() override;

    IMAGE_DOS_HEADER getDOSHeader(uintptr_t moduleBaseAddress) override;

    IMAGE_NT_HEADERS getNTHeaders(uintptr_t moduleBaseAddress) override;

    IMAGE_DATA_DIRECTORY getDataDirectory(IMAGE_NT_HEADERS NTHeaders, int index = 0) override;

    IMAGE_EXPORT_DIRECTORY getExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory) override;

    IMAGE_IMPORT_DESCRIPTOR getImportDescriptor(uintptr_t moduleBaseAddress) override;

    IMAGE_SECTION_HEADER getSectionHeader(uintptr_t moduleBaseAddress, int index) override;

    HANDLE openHandle(uintptr_t openHandleMethod, ACCESS_MASK handleAccessRights);

    std::wstring getProcName() override;

    template <typename T>
    T rpm(uintptr_t baseAddress) {
        T buffer;
        EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(this->hProcess, (PVOID)baseAddress, &buffer, sizeof(T), NULL)), "Failed to read memory");
        return buffer;

    }

    template <typename T>
    bool wpm(uintptr_t baseAddress, T buffer) {
        return NT_SUCCESS(winapi::NtWriteVirtualMemory(this->hProcess, (PVOID)baseAddress, &buffer, sizeof(T), NULL));
    }

private:

    void initPEB() override;
    void initPBI() override;
    void initPID() override;

    std::vector<ExportInfo> getExports(uintptr_t baseAddress);

    std::vector<ImportInfo> getImports(uintptr_t baseAddress);

    const std::unique_ptr<Util> util = std::make_unique<Util>();

    std::wstring processName;

    void initModules();
    std::vector<Module> modules;
    bool modulesInitialized = false;

    HANDLE hProcess;
    bool hProcessInitialized = false;
};