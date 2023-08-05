#pragma once
#include "../Memory.h"
#include "../Util/Util.h"

class Internal : public Memory {
public:
    Internal();

    PPEB getPEB() override;
    PROCESS_BASIC_INFORMATION getPBI() override;
    DWORD getPID() override;
    IMAGE_DOS_HEADER DOSHeader(uintptr_t moduleBaseAddress) override;
    IMAGE_NT_HEADERS getNTHeaders(uintptr_t moduleBaseAddress) override;
    IMAGE_DATA_DIRECTORY getDataDirectory(IMAGE_NT_HEADERS NTHeaders, int index = 0) override;
    IMAGE_EXPORT_DIRECTORY getExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory) override;
    IMAGE_IMPORT_DESCRIPTOR getImportDescriptor(uintptr_t moduleBaseAddress) override;
    IMAGE_SECTION_HEADER getSectionHeader(uintptr_t moduleBaseAddress, int index) override;
    std::wstring getProcName() override;
    bool unlinkModule(Module module) override;

private:

    
    void initPEB() override;
    void initPBI() override;
    void initPID() override;

    std::vector<ExportInfo> getExports(uintptr_t baseAddress);

    Module getModule(std::wstring moduleName);

    std::vector<ImportInfo> getImports(uintptr_t baseAddress);

    const std::unique_ptr<Util> util = std::make_unique<Util>();

    std::wstring processName;
};

