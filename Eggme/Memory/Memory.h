#pragma once
#include "Util/structs.h"

class Memory {
public:
    virtual ~Memory() {}

    virtual PPEB getPEB() = 0;
    virtual PROCESS_BASIC_INFORMATION getPBI() = 0;
    virtual DWORD getPID() = 0;
    virtual IMAGE_DOS_HEADER DOSHeader(uintptr_t moduleBaseAddress) = 0;
    virtual IMAGE_NT_HEADERS getNTHeaders(uintptr_t moduleBaseAddress) = 0;
    virtual IMAGE_DATA_DIRECTORY getDataDirectory(IMAGE_NT_HEADERS NTHeaders, int index = 0) = 0;
    virtual IMAGE_EXPORT_DIRECTORY getExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory) = 0;
    virtual IMAGE_IMPORT_DESCRIPTOR getImportDescriptor(uintptr_t moduleBaseAddress) = 0;
    virtual IMAGE_SECTION_HEADER getSectionHeader(uintptr_t moduleBaseAddress, int index) = 0;
    virtual bool unlinkModule(Module module) = 0;
    virtual std::wstring getProcName() = 0;
    virtual void initPEB() = 0;
    virtual void initPID() = 0;
    virtual void initPBI() = 0;
    
protected:
    static PPEB peb;
    bool pebInitialized = false;

    static PROCESS_BASIC_INFORMATION pbi;
    bool pbiInitialized = false;

    static DWORD pid;
    bool pidInitialized = false;
};