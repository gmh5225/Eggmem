#pragma once
#include "../Util/structs.h"
#include "../Util/Util.h"

class Internal
{
public:
	Internal();

	std::wstring getProcName();

	PPEB getPEB();
	PROCESS_BASIC_INFORMATION getPBI();
	DWORD getPID();
	IMAGE_DOS_HEADER getDOSHeader(uintptr_t moduleBaseAddress);

	IMAGE_NT_HEADERS getNTHeaders(uintptr_t moduleBaseAddress);

	IMAGE_DATA_DIRECTORY getDataDirectory(IMAGE_NT_HEADERS NTHeaders, int index = 0);

	IMAGE_EXPORT_DIRECTORY getExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory);

	IMAGE_IMPORT_DESCRIPTOR getImportDescriptor(uintptr_t moduleBaseAddress);

	IMAGE_SECTION_HEADER getSectionHeader(uintptr_t moduleBaseAddress, int index);

	void Nop(BYTE* destination, uintptr_t size);
	void Patch(BYTE* destination, BYTE* source, uintptr_t size);

	bool Detour32 (BYTE* source, BYTE* destination, const uintptr_t length);
	bool Detour64 (BYTE* source, BYTE* destination, const uintptr_t length);

	BYTE* TrampHook32 (BYTE* source, BYTE* destination, const uintptr_t length);
	BYTE* TrampHook64 (BYTE* source, BYTE* destination, const uintptr_t length);

private:

	std::vector<ExportInfo> getExports(uintptr_t baseAddress);

	Module getModule(std::wstring moduleName);

	std::vector<ImportInfo> getImports(uintptr_t baseAddress);

	const std::unique_ptr<Util> util = std::make_unique<Util>();
	
	std::wstring processName;

	void initPEB();
	PPEB peb;
	bool pebInitialized = false;

	void initPBI();
	PROCESS_BASIC_INFORMATION pbi;
	bool pbiInitialized = false;

	void initPID();
	DWORD pid;
	bool pidInitialized = false;

};

