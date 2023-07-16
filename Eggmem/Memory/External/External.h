#pragma once
#include "../Util/structs.h"
#include "../Util/Util.h"
class External
{
public:

	External(std::wstring processName);

	PPEB getPEB();

	const PROCESS_BASIC_INFORMATION getPBI();
	
	Module getModule(std::wstring moduleName);

	std::vector<ExportInfo> getExports(uintptr_t baseAddress);

	std::vector<ImportInfo> getImports(uintptr_t baseAddress);

	std::vector<Module> getModules();

	DWORD getPID();

	IMAGE_DOS_HEADER getDOSHeader(uintptr_t moduleBaseAddress);

	IMAGE_NT_HEADERS getNTHeaders(uintptr_t moduleBaseAddress);

	IMAGE_DATA_DIRECTORY getDataDirectory(IMAGE_NT_HEADERS NTHeaders, int index = 0);

    IMAGE_EXPORT_DIRECTORY getExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory);

	IMAGE_IMPORT_DESCRIPTOR* getImportDescriptor(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory);

	IMAGE_SECTION_HEADER getSectionHeader(uintptr_t moduleBaseAddress, int index);


private:

	const std::unique_ptr<Util> util = std::make_unique<Util>();

	std::wstring processName;

	void initPID();
	DWORD pid;
	bool pidInitialized = false;

	void initPEB();
	std::unique_ptr<PEB> pPeb;
	bool pebInitialized = false;

	void initPBI();
	PROCESS_BASIC_INFORMATION pbi;
	bool pbiInitialized = false;

	void initModules();
	std::vector<Module> modules;
	bool modulesInitialized = false;

	HANDLE hProcess;
};

