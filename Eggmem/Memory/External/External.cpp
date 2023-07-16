#include "External.h"
#include <TlHelp32.h>
#include <algorithm>
#include <assert.h>

External::External(std::wstring processName) {

	this->processName = processName;

}
void External::initPID() {
	if (!this->pidInitialized) {
		
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
					std::wstring lowerProcessName = this->processName;
					std::transform(lowerProcessName.begin(), lowerProcessName.end(), lowerProcessName.begin(), ::towlower);
					
					if (currentProcName.compare(lowerProcessName) == 0)
					{
						procId = pe32.th32ProcessID;
						break;
					}

				} while (Process32Next(hSnap, &pe32));
			}
		}
		CloseHandle(hSnap);
		EGG_ASSERT(procId != 0, "Failed to find process");
		this->pid = procId;
		this->pidInitialized = true;
	}
}

DWORD External::getPID() {
	if (!this->pidInitialized) {
		this->initPID();
	}
	return this->pid;
}

void External::initPBI() {
	if (!this->pbiInitialized) {
		EGG_ASSERT(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, "Handle is invalid");
		PROCESS_BASIC_INFORMATION pbi;
		EGG_ASSERT(NT_SUCCESS(winapi::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)), "Failed to query process information");
		this->pbi = pbi;
		this->pbiInitialized = true;
	}
}

const PROCESS_BASIC_INFORMATION External::getPBI() {
	if (!this->pbiInitialized) {
		this->initPBI();
	}
	return this->pbi;
}

void External::initPEB() {

	/*EGG_ASSERT(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, "Handle is invalid");*/
	if (Ensure(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, __func__, "Handle is invalid")) {
		return;
	}
	PROCESS_BASIC_INFORMATION pbi;
	EGG_ASSERT(NT_SUCCESS(winapi::NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)), "Failed to query process information");

	if (!this->pebInitialized) {
		this->pPeb = std::make_unique<PEB>();
		EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, pbi.PebBaseAddress, this->pPeb.get(), sizeof(PEB), nullptr)), "Failed to read process memory");
		this->pebInitialized = true;
	}
}

PPEB External::getPEB() {
	if (!this->pebInitialized) {
		this->initPEB();
	}
	return this->pPeb.get();
}

IMAGE_DOS_HEADER External::getDOSHeader(uintptr_t moduleBaseAddress) {
	if (Ensure(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, __func__, "Handle is invalid")) {
		return;
	}
	IMAGE_DOS_HEADER dosHeader;
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)moduleBaseAddress, &dosHeader, sizeof(IMAGE_DOS_HEADER), nullptr)), "Failed to read process memory");
	return dosHeader;
}

IMAGE_NT_HEADERS External::getNTHeaders(uintptr_t moduleBaseAddress) {
	if (Ensure(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, __func__, "Handle is invalid")) {
		return;
	}
	IMAGE_NT_HEADERS ntHeaders;
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)(moduleBaseAddress + this->getDOSHeader(moduleBaseAddress).e_lfanew), &ntHeaders, sizeof(IMAGE_NT_HEADERS), nullptr)), "Failed to read process memory");
	return ntHeaders;
}

IMAGE_DATA_DIRECTORY External::getDataDirectory(IMAGE_NT_HEADERS NTHeaders, int index = 0) {
	EGG_ASSERT(index < NTHeaders.OptionalHeader.NumberOfRvaAndSizes, "Index out of range");
	return NTHeaders.OptionalHeader.DataDirectory[index];
}

IMAGE_EXPORT_DIRECTORY External::getExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory) {
	if (Ensure(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, __func__, "Handle is invalid")) {
		return;
	}
	IMAGE_EXPORT_DIRECTORY exportDirectory;
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)(moduleBaseAddress + dataDirectory.VirtualAddress), &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr)), "Failed to read process memory");
}

IMAGE_IMPORT_DESCRIPTOR* External::getImportDescriptor(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory) {
	if (Ensure(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, __func__, "Handle is invalid")) {
		return;
	}
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor;
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)(moduleBaseAddress + dataDirectory.VirtualAddress), importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr)), "Failed to read process memory");
	return importDescriptor;
}

std::vector<ExportInfo> External::getExports(uintptr_t baseAddress) {
	if (Ensure(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, __func__, "Handle is invalid")) {
		return;
	}

	std::vector<ExportInfo> exports;

	auto DOSHeader = this->getDOSHeader(baseAddress);
	auto NTHeaders = this->getNTHeaders(baseAddress);
	auto exportDirectory = this->getExportDirectory(baseAddress, this->getDataDirectory(NTHeaders, 0));
	
	auto dataDirectory = this->getDataDirectory(NTHeaders, 0);

	const ULONG_PTR NameTableAddr = baseAddress + exportDirectory.AddressOfNames;
	const ULONG_PTR RVATableAddr = baseAddress + exportDirectory.AddressOfFunctions;
	const ULONG_PTR OrdTableAddr = baseAddress + exportDirectory.AddressOfNameOrdinals;

	auto NameTable = std::unique_ptr<uint32_t[]>(new uint32_t[exportDirectory.NumberOfNames]);
	auto RVATable = std::unique_ptr<uint32_t[]>(new uint32_t[exportDirectory.NumberOfFunctions]);
	auto OrdTable = std::unique_ptr<uint32_t[]>(new uint32_t[exportDirectory.NumberOfNames]);

	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)NameTableAddr, NameTable.get(), sizeof(unsigned long) * exportDirectory.NumberOfNames, nullptr)), "Failed to read process memory");
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)RVATableAddr, RVATable.get(), sizeof(unsigned long) * exportDirectory.NumberOfFunctions, nullptr)), "Failed to read process memory");
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)OrdTableAddr, OrdTable.get(), sizeof(unsigned short) * exportDirectory.NumberOfNames, nullptr)), "Failed to read process memory");

	for (DWORD i = 0; i < exportDirectory.NumberOfNames; ++i) {

		auto names = std::make_unique<uint32_t[]>(exportDirectory.NumberOfNames);
		winapi::NtReadVirtualMemory(hProcess, (PVOID)(baseAddress + exportDirectory.AddressOfNames + i), names.get(), exportDirectory.NumberOfNames, nullptr);

		char name[256] = {};
		winapi::NtReadVirtualMemory(hProcess, (PVOID)(baseAddress + names[0]), &name, sizeof(name), nullptr);

		if (!std::string(name).empty()) {
			/*std::cout << name << std::endl;*/
			ExportInfo exportInfo{
				.exportName = std::string(name),
				.exportAddress = baseAddress + RVATable[i],
			};
			exports.emplace_back(exportInfo);
		}

	}
	
	return exports;

}

std::vector<ImportInfo> External::getImports(uintptr_t baseAddress) {

	if (Ensure(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, __func__, "Handle is invalid")) {
		return;
	}

	std::vector<ExportInfo> exports;

	auto DOSHeader = this->getDOSHeader(baseAddress);
	auto NTHeaders = this->getNTHeaders(baseAddress);

	IMAGE_DATA_DIRECTORY importDataDir = this->getDataDirectory(NTHeaders, IMAGE_DIRECTORY_ENTRY_IMPORT);
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = this->getImportDescriptor(baseAddress, importDataDir);

	
	std::vector<ImportInfo> importInfos;

	do {
		EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, importDescriptor, importDescriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr)), "NtReadVirtualMemory failed");

		ImportInfo info;

		char dllName[256]; 
		EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)importDescriptor->Name, dllName, sizeof(dllName), nullptr)), "NtReadVirtualMemory failed");
		info.dllName = std::string(dllName);

		IMAGE_THUNK_DATA64* originalFirstThunk = (IMAGE_THUNK_DATA64*)importDescriptor->OriginalFirstThunk;
		IMAGE_THUNK_DATA64* firstThunk = (IMAGE_THUNK_DATA64*)importDescriptor->FirstThunk;

		while (originalFirstThunk->u1.AddressOfData != 0) {
			IndividualImport individualImport;

			IMAGE_IMPORT_BY_NAME importByName;
			EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)originalFirstThunk->u1.AddressOfData, &importByName, sizeof(importByName), nullptr)), "NtReadVirtualMemory failed");
			individualImport.importName = std::string((char*)importByName.Name);
			individualImport.importAddress = firstThunk->u1.Function;

			info.imports.push_back(individualImport);

			originalFirstThunk++;
			firstThunk++;
		}

		importInfos.push_back(info);

	} while (importDescriptor->Name != 0 || importDescriptor->Characteristics != 0);
	return importInfos;
}

Module External::getModule(std::wstring moduleName) {

	if (Ensure(this->hProcess != NULL || this->hProcess != INVALID_HANDLE_VALUE, __func__, "Handle is invalid")) {
		return;
	}

	Module module;
	uintptr_t inMemoryOrderModuleList = (uintptr_t)(this->getPEB()->Ldr) + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);
	LIST_ENTRY moduleList;
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (PVOID)inMemoryOrderModuleList, &moduleList, sizeof(LIST_ENTRY), nullptr)), "Failed to read process memory");
	LDR_DATA_TABLE_ENTRY currentModuleEntry{};
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, CONTAINING_RECORD(moduleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &currentModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr)), "Failed to read process memory");

	do {
		USHORT length = (USHORT)currentModuleEntry.FullDllName.MaximumLength;
		WCHAR* buffer = new WCHAR[length / sizeof(WCHAR) + 1]();
		buffer[length / sizeof(WCHAR)] = '\0';
		ULONG_PTR FullDllNameBufferAddr = (ULONG_PTR)currentModuleEntry.FullDllName.Buffer;
		EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, (void*)FullDllNameBufferAddr, buffer, length, nullptr)), "Failed to read process memory");
		std::wstring text(buffer, length / sizeof(WCHAR));
		delete[] buffer;
		IMAGE_DOS_HEADER DOSHeader = this->getDOSHeader((uintptr_t)currentModuleEntry.DllBase);
		IMAGE_NT_HEADERS NTHeaders = this->getNTHeaders((uintptr_t)currentModuleEntry.DllBase);

		if (!moduleName.empty()) {
			std::wstring lowerModuleName(moduleName);
			std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::towlower);

			std::wstring lowerTempModuleName(text);
			std::transform(lowerTempModuleName.begin(), lowerTempModuleName.end(), lowerTempModuleName.begin(), ::towlower);

			if (lowerModuleName == lowerTempModuleName) {
				Module tempModule{
					.moduleName = text,
					.baseAddress = (uintptr_t)currentModuleEntry.DllBase,
					.entryPoint = NTHeaders.OptionalHeader.AddressOfEntryPoint,
					.size = NTHeaders.OptionalHeader.SizeOfImage,
					.loadCount = 0,
					.flags = NTHeaders.OptionalHeader.LoaderFlags,
					.sectionPointer = (uintptr_t)NTHeaders.OptionalHeader.SectionAlignment,
					.checkSum = NTHeaders.OptionalHeader.CheckSum,
					.exportInfo = this->getExports((uintptr_t)currentModuleEntry.DllBase),
					.importInfo = this->getImports((uintptr_t)currentModuleEntry.DllBase),
				};
				return tempModule;
			}
		}
		LDR_DATA_TABLE_ENTRY* currentModuleEntryBase = CONTAINING_RECORD(currentModuleEntry.InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(hProcess, currentModuleEntryBase, &currentModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr)), "Failed to read process memory");


	} while (currentModuleEntry.InMemoryOrderLinks.Flink != moduleList.Flink);

}



