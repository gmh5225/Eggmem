#include "External.h"
#include <TlHelp32.h>
#include <algorithm>
#include <assert.h>
#include <iostream>
#pragma warning(disable: 6289)
__pragma(warning(suppress: 6289))

External::External(std::wstring processName) {

	this->processName = processName;
	this->getPID();
	this->openHandle(OPEN_PROCESS_HANDLE, PROCESS_ALL_ACCESS);

}

std::wstring External::getProcName() {
	return this->processName;
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
		EGG_ASSERT(this->hProcess != INVALID_HANDLE_VALUE, "Handle is invalid");
		PROCESS_BASIC_INFORMATION pbi;
		EGG_ASSERT(NT_SUCCESS(winapi::NtQueryInformationProcess(this->hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)), "Failed to query process information");
		this->pbi = pbi;
		this->pbiInitialized = true;
	}
}

PROCESS_BASIC_INFORMATION External::getPBI() {
	if (!this->pbiInitialized) {
		this->initPBI();
	}
	return this->pbi;
}

void External::initPEB() {

	PROCESS_BASIC_INFORMATION pbi;
	EGG_ASSERT(NT_SUCCESS(winapi::NtQueryInformationProcess(this->hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)), "Failed to query process information");

	if (!this->pebInitialized) {
		PEB peb = this->rpm<PEB>((uintptr_t)pbi.PebBaseAddress);
		this->peb = &peb;
		this->pebInitialized = true;
	}
}

PPEB External::getPEB() {
	if (!this->pebInitialized) {
		this->initPEB();
	}
	return this->peb;
}

IMAGE_DOS_HEADER External::getDOSHeader(uintptr_t moduleBaseAddress) {
	return this->rpm<IMAGE_DOS_HEADER>(moduleBaseAddress);
}

IMAGE_NT_HEADERS External::getNTHeaders(uintptr_t moduleBaseAddress) {
	return this->rpm<IMAGE_NT_HEADERS>(moduleBaseAddress + this->getDOSHeader(moduleBaseAddress).e_lfanew);
}

IMAGE_DATA_DIRECTORY External::getDataDirectory(IMAGE_NT_HEADERS NTHeaders, int index) {
	EGG_ASSERT(index < NTHeaders.OptionalHeader.NumberOfRvaAndSizes, "Index out of range");
	return NTHeaders.OptionalHeader.DataDirectory[index];
}

IMAGE_EXPORT_DIRECTORY External::getExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory) {
	return this->rpm<IMAGE_EXPORT_DIRECTORY>(moduleBaseAddress + dataDirectory.VirtualAddress);
}

IMAGE_IMPORT_DESCRIPTOR External::getImportDescriptor(uintptr_t moduleBaseAddress) {

	IMAGE_NT_HEADERS ntHeaders = this->getNTHeaders(moduleBaseAddress);
	DWORD importDirectoryRVA = ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	IMAGE_IMPORT_DESCRIPTOR importDescriptor = this->rpm<IMAGE_IMPORT_DESCRIPTOR>(moduleBaseAddress + importDirectoryRVA);
 	return importDescriptor;
}

IMAGE_SECTION_HEADER External::getSectionHeader(uintptr_t moduleBaseAddress, int index)
{

	IMAGE_DOS_HEADER dosHeader = this->getDOSHeader(moduleBaseAddress);
	IMAGE_NT_HEADERS ntHeaders = this->getNTHeaders(moduleBaseAddress);
	/*IMAGE_SECTION_HEADER sectionHeader = this->rpm<IMAGE_SECTION_HEADER>(moduleBaseAddress + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS) + index * sizeof(IMAGE_SECTION_HEADER));*/
	DWORD offsetToSectionTable = dosHeader.e_lfanew + 4 /* Signature */ + sizeof(IMAGE_FILE_HEADER) + ntHeaders.FileHeader.SizeOfOptionalHeader;
	return this->rpm<IMAGE_SECTION_HEADER>(moduleBaseAddress + offsetToSectionTable + index * sizeof(IMAGE_SECTION_HEADER));

	
}

HANDLE External::openHandle(uintptr_t openHandleMethod, ACCESS_MASK handleAccessRights)
{

	if (openHandleMethod == OPEN_PROCESS_HANDLE) {
		OBJECT_ATTRIBUTES objectAttributes = this->util->InitObjectAttributes(nullptr, 0, nullptr, nullptr);
		CLIENT_ID clientID { .UniqueProcess = (HANDLE)this->pid, .UniqueThread = nullptr };
		HANDLE handle;
		EGG_ASSERT(NT_SUCCESS(winapi::NtOpenProcess(&handle, handleAccessRights, &objectAttributes, &clientID)), "Failed to open process handle");
		std::cout << "Opened process handle: " << handle << std::endl;
		this->hProcess = handle;
		return this->hProcess;
	}
	else if (openHandleMethod == HIJACK_PROCESS_HANDLE) {
		//todo
	}
}

std::vector<ExportInfo> External::getExports(uintptr_t baseAddress) {
	

	std::vector<ExportInfo> exports;
	auto NTHeaders = this->getNTHeaders(baseAddress);
	auto exportDirectory = this->getExportDirectory(baseAddress, this->getDataDirectory(NTHeaders, 0));
	

	const ULONG_PTR NameTableAddr = baseAddress + exportDirectory.AddressOfNames;
	const ULONG_PTR RVATableAddr = baseAddress + exportDirectory.AddressOfFunctions;
	const ULONG_PTR OrdTableAddr = baseAddress + exportDirectory.AddressOfNameOrdinals;

	auto NameTable = std::unique_ptr<uint32_t[]>(new uint32_t[exportDirectory.NumberOfNames]);
	auto RVATable = std::unique_ptr<uint32_t[]>(new uint32_t[exportDirectory.NumberOfFunctions]);
	auto OrdTable = std::unique_ptr<uint32_t[]>(new uint32_t[exportDirectory.NumberOfNames]);

	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(this->hProcess, (PVOID)NameTableAddr, NameTable.get(), sizeof(unsigned long) * exportDirectory.NumberOfNames, nullptr)), "Failed to read process memory");
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(this->hProcess, (PVOID)RVATableAddr, RVATable.get(), sizeof(unsigned long) * exportDirectory.NumberOfFunctions, nullptr)), "Failed to read process memory");
	EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(this->hProcess, (PVOID)OrdTableAddr, OrdTable.get(), sizeof(unsigned short) * exportDirectory.NumberOfNames, nullptr)), "Failed to read process memory");

	for (DWORD i = 0; i < exportDirectory.NumberOfNames; ++i) {

		auto names = std::make_unique<uint32_t[]>(exportDirectory.NumberOfNames);
		winapi::NtReadVirtualMemory(this->hProcess, (PVOID)(baseAddress + exportDirectory.AddressOfNames + i), names.get(), exportDirectory.NumberOfNames, nullptr);

		char name[256] = {};
		winapi::NtReadVirtualMemory(this->hProcess, (PVOID)(baseAddress + names[0]), &name, sizeof(name), nullptr);

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
	std::vector<ImportInfo> imports;
	IMAGE_IMPORT_DESCRIPTOR importDescriptorObject = this->getImportDescriptor(baseAddress);
	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = &importDescriptorObject;

	for (int i = 0; importDescriptor[i].Characteristics != 0; i++) {
				ImportInfo importInfo;
		char name[256] = {};

		for (int j = 0; j < 255 && name[j] != '\0'; j++) {
			name[j] = this->rpm<char>(baseAddress + importDescriptor[i].Name + j);
		}
		name[255] = '\0';  // Ensure the string is null-terminated

		std::cout << "Module name: " << std::string(name) << std::endl;
		importInfo.dllName = std::string(name);


		if (importDescriptor[i].OriginalFirstThunk != 0) {
			IMAGE_THUNK_DATA originalThunkb = this->rpm<IMAGE_THUNK_DATA>(baseAddress + importDescriptor[i].OriginalFirstThunk);
			IMAGE_THUNK_DATA* originalThunk = &originalThunkb;

			while (originalThunk->u1.Function != 0) {

				if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					importInfo.importNames.emplace_back("Ordinal");
					importInfo.importAddress.emplace_back(originalThunk->u1.Ordinal & (~IMAGE_ORDINAL_FLAG));
				}
				else {
					IMAGE_IMPORT_BY_NAME importByName = this->rpm<IMAGE_IMPORT_BY_NAME>(baseAddress + originalThunk->u1.AddressOfData);
					char importName[256] = {};

					EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(this->hProcess, (PVOID)(baseAddress + reinterpret_cast<uintptr_t>(importByName.Name)), &importName, sizeof(importName), nullptr)), "Failed to read process memory");

					importName[255] = '\0';  // Ensure the string is null-terminated
					importInfo.importNames.emplace_back(std::string(importName));
					std::cout << "Import Name: " << importInfo.importNames.data() << std::endl;
					importInfo.importAddress.emplace_back(reinterpret_cast<uintptr_t>(originalThunk));
					std::cout << "Import Address: " << std::hex << importInfo.importAddress.data() << std::endl;
				}

				imports.emplace_back(importInfo);
				originalThunk++;  // Go to the next IMAGE_THUNK_DATA structure
			}
		}
	}

	return imports;
}


Module External::getModule(std::wstring moduleName) {

	Module module;
	uintptr_t inMemoryOrderModuleList = (uintptr_t)(this->getPEB()->Ldr) + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);
	LIST_ENTRY moduleList = this->rpm<LIST_ENTRY>(inMemoryOrderModuleList);

	LDR_DATA_TABLE_ENTRY currentModuleEntry = this->rpm<LDR_DATA_TABLE_ENTRY>((uintptr_t)(CONTAINING_RECORD(moduleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)));

	do {
		USHORT length = (USHORT)currentModuleEntry.FullDllName.MaximumLength;
		WCHAR* buffer = new WCHAR[length / sizeof(WCHAR) + 1]();
		buffer[length / sizeof(WCHAR)] = '\0';
		ULONG_PTR FullDllNameBufferAddr = (ULONG_PTR)currentModuleEntry.FullDllName.Buffer;
		EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(this->hProcess, (void*)FullDllNameBufferAddr, buffer, length, nullptr)), "Failed to read process memory");
		std::wstring text(buffer, length / sizeof(WCHAR));
		delete[] buffer;

		
		IMAGE_NT_HEADERS NTHeaders = this->getNTHeaders((uintptr_t)currentModuleEntry.DllBase);
		std::vector<imageSection> sectionList;
		for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++) {
			IMAGE_SECTION_HEADER sectionHeader = this->getSectionHeader((uintptr_t)currentModuleEntry.DllBase, i);

 			imageSection section;
			section.name = std::string(reinterpret_cast<const char*>(sectionHeader.Name), strnlen(reinterpret_cast<const char*>(sectionHeader.Name), 8));
			section.baseAddress = (uintptr_t)currentModuleEntry.DllBase + sectionHeader.VirtualAddress;
			section.size = sectionHeader.Misc.VirtualSize;
			section.flags = sectionHeader.Characteristics;

			sectionList.push_back(section);
		}
		if (!moduleName.empty()) {
			std::wstring lowerModuleName(moduleName);
			std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::towlower);

			std::wstring lowerTempModuleName(text);
			std::transform(lowerTempModuleName.begin(), lowerTempModuleName.end(), lowerTempModuleName.begin(), ::towlower);
			std::wcout << lowerModuleName << " " << lowerTempModuleName << std::endl;
			//std::cout << this->getImports((uintptr_t)currentModuleEntry.DllBase).size() << std::endl;
			if (this->util->Contains(lowerTempModuleName, lowerModuleName)) {
				Module tempModule{
					.moduleName = text,
					.moduleHandle = (HMODULE)NTHeaders.OptionalHeader.ImageBase,
					.baseAddress = (uintptr_t)currentModuleEntry.DllBase,
					.entryPoint = NTHeaders.OptionalHeader.AddressOfEntryPoint,
					.size = NTHeaders.OptionalHeader.SizeOfImage,
					.loadCount = 0,
					.flags = NTHeaders.OptionalHeader.LoaderFlags,
					.sectionPointer = (uintptr_t)NTHeaders.OptionalHeader.SectionAlignment,
					.checkSum = NTHeaders.OptionalHeader.CheckSum,
					.exportInfo = this->getExports((uintptr_t)currentModuleEntry.DllBase),
					//.importInfo = this->getImports((uintptr_t)currentModuleEntry.DllBase),
					.sections = sectionList,
				};
				return tempModule;
			}
		}
		else {
			//print out all the info
			Module tempModule{
				.moduleName = text,
				.moduleHandle = (HMODULE)NTHeaders.OptionalHeader.ImageBase,
				.baseAddress = (uintptr_t)currentModuleEntry.DllBase,
				.entryPoint = NTHeaders.OptionalHeader.AddressOfEntryPoint,
				.size = NTHeaders.OptionalHeader.SizeOfImage,
				.loadCount = 0,
				.flags = NTHeaders.OptionalHeader.LoaderFlags,
				.sectionPointer = (uintptr_t)NTHeaders.OptionalHeader.SectionAlignment,
				.checkSum = NTHeaders.OptionalHeader.CheckSum,
				.exportInfo = this->getExports((uintptr_t)currentModuleEntry.DllBase),
				//.importInfo = this->getImports((uintptr_t)currentModuleEntry.DllBase),
				.sections = sectionList,
			};
			std::wcout << "Module Name: " << tempModule.moduleName << std::endl;
			std::cout << "Module Handle: " << std::hex << tempModule.moduleHandle << std::endl;
			std::cout << "Base Address: " << tempModule.baseAddress << std::endl;
			std::cout << "Entry Point: " << tempModule.entryPoint << std::endl;
			std::cout << "Section Pointer: " << tempModule.sectionPointer << std::endl;
			std::cout << "Size: " << std::dec << tempModule.size << std::endl;
			std::cout << "Load Count: " << tempModule.loadCount << std::endl;
			std::cout << "Flags: " << tempModule.flags << std::endl;
			std::cout << "CheckSum: " << tempModule.checkSum << std::endl;
			std::cout << "Export Info: " << tempModule.exportInfo.size() << std::endl;
			//std::cout << "Import Info: " << tempModule.importInfo.size() << std::endl;
			for (int i = 0; i < tempModule.sections.size(); i++) {
				std::cout << "Section " << i << " Name: " << tempModule.sections[i].name << std::endl;
				std::cout << "Section " << i << " Size: " << tempModule.sections[i].size << std::endl;
				std::cout << "Section " << i << std::hex << " Base Address: " << tempModule.sections[i].baseAddress << std::endl;
				std::cout << "Section " << i << " Flags: " << tempModule.sections[i].flags << std::endl;
			}
			std::cout << "Num of exports: " << tempModule.exportInfo.size() << std::endl;
			/*for (int i = 0; i < tempModule.exportInfo.size(); i++) {
				std::cout << "Export " << std::dec << i << " Name: " << tempModule.exportInfo[i].exportName << std::endl;
				std::cout << "Export " << i << std::hex << " Address: " << tempModule.exportInfo[i].exportAddress << std::endl;
			}*/
		}
		LDR_DATA_TABLE_ENTRY* currentModuleEntryBase = CONTAINING_RECORD(currentModuleEntry.InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

		EGG_ASSERT(NT_SUCCESS(winapi::NtReadVirtualMemory(this->hProcess, currentModuleEntryBase, &currentModuleEntry, sizeof(LDR_DATA_TABLE_ENTRY), nullptr)), "Failed to read process memory");


	} while (currentModuleEntry.InMemoryOrderLinks.Flink != moduleList.Flink);
	return Module{};
}



