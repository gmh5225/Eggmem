#include "Internal.h"
#include "../Util/Util.h"
#include <algorithm>
#include <iostream>
Internal::Internal() {
	


}


std::wstring Internal::getProcName()
{
	return this->processName;
}



void Internal::initPEB()
{
	if (!pbiInitialized)
		initPBI();

#ifdef _WIN64
	this->peb = (PPEB)__readgsqword(0x60);
	this->pebInitialized = true;
	
	#else
	peb = (PPEB)__readfsdword(0x30);
	this->pebInitialized = true;
	#endif
}

PPEB Internal::getPEB()
{
	if (!this->pebInitialized)
		this->initPEB();

	return this->peb;
}

void Internal::initPID()
{
	this->pid = GetCurrentProcessId();
	this->pidInitialized = true;
}

DWORD Internal::getPID()
{
	if (!this->pidInitialized)
		this->initPID();

	return this->pid;
}

IMAGE_DOS_HEADER Internal::getDOSHeader(uintptr_t moduleBaseAddress)
{
	return *(IMAGE_DOS_HEADER*)moduleBaseAddress;
}

IMAGE_NT_HEADERS Internal::getNTHeaders(uintptr_t moduleBaseAddress)
{
	return *(IMAGE_NT_HEADERS*)(moduleBaseAddress + getDOSHeader(moduleBaseAddress).e_lfanew);
}

IMAGE_DATA_DIRECTORY Internal::getDataDirectory(IMAGE_NT_HEADERS NTHeaders, int index)
{
	return NTHeaders.OptionalHeader.DataDirectory[index];
}

IMAGE_EXPORT_DIRECTORY getExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory) {
	return *(IMAGE_EXPORT_DIRECTORY*)(moduleBaseAddress + dataDirectory.VirtualAddress);
}

IMAGE_IMPORT_DESCRIPTOR Internal::getImportDescriptor(uintptr_t moduleBaseAddress)
{
	return *(IMAGE_IMPORT_DESCRIPTOR*)(moduleBaseAddress + getNTHeaders(moduleBaseAddress).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
}

IMAGE_SECTION_HEADER Internal::getSectionHeader(uintptr_t moduleBaseAddress, int index)
{
	DWORD offsetToSectionTable = getDOSHeader(moduleBaseAddress).e_lfanew + 4 /* Signature */ + sizeof(IMAGE_FILE_HEADER) + getNTHeaders(moduleBaseAddress).FileHeader.SizeOfOptionalHeader;
	return *(IMAGE_SECTION_HEADER*)(moduleBaseAddress + offsetToSectionTable + (sizeof(IMAGE_SECTION_HEADER) * index));
}

//void Internal::Nop(BYTE* destination, uintptr_t size)
//{
//	DWORD oldProtection;
//	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&destination), (SIZE_T*)&size, PAGE_EXECUTE_READWRITE, &oldProtection)), "NtProtectVirtualMemory failed");
//	memset(destination, 0x90, size);
//	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&destination), (SIZE_T*)&size, oldProtection, &oldProtection)), "NtProtectVirtualMemory failed");
//}
//
//void Internal::Patch(BYTE* destination, BYTE* source, uintptr_t size)
//{
//	DWORD oldProtection;
//	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&destination), (SIZE_T*)&size, PAGE_EXECUTE_READWRITE, &oldProtection)), "NtProtectVirtualMemory failed");
//	memcpy(destination, source, size);
//	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&destination), (SIZE_T*)&size, oldProtection, &oldProtection)), "NtProtectVirtualMemory failed");
//}

//bool Internal::Detour32(BYTE* source, BYTE* destination, const uintptr_t length)
//{
//	if (length < 5) return false;
//
//	DWORD oldProtection;
//	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&source), (SIZE_T*)&length, PAGE_EXECUTE_READWRITE, &oldProtection)), "NtProtectVirtualMemory failed");
//
//	uintptr_t relativeAddress = ((uintptr_t)destination - (uintptr_t)source) - 5;
//
//	*source = 0xE9; 
//	*(uintptr_t*)(source + 1) = relativeAddress;
//
//	Nop(source + 5, length - 5);
//
//	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&source), (SIZE_T*)&length, oldProtection, &oldProtection)), "NtProtectVirtualMemory failed");
//
//	return true;
//}
//
//BYTE* Internal::Tramp
// 
// 
// 
// 32(BYTE* source, BYTE* destination, const uintptr_t length)
//{
//	if (length < 5) return nullptr;
//	
//	BYTE* gateway = nullptr;
//	SIZE_T size = length + 5; 
//	EGG_ASSERT(NT_SUCCESS(winapi::NtAllocateVirtualMemory(NtCurrentProcess, (PVOID*)&gateway, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)), "NtAllocateVirtualMemory failed");
//
//	memcpy(gateway, source, length);
//	uintptr_t jumpAddress = ((uintptr_t)source - (uintptr_t)gateway) - 5;
//	*(gateway + length) = 0xE9; 
//	*(uintptr_t*)(gateway + length + 1) = jumpAddress;
//
//	Detour32(source, destination, length);
//
//	return gateway;
//}
//
//bool Internal::Detour64(BYTE* source, BYTE* destination, const uintptr_t length)
//{
//	if (length < 14) return false;
//
//	DWORD oldProtection;
//	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&source), (SIZE_T*)&length, PAGE_EXECUTE_READWRITE, &oldProtection)), "NtProtectVirtualMemory failed");
//
//	memset(source, 0x90, length);
//	uintptr_t* ptrToDestination = (uintptr_t*)(source + 6);
//	*source = 0xFF;
//	*(source + 1) = 0x25;
//	*(DWORD*)(source + 2) = 0;
//	*ptrToDestination = (uintptr_t)destination;
//
//	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&source), (SIZE_T*)&length, oldProtection, &oldProtection)), "NtProtectVirtualMemory failed");
//
//	return true;
//}
//
//BYTE* Internal::TrampHook64(BYTE* source, BYTE* destination, const uintptr_t length)
//{
//	if (length < 14) return nullptr;
//
//	BYTE* gateway = nullptr;
//	SIZE_T size = length + 14; 
//	EGG_ASSERT(NT_SUCCESS(winapi::NtAllocateVirtualMemory(NtCurrentProcess, (PVOID*)&gateway, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)), "NtAllocateVirtualMemory failed");
//
//	memcpy(gateway, source, length);
//	uintptr_t jumpAddress = (uintptr_t)source + length;
//	*(gateway + length) = 0xFF;
//	*(gateway + length + 1) = 0x25;
//	*(DWORD*)(gateway + length + 2) = 0;
//	*(uintptr_t*)(gateway + length + 6) = jumpAddress;
//
//	Detour64(source, destination, length);
//
//	return gateway;
//}

std::vector<ExportInfo> Internal::getExports(uintptr_t moduleBaseAddress)
{
	std::vector<ExportInfo> exports;
	
	auto NTHeaders = getNTHeaders(moduleBaseAddress);

	auto exportDirectory = getExportDirectory(moduleBaseAddress, getDataDirectory(NTHeaders, IMAGE_DIRECTORY_ENTRY_EXPORT));
	
	const unsigned long* NameTable = reinterpret_cast<const unsigned long*>(moduleBaseAddress + exportDirectory.AddressOfNames);
	const unsigned long* RVATable = reinterpret_cast<const unsigned long*>(moduleBaseAddress + exportDirectory.AddressOfFunctions);

	for (int i = 0; i < exportDirectory.NumberOfNames; ++i) {
		const char* ExportName = reinterpret_cast<const char*>(moduleBaseAddress + NameTable[i]);
		ExportInfo exportInfo{
			.exportName = std::string(ExportName),
			.exportAddress = moduleBaseAddress + RVATable[i],
		};
		exports.emplace_back(exportInfo);
	}
	return exports;

}

Module Internal::getModule(std::wstring moduleName) {

	uintptr_t inMemoryOrderModuleList = (uintptr_t)(this->getPEB()->Ldr) + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);
	
	LIST_ENTRY moduleList = *(LIST_ENTRY*)inMemoryOrderModuleList;
	

	LDR_DATA_TABLE_ENTRY currentModuleEntry = *(LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(moduleList.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	do {

		USHORT length = currentModuleEntry.FullDllName.MaximumLength;
		WCHAR* buffer = new WCHAR[length / sizeof(WCHAR) + 1]();
		buffer[length / sizeof(WCHAR)] = '\0';

		std::memcpy(buffer, currentModuleEntry.FullDllName.Buffer, length);

		std::wstring text(buffer, length / sizeof(WCHAR));
		delete[] buffer;

		std::vector<imageSection> sectionList;
		IMAGE_NT_HEADERS NTHeaders = this->getNTHeaders((uintptr_t)currentModuleEntry.DllBase);
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
			else {
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
		}

		currentModuleEntry = *(LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(currentModuleEntry.InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

	} while (currentModuleEntry.InMemoryOrderLinks.Flink != moduleList.Flink);
}

bool Internal::unlinkModule(Module module) {



}

IMAGE_EXPORT_DIRECTORY Internal::getExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY dataDirectory)
{
	return *(IMAGE_EXPORT_DIRECTORY*)(moduleBaseAddress + this->getDataDirectory(getNTHeaders(moduleBaseAddress), 0).VirtualAddress);
}

void Internal::initPBI() {

	PROCESS_BASIC_INFORMATION pbi;
	EGG_ASSERT(NT_SUCCESS(NtQueryInformationProcess(NtCurrentProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)), "Failed to query process information");
	this->pbi = pbi;
	this->pbiInitialized = true;

}

PROCESS_BASIC_INFORMATION Internal::getPBI() {

	if (!this->pbiInitialized)
		this->initPBI();

	return this->pbi;

}


