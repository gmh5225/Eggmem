#include "PE.h"

PE& PE::get()
{
	static PE instance;
	return instance;
}

std::unique_ptr<PROCESS_BASIC_INFORMATION> PE::PBI() {

	std::unique_ptr<PROCESS_BASIC_INFORMATION> pbi(new PROCESS_BASIC_INFORMATION);
	EGG_ASSERT(NT_SUCCESS(NtQueryInformationProc(NtCurrentProcess, ProcessBasicInformation, pbi.get(), sizeof(PROCESS_BASIC_INFORMATION), NULL)), "NtQueryInformationProcess failed");
	return pbi;

}

PEB* PE::getPEB()
{
	
#ifdef _WIN64
	return (PEB*)__readgsqword(0x60);
#else
	return (PEB*)__readfsdword(0x30);
#endif

}
IMAGE_DOS_HEADER* PE::DOSHeader(uintptr_t moduleBaseAddress)
{
	return (IMAGE_DOS_HEADER*)moduleBaseAddress;
}

IMAGE_NT_HEADERS* PE::NTHeaders(uintptr_t moduleBaseAddress)
{
	return (IMAGE_NT_HEADERS*)(moduleBaseAddress+ DOSHeader(moduleBaseAddress)->e_lfanew);
}

IMAGE_DATA_DIRECTORY* PE::DataDirectory(IMAGE_NT_HEADERS* NTHeaders)
{
	return NTHeaders->OptionalHeader.DataDirectory;
}
IMAGE_EXPORT_DIRECTORY* PE::ExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY* dataDirectory)
{
	return (IMAGE_EXPORT_DIRECTORY*)(moduleBaseAddress + dataDirectory->VirtualAddress);
}

IMAGE_IMPORT_DESCRIPTOR* PE::ImportDescriptor(uintptr_t moduleBaseAddress)
{
	return (IMAGE_IMPORT_DESCRIPTOR*)(moduleBaseAddress + DataDirectory(NTHeaders(moduleBaseAddress))[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
}

IMAGE_SECTION_HEADER* PE::SectionHeader(uintptr_t moduleBaseAddress, int index)
{
	return (IMAGE_SECTION_HEADER*)(moduleBaseAddress + DOSHeader(moduleBaseAddress)->e_lfanew + 4 /* Signature */ + sizeof(IMAGE_FILE_HEADER) + NTHeaders(moduleBaseAddress)->FileHeader.SizeOfOptionalHeader + (sizeof(IMAGE_SECTION_HEADER) * index));
}

IMAGE_SECTION_HEADER* PE::SectionHeader(uintptr_t moduleBaseAddress, std::string_view& sectionName)
{
	IMAGE_NT_HEADERS* ntHeaders = NTHeaders(moduleBaseAddress);

	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(NTHeaders(moduleBaseAddress));

	for (unsigned int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
	{
		if (Contains(std::string((char*)section->Name), sectionName)) {
			return section;
		}
	}

	EGG_ASSERT(false, "Section not found");
	return nullptr;
}

