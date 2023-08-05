#pragma once
#include "../../../Util/winapi.h"
#include "../../../Util/Util.h"
#include <memory>
class PE
{
public:
	
	~PE() = default;

	PEB* getPEB();
	std::unique_ptr<PROCESS_BASIC_INFORMATION> PBI();
	IMAGE_DOS_HEADER* DOSHeader(uintptr_t moduleBaseAddress);
	IMAGE_NT_HEADERS* NTHeaders(uintptr_t moduleBaseAddress);
	IMAGE_DATA_DIRECTORY* DataDirectory(IMAGE_NT_HEADERS* NTHeaders);
	IMAGE_EXPORT_DIRECTORY* ExportDirectory(uintptr_t moduleBaseAddress, IMAGE_DATA_DIRECTORY* dataDirectory);
	IMAGE_IMPORT_DESCRIPTOR* ImportDescriptor(uintptr_t moduleBaseAddress);
	IMAGE_SECTION_HEADER* SectionHeader(uintptr_t moduleBaseAddress, int index);
	IMAGE_SECTION_HEADER* SectionHeader(uintptr_t moduleBaseAddress, std::string_view& sectionName);

	static PE& get();
	PE(PE const&) = delete;
	void operator=(PE const&) = delete;
private:
	PE() = default;
};

