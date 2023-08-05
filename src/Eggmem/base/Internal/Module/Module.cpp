#include "Module.h"
#include <algorithm>

Module::Module(uintptr_t moduleBaseAddress) {
	this->initWithAddress(moduleBaseAddress);
}

bool Module::importsInitialized = false;
bool Module::exportsInitialized = false;
bool Module::sectionsInitialized = false;

Module::Module(std::string_view moduleName) {
	this->initWithName(moduleName);
}


std::shared_ptr<Import> Module::findImport(std::string_view name)
{
	if (!this->importsInitialized) {
		initImports();
	}

	for (auto& import_ : moduleImports)
	{
		if (Contains(import_->name(), name))
		{
			return import_;
		}
	}
	eggError(__func__, "Import not found");
	return nullptr; 
}

std::shared_ptr<Export> Module::findExport(std::string_view name)
{
	for (auto& export_ : moduleExports)
	{
		if (Contains(export_->name(), name))
		{
			return export_;
		}
	}
	eggError(__func__, "Export not found");
	return nullptr; 
}

std::shared_ptr<Section> Module::findSection(std::string_view name)
{
	if (!this->sectionsInitialized) {
		initSections();
	}
	for (auto& section : moduleSections)
	{
		if (Contains(section->name(), name))
		{
			return section;
		}
	}
	eggError(__func__, "Section not found");
	return nullptr; 
}

std::vector<std::shared_ptr<Import>> Module::imports() {

	if (this->importsInitialized) {
		return moduleImports;
	}
	else {
		safeCallVEH(__func__, [this]() {
			initImports();
			});
		return moduleImports;
	}
}

std::vector<std::shared_ptr<Section>> Module::sections() {
	if (this->sectionsInitialized) {
		return moduleSections;
	}
	else {
		safeCallVEH(__func__, [this]() {
			initSections();
			});
		return moduleSections;
	}
}

std::vector<std::shared_ptr<Export>> Module::exports() {
	if (this->exportsInitialized) {
		return moduleExports;
	}
	else {
		safeCallVEH(__func__, [this]() {
			initExports();
			});
		return moduleExports;
	}
}

std::string Module::name() const {
	return this->moduleName;
}

uintptr_t Module::base() const {
	return this->moduleBaseAddress;
}

uintptr_t Module::entry() const {
	return this->moduleEntryPoint;
}

size_t Module::size() const {
	return this->moduleSize;
}

USHORT Module::loadCount() const {
	return this->moduleLoadCount;
}

ULONG Module::flags() const {
	return this->moduleFlags;
}

void Module::initImports() {

}

void Module::initExports() {

}

void Module::initSections()
{
	if (!sectionsInitialized) {
		std::vector<std::shared_ptr<Section>> sectionList;
		for (int i = 0; i < pe.NTHeaders(this->moduleBaseAddress)->FileHeader.NumberOfSections; i++) {
			IMAGE_SECTION_HEADER* sectionHeader = pe.SectionHeader((uintptr_t)moduleBaseAddress, i);

			auto section = std::make_shared<Section>(*sectionHeader);
			sectionList.push_back(section);
		}
		this->moduleSections = sectionList;
		this->sectionsInitialized = true;
	}
	else {
		return;
	}
}

void Module::initWithName(std::string_view moduleName) {
	std::wstring wModuleName(moduleName.begin(), moduleName.end());

	uintptr_t inMemoryOrderModuleList = (uintptr_t)(this->pe.getPEB()->Ldr) + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList);

	LIST_ENTRY* moduleList = (LIST_ENTRY*)inMemoryOrderModuleList;

	LDR_DATA_TABLE_ENTRY* currentModuleEntry = (LDR_DATA_TABLE_ENTRY*)CONTAINING_RECORD(moduleList->Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	do {
		USHORT length = currentModuleEntry->FullDllName.MaximumLength;
		WCHAR* buffer = new WCHAR[length / sizeof(WCHAR) + 1]();
		buffer[length / sizeof(WCHAR)] = '\0';

		std::memcpy(buffer, currentModuleEntry->FullDllName.Buffer, length);

		std::wstring text(buffer, length / sizeof(WCHAR));
		delete[] buffer;

		std::wstring lowerModuleName(wModuleName);
		std::transform(lowerModuleName.begin(), lowerModuleName.end(), lowerModuleName.begin(), ::towlower);

		std::wstring lowerTempModuleName(text);
		std::transform(lowerTempModuleName.begin(), lowerTempModuleName.end(), lowerTempModuleName.begin(), ::towlower);

		if (Contains(lowerTempModuleName, lowerModuleName)) {
			this->initWithAddress((uintptr_t)currentModuleEntry->DllBase);
		}
	} while (currentModuleEntry->InMemoryOrderLinks.Flink != moduleList->Flink);
}

void Module::initWithAddress(uintptr_t moduleBaseAddress) {
	
	IMAGE_NT_HEADERS* NTHeaders = pe.NTHeaders(moduleBaseAddress);

	this->moduleBaseAddress = moduleBaseAddress;
	this->moduleEntryPoint = NTHeaders->OptionalHeader.AddressOfEntryPoint;
	this->moduleSize = NTHeaders->OptionalHeader.SizeOfImage;
	this->moduleLoadCount = 0;
	this->moduleFlags = NTHeaders->OptionalHeader.LoaderFlags;
	this->moduleSections = sections();
	this->moduleExports = exports();
	this->moduleImports = imports();
	this->moduleCheckSum = NTHeaders->OptionalHeader.CheckSum;

}