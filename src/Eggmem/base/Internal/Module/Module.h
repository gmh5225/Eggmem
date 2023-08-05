#pragma once
#include <string>
#include "../../../Util/winapi.h"
#include "../../../Util/Util.h"
#include "../PE/PE.h"
#include "Import/Import.h"
#include "Export/Export.h"
#include "Section/Section.h"
class Module
{

public:

	Module(uintptr_t moduleBaseAddress);
	Module(std::string_view moduleName);
	std::vector<std::shared_ptr<Import>> imports();
	std::shared_ptr<Import> findImport(std::string_view name);
	std::vector<std::shared_ptr<Export>> exports();
	std::shared_ptr<Export> findExport(std::string_view name);
	std::vector<std::shared_ptr<Section>> sections();
	std::shared_ptr<Section> findSection(std::string_view name);
	std::string name() const;
	uintptr_t base() const;
	
	uintptr_t entry() const;
	
	size_t size() const;
	
	USHORT loadCount() const;
	
	ULONG flags() const;
	

private:

	PE& pe = PE::get();
	std::vector<std::shared_ptr<Import>> moduleImports;
	void initImports();
	static bool importsInitialized;

	std::vector<std::shared_ptr<Export>> moduleExports;
	void initExports();
	static bool exportsInitialized;

	std::vector<std::shared_ptr<Section>> moduleSections;
	void initSections();
	static bool sectionsInitialized;
	std::string moduleName;

	uintptr_t moduleBaseAddress;
	uintptr_t moduleEntryPoint;
	size_t moduleSize;
	USHORT moduleLoadCount;
	ULONG moduleFlags;

	unsigned long long moduleCheckSum;

	void initWithName(std::string_view moduleName);
	void initWithAddress(uintptr_t moduleBaseAddress);

};



