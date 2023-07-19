
#include <iostream>
#include "Eggmem.h"
int main() {
    /*struct Module {
        std::wstring moduleName;
        HMODULE moduleHandle;
        uintptr_t baseAddress;
        uintptr_t entryPoint;
        size_t size;
        USHORT loadCount;
        ULONG flags;
        uintptr_t sectionPointer;
        unsigned long long checkSum;
        std::vector<ExportInfo> exportInfo;
        std::vector<ImportInfo> importInfo;
        std::vector<imageSection> sections;
    };*/
    Eggmem eggmem(L"csgo.exe");
    std::unique_ptr<External> external = eggmem.getExternal();
    

	Module module = external->getModule(L"engine");
    
	std::wcout << "Module Name: " << module.moduleName << std::endl;
	std::cout << "Module Handle: " << std::hex << module.moduleHandle << std::endl;
	std::cout << "Base Address: " << module.baseAddress << std::endl;
	std::cout << "Entry Point: " << module.entryPoint << std::endl;
	std::cout << "Section Pointer: " << module.sectionPointer << std::endl;
	std::cout << "Size: " << std::dec << module.size << std::endl;
	std::cout << "Load Count: " << module.loadCount << std::endl;
	std::cout << "Flags: " << module.flags << std::endl;
	std::cout << "CheckSum: " << module.checkSum << std::endl;
	std::cout << "Export Info: " << module.exportInfo.size() << std::endl;
	//std::cout << "Import Info: " << tempModule.importInfo.size() << std::endl;
	for (int i = 0; i < module.sections.size(); i++) {
		std::cout << "Section " << i << " Name: " << module.sections[i].name << std::endl;
		std::cout << "Section " << i << " Size: " << module.sections[i].size << std::endl;
		std::cout << "Section " << i << std::hex << " Base Address: " << module.sections[i].baseAddress << std::endl;
		std::cout << "Section " << i << " Flags: " << module.sections[i].flags << std::endl;
	}
	for (int i = 0; i < module.exportInfo.size(); i++) {
		std::cout << "Export " << std::dec << i << " Name: " << module.exportInfo[i].exportName << std::endl;
		std::cout << "Export " << i << std::hex << " Address: " << module.exportInfo[i].exportAddress << std::endl;
	}


	return 0;
}