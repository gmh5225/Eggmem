
#include <iostream>
#include "Eggmem.h"
int main() {
	std::unique_ptr<eggmem::Eggmem> eggmem = std::make_unique<eggmem::Eggmem>();
	DWORD processID =  eggmem->pMemory->GetProcId(L"Spotify.exe");

	HANDLE hProcess;
	CLIENT_ID clientID;
	clientID.UniqueProcess = reinterpret_cast<HANDLE>(processID);
	clientID.UniqueThread = nullptr;

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, nullptr, 0, nullptr, nullptr);

	NTSTATUS status = eggmem::winapi::NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, &clientID);
	if (!NT_SUCCESS(status)) {
		eggmem->pUtil->eggError(__func__, "NtOpenProcess failed");
		std::cout << status;
		system("pause");
		return 0;
	}
	

	std::vector<eggmem::Module> modules{};
	auto result = eggmem->pMemory->GetModule(hProcess);  

	if (std::holds_alternative<std::vector<eggmem::Module>>(result)) {
		modules = std::get<std::vector<eggmem::Module>>(result);
		
	}
	

	for (int i = 1; i < modules.size(); i++) {
		std::wcout << "module name: " << modules[i].moduleName << "\n";
		std::cout <<  "base address: " <<std::hex << modules[i].baseAddress << "\n";
		std::cout <<  "entry point: " <<modules[i].entryPoint << "\n";
		std::cout << "section pointer" << modules[i].sectionPointer << "\n";
		std::cout <<  "size: " <<std::dec << modules[i].size << "\n";
		std::cout <<  "flags: " <<modules[i].flags << "\n";
		std::cout <<  "load count: " <<modules[i].loadCount << "\n";
		auto result2 = eggmem->pMemory->getExports(hProcess, modules[i].baseAddress);
		if (std::holds_alternative<std::vector<eggmem::ExportInfo>>(result2)) {
			auto exports = std::get<std::vector<eggmem::ExportInfo>>(result2);
			for (int j = 0; j < exports.size(); j++) {
				std::cout << "export name: " << exports[j].exportName << " [" << std::hex << exports[j].exportAddress << "]\n";
		
			}
		}
	}

	
	
	std::cout << "HANDLE: " << hProcess << "\n";
	system("pause");


	return 0;
}