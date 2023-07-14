#include "Eggmem/globals/globals.h"
#include "Eggmem/util/structs.h"
#include <iostream>
int main() {
	
	DWORD processID = eggmem::g_pMemory->GetProcId(L"Spotify.exe");

	HANDLE hProcess;
	CLIENT_ID clientID;
	clientID.UniqueProcess = reinterpret_cast<HANDLE>(processID);
	clientID.UniqueThread = nullptr;

	OBJECT_ATTRIBUTES objectAttributes;
	InitializeObjectAttributes(&objectAttributes, nullptr, 0, nullptr, nullptr);

	NTSTATUS status = eggmem::winapi::NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, &clientID);
	if (!NT_SUCCESS(status)) {
		eggmem::g_pUtil->eggError(__func__, "NtOpenProcess failed");
		std::cout << status;
		system("pause");
		return 0;
	}
	

	std::vector<eggmem::Module> modules{};
	auto result = eggmem::g_pMemory->GetModule(hProcess, std::nullopt);  

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
		auto result2 = eggmem::g_pMemory->getExports(hProcess, modules[i].baseAddress, std::nullopt);
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