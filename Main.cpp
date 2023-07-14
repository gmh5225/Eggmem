#include "Eggmem/globals/globals.h"
#include "Eggmem/util/structs.h"
#include <iostream>
int main() {
	
	DWORD processID = eggmem::g_pMemory->GetProcId("ida.exe");
	/*HANDLE hProcess = eggmem::g_pMemory->hijackHandle(processID, processID, PROCESS_ALL_ACCESS);*/
	HANDLE hProcess{};
	CLIENT_ID* clientID = new CLIENT_ID{ (HANDLE)processID, 0 };
	OBJECT_ATTRIBUTES objectAttributes = eggmem::g_pUtil->InitObjectAttributes(nullptr, 0, nullptr, nullptr);
	eggmem::winapi::NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &objectAttributes, clientID);
	

	std::vector<eggmem::Module> modules{};
	auto result = eggmem::g_pMemory->GetModule(hProcess, std::nullopt);  

	if (std::holds_alternative<std::vector<eggmem::Module>>(result)) {
		modules = std::get<std::vector<eggmem::Module>>(result);
		
	}
	/*std::cout << modules.size() << "\n";
	for (int i = 0; i < modules.size(); i++) {
		std::wcout << modules[i].moduleName << "     " << modules[i].baseAddress << "\n";
		std::cout << modules[i].entryPoint << "\n";
	}*/

	
	
	std::cout << "HANDLE: " << hProcess << "\n";
	system("pause");


	return 0;
}