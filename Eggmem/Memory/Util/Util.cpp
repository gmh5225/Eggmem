#include "Util.h"

#include <TlHelp32.h>
#include <iostream>




void eggError(const std::string_view funcName, const std::string_view errorMessage) {
	std::cout << "[" << funcName << "] -> " << errorMessage << "\n";
}

std::vector<DWORD> Util::GetChildProcesses(DWORD parentProcessID) {
	std::vector<DWORD> childProcessIDs;

	// Take a snapshot of all processes in the system.
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);



	if (hSnapshot != INVALID_HANDLE_VALUE) {
		PROCESSENTRY32 pe32;

		pe32.dwSize = sizeof(PROCESSENTRY32);

		// Get information about the first process,
		// and exit if unsuccessful

		ZeroMemory(&pe32, sizeof(PROCESSENTRY32));
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hSnapshot, &pe32)) {
			do {
				// Check if this process's parent is the one we're looking for
				if (pe32.th32ParentProcessID == parentProcessID) {
					childProcessIDs.push_back(pe32.th32ProcessID);
				}
			} while (Process32Next(hSnapshot, &pe32));
		}

		CloseHandle(hSnapshot);
	}

	return childProcessIDs;
}

OBJECT_ATTRIBUTES Util::InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security)
{
	OBJECT_ATTRIBUTES object;

	object.Length = sizeof(OBJECT_ATTRIBUTES);
	object.ObjectName = name;
	object.Attributes = attributes;
	object.RootDirectory = hRoot;
	object.SecurityDescriptor = security;

	return object;
}

bool Ensure(bool condition, const std::string_view funcName, const std::string_view message) {
	if (!condition) {
		eggError(funcName, message);
		return false;
	}
	return true;
}


