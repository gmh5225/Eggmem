#include "Util.h"
#include <rtcerr.h>
#include <iostream>
#include <TlHelp32.h>
inline void eggError(const std::string_view funcName, const std::string_view errorMessage) {

	throw std::runtime_error(std::string(funcName) + ": " + std::string(errorMessage));

}

std::vector<DWORD> GetChildProcesses(DWORD parentProcessID) {
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

OBJECT_ATTRIBUTES constexpr InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security)
{
	OBJECT_ATTRIBUTES object;

	object.Length = sizeof(OBJECT_ATTRIBUTES);
	object.ObjectName = name;
	object.Attributes = attributes;
	object.RootDirectory = hRoot;
	object.SecurityDescriptor = security;

	return object;
}

CLIENT_ID constexpr InitClientId(HANDLE hProcess, HANDLE hThread)
{
	CLIENT_ID id;

	id.UniqueProcess = hProcess;
	id.UniqueThread = hThread;

	return id;
}

UNICODE_STRING constexpr InitUnicodeString(const wchar_t* str, USHORT length)
{
	UNICODE_STRING string;

	string.Buffer = (wchar_t*)str;
	string.Length = length;
	string.MaximumLength = length + 2;

	return string;
}

LONG CALLBACK VEHHandler(EXCEPTION_POINTERS* ExceptionInfo) {
	std::cout << "VEH triggered for exception code: " << ExceptionInfo->ExceptionRecord->ExceptionCode << "\n";
	std::cout << "Exception flags: " << ExceptionInfo->ExceptionRecord->ExceptionFlags << "\n";
	std::cout << "Exception address: " << ExceptionInfo->ExceptionRecord->ExceptionAddress << "\n";
	return EXCEPTION_CONTINUE_SEARCH;
}

int SEHFilter(unsigned int code, struct _EXCEPTION_POINTERS* ep) {
	std::cout << "SEH triggered for exception code: " << code << "\n";
	std::cout << "Exception flags: " << ep->ExceptionRecord->ExceptionFlags << "\n";
	std::cout << "Exception address: " << ep->ExceptionRecord->ExceptionAddress << "\n";
	return EXCEPTION_EXECUTE_HANDLER;
}



bool Contains(const std::wstring_view& str, const std::wstring_view& substring)
{
	return str.find(substring) != std::wstring::npos;
}

bool Contains(const std::string_view& str, const std::string_view& substring)
{
	return str.find(substring) != std::string::npos;
}