#include "VEH.h"
#include "../../../Util/Util.h"
#include "../../../Util/winapi.h"
std::unordered_map<void*, VEH*> VEH::instancesMap;
BYTE* VEH::install()
{

	instancesMap[original] = this;
	if (areFunctionsInTheSamePage(original, hookFunction))
		return 0;

	VEHHandle = AddVectoredExceptionHandler(true, (PVECTORED_EXCEPTION_HANDLER)Handler);

	if (VEHHandle && VirtualProtect((LPVOID)original, 1, PAGE_EXECUTE_READ | PAGE_GUARD, &oldProtection)) {
		_installed = true;
		return (BYTE*)1;
	}

	return 0;
}

uintptr_t VEH::getOriginalFunction() const
{
	return (uintptr_t)original;
}

long __stdcall VEH::Handler(EXCEPTION_POINTERS* pExceptionInfo)
{
	auto iter = instancesMap.find((void*)pExceptionInfo->ContextRecord->XIP);
	if (iter == instancesMap.end())
		return EXCEPTION_CONTINUE_SEARCH;

	VEH* instance = iter->second;

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION)
	{
		if (pExceptionInfo->ContextRecord->XIP == (uintptr_t)instance->original)
		{
			pExceptionInfo->ContextRecord->XIP = (uintptr_t)instance->hookFunction;
		}

		pExceptionInfo->ContextRecord->EFlags |= 0x100;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	if (pExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP)
	{
		unsigned long dwOld;
		size_t length = 1;
		EGG_ASSERT(NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess, (void**)(&instance->original), (SIZE_T*)&length, PAGE_EXECUTE_READ | PAGE_GUARD, &dwOld)), "NtProtectVirtualMemory failed");
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

bool VEH::uninstall()
{

	if (!_installed)
		return false;
	DWORD old;
	if (VEHHandle && VirtualProtect((LPVOID)original, 1, oldProtection, &old) && RemoveVectoredExceptionHandler(VEHHandle)) {
		instancesMap.erase(original);
		_installed = false;
		return true;
	}

	return false;
}

bool VEH::areFunctionsInTheSamePage(void* function1, void* function2)
{
	MEMORY_BASIC_INFORMATION mbi1;
	if (!VirtualQuery(function1, &mbi1, sizeof(mbi1)))
		return true;

	MEMORY_BASIC_INFORMATION mbi2;
	if (!VirtualQuery(function2, &mbi2, sizeof(mbi2)))
		return true;

	if (mbi1.BaseAddress == mbi2.BaseAddress)
		return true; 

	return false;
}
