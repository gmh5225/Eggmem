#include "Trampoline.h"
#include "../../Util/Util.h"

bool Trampoline::uninstall() {
	memcpy((void*)hookAddress, originalBytes.get(), length);
	return true;
}
#ifndef _WIN64
BYTE* Trampoline::install() {
	if (length < 5) return nullptr;
		
	BYTE* gateway = nullptr;
	SIZE_T size = length + 5; 
	EGG_ASSERT(NT_SUCCESS(winapi::NtAllocateVirtualMemory(NtCurrentProcess, (PVOID*)&gateway, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)), "NtAllocateVirtualMemory failed");
	
	memcpy(gateway, (void*)hookAddress, length);
	uintptr_t jumpAddress = ((uintptr_t)hookAddress - (uintptr_t)gateway) - 5;
	*(gateway + length) = 0xE9; 
	*(uintptr_t*)(gateway + length + 1) = jumpAddress;
	
	DWORD oldProtection;
	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&hookAddress), (SIZE_T*)&length, PAGE_EXECUTE_READWRITE, &oldProtection)), "NtProtectVirtualMemory failed");
	
	uintptr_t relativeAddress = ((uintptr_t)redirectFunctionAddress - (uintptr_t)hookAddress) - 5;
	
	*(BYTE*)hookAddress = 0xE9; 
	*(uintptr_t*)(hookAddress + 1) = relativeAddress;
	
	Nop((BYTE*)hookAddress + 5, length - 5);
	
	EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&hookAddress), (SIZE_T*)&length, oldProtection, &oldProtection)), "NtProtectVirtualMemory failed");
	
	return gateway;
}
#else
BYTE* Trampoline::install() {

if (length < 14) return nullptr;

BYTE* gateway = nullptr;
SIZE_T size = length + 14; 
EGG_ASSERT(NT_SUCCESS(winapi::NtAllocateVirtualMemory(NtCurrentProcess, (PVOID*)&gateway, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)), "NtAllocateVirtualMemory failed");

memcpy(gateway, (void*)hookAddress, length);
uintptr_t jumpAddress = (uintptr_t)hookAddress + length;
*(gateway + length) = 0xFF;
*(gateway + length + 1) = 0x25;
*(DWORD*)(gateway + length + 2) = 0;
*(uintptr_t*)(gateway + length + 6) = jumpAddress;
if (length < 14) return 0;

DWORD oldProtection;
EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&hookAddress), (SIZE_T*)&length, PAGE_EXECUTE_READWRITE, &oldProtection)), "NtProtectVirtualMemory failed");

memset((void*)hookAddress, 0x90, length);
uintptr_t* ptrToDestination = (uintptr_t*)(hookAddress + 6);
*(BYTE*)hookAddress = 0xFF;
*((BYTE*)hookAddress + 1) = 0x25;
*(DWORD*)(hookAddress + 2) = 0;
*ptrToDestination = (uintptr_t)redirectFunctionAddress;

EGG_ASSERT(NT_SUCCESS(winapi::NtProtectVirtualMemory(NtCurrentProcess, (void**)(&hookAddress), (SIZE_T*)&length, oldProtection, &oldProtection)), "NtProtectVirtualMemory failed");
return gateway;
}
#endif
