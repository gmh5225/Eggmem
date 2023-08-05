#include "Hook.h"
#include "../../Util/Util.h"

//void Hook::Nop(BYTE* destination, uintptr_t size)
//{
//	DWORD oldProtection;
//	EGG_ASSERT(NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess, (void**)(&destination), (SIZE_T*)&size, PAGE_EXECUTE_READWRITE, &oldProtection)), "NtProtectVirtualMemory failed");
//	memset(destination, 0x90, size);
//	EGG_ASSERT(NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess, (void**)(&destination), (SIZE_T*)&size, oldProtection, &oldProtection)), "NtProtectVirtualMemory failed");
//}
