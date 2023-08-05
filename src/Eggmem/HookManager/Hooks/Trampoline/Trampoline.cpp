//void* Trampoline::FindSuitableMemory() {
//	SYSTEM_INFO systemInfo;
//	GetSystemInfo(&systemInfo);
//
//	MEMORY_BASIC_INFORMATION mbi;
//	LPVOID pStart = systemInfo.lpMinimumApplicationAddress;
//	LPVOID pEnd = systemInfo.lpMaximumApplicationAddress;
//	LPVOID pLowerBound = (BYTE*)ogFunction - 0x7FFFFFFF;
//	LPVOID pUpperBound = (BYTE*)ogFunction + 0x7FFFFFFF;
//
//	while (pStart < pEnd) {
//		if (VirtualQueryEx(NtCurrentProcess, pStart, &mbi, sizeof(mbi)) == sizeof(mbi)) {
//			if (mbi.State == MEM_FREE && mbi.RegionSize >= length + 5) {
//				if (mbi.BaseAddress >= pLowerBound && mbi.BaseAddress <= pUpperBound) {
//					this->gateway = (BYTE*)mbi.BaseAddress;
//					return mbi.BaseAddress;
//				}
//			}
//			pStart = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
//		}
//		else {
//			break;
//		}
//	}
//
//	return nullptr;
//}
#include "Trampoline.h"
#include "../../../Util/Util.h"
#include "../../../Util/winapi.h"


bool Trampoline::uninstall() {
	return safeCallVEH(__func__, [&] {
		safeCallSEH("memcpy", [&] {
			memcpy((void*)original, originalBytes.get(), length);
			});
		this->_installed = false;
		return true;
		});
}

uintptr_t Trampoline::getOriginalFunction() const
{
    return (uintptr_t)gateway;
}


void* Trampoline::FindSuitableMemory() {
   
        SYSTEM_INFO systemInfo;
        GetSystemInfo(&systemInfo);

        MEMORY_BASIC_INFORMATION mbi;
        void* pStart = systemInfo.lpMinimumApplicationAddress;
        void* pEnd = systemInfo.lpMaximumApplicationAddress;
        void* pLowerBound = (BYTE*)original - 0x7FFFFFFF;

        if (pLowerBound > original) {
			pLowerBound = systemInfo.lpMinimumApplicationAddress;
		}

        void* pUpperBound = (BYTE*)original + 0x7FFFFFFF;

        if (pUpperBound < original) {
            pUpperBound = systemInfo.lpMaximumApplicationAddress;
        }

        while (pStart < pEnd) {
            if (VirtualQueryEx(NtCurrentProcess, pStart, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                if (mbi.State == MEM_FREE && mbi.RegionSize >= length + 5 && mbi.Protect == PAGE_EXECUTE_READWRITE) {
                    if (mbi.BaseAddress >= pLowerBound && mbi.BaseAddress <= pUpperBound) {
                        this->gateway = (BYTE*)mbi.BaseAddress;
                        return mbi.BaseAddress;
                    }
                }
                pStart = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
            }
            else {
                break;
            }
        }

        return (void*)0;
        
}

#ifndef _WIN64
BYTE* Trampoline::install() {
    if (length < 5) return nullptr;

    return safeCallSEH(__func__, [this] {
        gateway = (BYTE*)(safeCallVEH("FindSuitableMemory", [this] { return FindSuitableMemory(); }));
        if (gateway == nullptr) {
            std::cout << "Failed to find suitable memory, allocating space for gateway instead. \n";
            gateway = (BYTE*)mem.allocate(length + 5, PAGE_EXECUTE_READWRITE);
				
        }

        memcpy(gateway, original, length);

        intptr_t jumpOffset = (intptr_t)original - ((intptr_t)gateway + length + 5);
        *(gateway + length) = 0xE9;
        *(intptr_t*)(gateway + length + 1) = jumpOffset;

        DWORD oldProtection;
        EGG_ASSERT(NT_SUCCESS(safeCallVEH("NtProtectVirtualMemory", [&] {
            return NtProtectVirtualMemory(NtCurrentProcess, (void**)(&original), (SIZE_T*)&length, PAGE_EXECUTE_READWRITE, &oldProtection);
            })), "NtProtectVirtualMemory failed");

        intptr_t hookOffset = (intptr_t)hookFunction - ((intptr_t)original + 5);
        *(BYTE*)original = 0xE9;
        *(intptr_t*)((intptr_t)original + 1) = hookOffset;

        safeCallSEH("memset", [&] { return memset((BYTE*)original + 5, 0x90, length - 5); });

        EGG_ASSERT(NT_SUCCESS(safeCallVEH("NtProtectVirtualMemory", [&] {
            return NtProtectVirtualMemory(NtCurrentProcess, (void**)(&original), (SIZE_T*)&length, oldProtection, &oldProtection);
            })), "NtProtectVirtualMemory failed");

        return gateway;
        });
}
#else
BYTE* Trampoline::install() {
    if (length < 5) return nullptr;

    return safeCallSEH(__func__, [this] {
        gateway = (BYTE*)(safeCallVEH("FindSuitableMemory", [this] { return FindSuitableMemory(); }));

        DWORD oldProtection;
        EGG_ASSERT(NT_SUCCESS(safeCallVEH("NtProtectVirtualMemory", [&] {
            return NtProtectVirtualMemory(NtCurrentProcess, (void**)(&ogFunction), (SIZE_T*)&length, PAGE_EXECUTE_READWRITE, &oldProtection);
            })), "NtProtectVirtualMemory failed");

        if (gateway != nullptr) {

            memcpy(gateway, ogFunction, length);
            uintptr_t jumpAddress = (uintptr_t)ogFunction + length;
            *(gateway + length) = 0xE9;
            *(BYTE*)(gateway + length + 1) = (uintptr_t)(jumpAddress - ((uintptr_t)gateway + length + 5));
            memset(ogFunction, 0x90, length);
            *(BYTE*)ogFunction = 0xE9;
            *(DWORD*)((uintptr_t)ogFunction + 1) = (DWORD)((uintptr_t)hookFunction - ((uintptr_t)ogFunction + 5));
        }
        else {
            gateway = (BYTE*)safeCallVEH("VirtualAlloc", [&] {
                return VirtualAlloc(NULL, length + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
                });

            memcpy(gateway, ogFunction, length);
            uintptr_t jumpAddress = (uintptr_t)ogFunction + length;
            *(gateway + length) = 0xFF;
            *(gateway + length + 1) = 0x25;
            *(DWORD*)(gateway + length + 2) = 0;
            *(uintptr_t*)(gateway + length + 6) = jumpAddress;

            memset(ogFunction, 0x90, length);
            uintptr_t* ptrToDestination = (uintptr_t*)((uintptr_t)ogFunction + 6);
            *(BYTE*)ogFunction = 0xFF;
            *((BYTE*)(uintptr_t)ogFunction + 1) = 0x25;
            *(BYTE*)((uintptr_t)ogFunction + 2) = 0;
            *ptrToDestination = (uintptr_t)hookFunction;
        }

        EGG_ASSERT(NT_SUCCESS(safeCallVEH("NtProtectVirtualMemory", [&] {
            return NtProtectVirtualMemory(NtCurrentProcess, (void**)(&ogFunction), (SIZE_T*)&length, oldProtection, &oldProtection);
            })), "NtProtectVirtualMemory failed");
        this->_installed = true;

        return gateway;
        });
}
#endif


//#ifndef _WIN64
//BYTE* Trampoline::install() {
//	if (length < 5) return nullptr;
//		
//	BYTE* gateway = nullptr;
//	SIZE_T size = length + 5; 
//	EGG_ASSERT(NT_SUCCESS(NtAllocateVirtualMemory(NtCurrentProcess, (void**)&gateway, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)), "NtAllocateVirtualMemory failed");
//	
//	memcpy(gateway, ogFunction, length);
//	uintptr_t jumpAddress = ((uintptr_t)ogFunction - (uintptr_t)gateway) - 5;
//	*(gateway + length) = 0xE9; 
//	*(uintptr_t*)(gateway + length + 1) = jumpAddress;
//	
//	DWORD oldProtection;
//	EGG_ASSERT(NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess, (void**)(&ogFunction), (SIZE_T*)&length, PAGE_EXECUTE_READWRITE, &oldProtection)), "NtProtectVirtualMemory failed");
//	
//	uintptr_t relativeAddress = ((uintptr_t)hookFunction - (uintptr_t)ogFunction) - 5;
//	
//	*(BYTE*)ogFunction = 0xE9; 
//	*(uintptr_t*)(ogFunction + 1) = relativeAddress;
//	
//	Nop((BYTE*)ogFunction + 5, length - 5);
//	
//	EGG_ASSERT(NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess, (void**)(&ogFunction), (SIZE_T*)&length, oldProtection, &oldProtection)), "NtProtectVirtualMemory failed");
//	
//	return gateway;
//}
//#else
//BYTE* Trampoline::install() {
//	if (length < 5) return nullptr;
//
//
//
//	DWORD oldProtection;
//	EGG_ASSERT(NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess, (void**)(&ogFunction), (SIZE_T*)&length, PAGE_EXECUTE_READWRITE, &oldProtection)), "NtProtectVirtualMemory failed");
//
//	if (gateway != nullptr) {
//		// Near jump case
//		memcpy(gateway, ogFunction, length);
//		uintptr_t jumpAddress = (uintptr_t)ogFunction + length;
//		*(gateway + length) = 0xE9;
//		*(BYTE*)(gateway + length + 1) = (uintptr_t)(jumpAddress - ((uintptr_t)gateway + length + 5));
//		Nop((BYTE*)ogFunction, length);
//		*(BYTE*)ogFunction = 0xE9;
//		*(DWORD*)((uintptr_t)ogFunction + 1) = (DWORD)((uintptr_t)hookFunction - ((uintptr_t)ogFunction + 5));
//		
//	}
//	else {
//		// Far jump case
//		gateway = (BYTE*)VirtualAlloc(NULL, length + 14, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
//		if (gateway == nullptr) return nullptr;
//
//		memcpy(gateway, ogFunction, length);
//		uintptr_t jumpAddress = (uintptr_t)ogFunction + length;
//		*(gateway + length) = 0xFF;
//		*(gateway + length + 1) = 0x25;
//		*(DWORD*)(gateway + length + 2) = 0;
//		*(uintptr_t*)(gateway + length + 6) = jumpAddress;
//
//		memset(ogFunction, 0x90, length);
//		uintptr_t* ptrToDestination = (uintptr_t*)((uintptr_t)ogFunction + 6);
//		*(BYTE*)ogFunction = 0xFF;
//		*((BYTE*)(uintptr_t)ogFunction + 1) = 0x25;
//		*(BYTE*)((uintptr_t)ogFunction + 2) = 0;
//		*ptrToDestination = (uintptr_t)hookFunction;
//	}
//
//	EGG_ASSERT(NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess, (void**)(&ogFunction), (SIZE_T*)&length, oldProtection, &oldProtection)), "NtProtectVirtualMemory failed");
//	this->installed = true;
//	return (BYTE*)gateway;
//}
//#endif
