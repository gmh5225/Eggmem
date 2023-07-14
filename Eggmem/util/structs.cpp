#include "structs.h"

namespace eggmem {

namespace winapi {
    using namespace winapidefs;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    _NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(ntdll, "NtOpenProcess");
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(ntdll, "NtDuplicateObject");
    _NtAllocateVirtualMemory NtAllocateVirtualMemory = (_NtAllocateVirtualMemory)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
    _NtGetContextThread NtGetContextThread = (_NtGetContextThread)GetProcAddress(ntdll, "NtGetContextThread");
    _NtSetContextThread NtSetContextThread = (_NtSetContextThread)GetProcAddress(ntdll, "NtSetContextThread");
    _NtResumeThread NtResumeThread = (_NtResumeThread)GetProcAddress(ntdll, "NtResumeThread");
    _NtSuspendThread NtSuspendThread = (_NtSuspendThread)GetProcAddress(ntdll, "NtSuspendThread");
    _NtReadVirtualMemory NtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
    _NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    _NtFreeVirtualMemory NtFreeVirtualMemory = (_NtFreeVirtualMemory)GetProcAddress(ntdll, "NtFreeVirtualMemory");
    _NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    _RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(ntdll, "RtlAdjustPrivilege");
    _NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(ntdll, "NtQueryObject");
    _NtQueryInformationThread NtQueryInformationThread = (_NtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
    _NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
    
};

}
