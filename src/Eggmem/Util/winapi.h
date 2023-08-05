#pragma once
#include <Windows.h>
#include <winternl.h>

using _NtDuplicateObject = NTSTATUS(NTAPI*) (
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

using _RtlAdjustPrivilege = NTSTATUS(NTAPI*) (
    IN ULONG    Privilege,
    IN BOOLEAN  Enable,
    IN BOOLEAN  CurrentThread,
    OUT PBOOLEAN Enabled
    );


using _NtOpenProcess = NTSTATUS(NTAPI*) (
    OUT PHANDLE            ProcessHandle,
    IN ACCESS_MASK         DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN CLIENT_ID* ClientId OPTIONAL
    );

using _NtQuerySystemInformation = NTSTATUS(NTAPI*)(
    IN ULONG  SystemInformationClass,
    OUT PVOID  SystemInformation,
    IN ULONG  SystemInformationLength,
    OUT PULONG ReturnLength
    );

using _NtAllocateVirtualMemory = NTSTATUS(NTAPI*)(
    IN HANDLE    ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN ULONG_PTR ZeroBits,
    IN OUT PSIZE_T   RegionSize,
    IN ULONG     AllocationType,
    IN ULONG     Protect
    );

using _NtFreeVirtualMemory = NTSTATUS(NTAPI*)(
    HANDLE  ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG   FreeType
    );

using _NtWriteVirtualMemory = NTSTATUS(NTAPI*)(
    IN HANDLE    ProcessHandle,
    IN PVOID     BaseAddress,
    IN PVOID     Buffer,
    IN ULONG_PTR BufferSize,
    OUT PULONG_PTR NumberOfBytesWritten
    );

using _NtReadVirtualMemory = NTSTATUS(NTAPI*)(
    IN HANDLE    ProcessHandle,
    IN PVOID     BaseAddress,
    OUT PVOID    Buffer,
    IN ULONG_PTR BufferSize,
    OUT PULONG_PTR NumberOfBytesRead
    );

using _NtSuspendThread = NTSTATUS(NTAPI*)(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL
    );

using _NtResumeThread = NTSTATUS(NTAPI*)(
    IN HANDLE ThreadHandle,
    OUT PULONG PreviousSuspendCount OPTIONAL
    );

using _NtGetContextThread = NTSTATUS(NTAPI*)(
    IN HANDLE ThreadHandle,
    OUT PCONTEXT Context
    );

using _NtSetContextThread = NTSTATUS(NTAPI*)(
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context
    );

using _NtProtectVirtualMemory = NTSTATUS(NTAPI*)(
    IN HANDLE ProcessHandle,
    IN OUT PVOID* BaseAddress,
    IN OUT PSIZE_T RegionSize,
    IN ULONG NewProtect,
    OUT PULONG OldProtect
    );

using _NtQueryObject = NTSTATUS(NTAPI*)(
    IN HANDLE Handle,
    IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
    OUT PVOID ObjectInformation,
    IN ULONG ObjectInformationLength,
    OUT PULONG ReturnLength OPTIONAL
    );

using _NtOpenThread = NTSTATUS(NTAPI*)(
    _Out_ PHANDLE            ThreadHandle,
    _In_  ACCESS_MASK        DesiredAccess,
    _In_  POBJECT_ATTRIBUTES ObjectAttributes,
    _In_  CLIENT_ID* ClientId
    );

using _NtQueryInformationThread = NTSTATUS(NTAPI*)(
    _In_            HANDLE          ThreadHandle,
    _In_            THREADINFOCLASS ThreadInformationClass,
    _Inout_         PVOID           ThreadInformation,
    _In_            ULONG           ThreadInformationLength,
    _Out_opt_       PULONG          ReturnLength
    );

//__kernel_entry NTSTATUS
//NTAPI
//NtQueryInformationProcess(
//    IN HANDLE ProcessHandle,
//    IN PROCESSINFOCLASS ProcessInformationClass,
//    OUT PVOID ProcessInformation,
//    IN ULONG ProcessInformationLength,
//    OUT PULONG ReturnLength OPTIONAL
//);

using _NtQueryInformationProcess = __kernel_entry NTSTATUS(NTAPI*)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
	);

//typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported

using PPS_POST_PROCESS_INIT_ROUTINE = void(__stdcall*)(void);

extern HMODULE ntdll;
extern _NtQueryInformationProcess NtQueryInformationProc;
extern _NtOpenProcess NtOpenProcess;
extern _NtDuplicateObject NtDuplicateObject;
extern _NtAllocateVirtualMemory NtAllocateVirtualMemory;
extern _NtGetContextThread NtGetContextThread;
extern _NtSetContextThread NtSetContextThread;
extern _NtResumeThread NtResumeThread;
extern _NtSuspendThread NtSuspendThread;
extern _NtReadVirtualMemory NtReadVirtualMemory;
extern _NtWriteVirtualMemory NtWriteVirtualMemory;
extern _NtFreeVirtualMemory NtFreeVirtualMemory;
extern _NtProtectVirtualMemory NtProtectVirtualMemory;
extern _RtlAdjustPrivilege RtlAdjustPrivilege;
