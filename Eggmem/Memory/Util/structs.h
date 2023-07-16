//do header guard


#pragma once

#define SeDebugPriv 20
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ( (HANDLE)(LONG_PTR) -1 ) 
#define ProcessHandleType 0x7


#define WIN32_LEAN_AND_MEAN
#include <string>
#include <Windows.h>
#include <winternl.h>
#include <vector>
#include <memory>
#include <stdexcept>

    struct Module {
        std::wstring moduleName;
        uintptr_t baseAddress;
        uintptr_t entryPoint;
        size_t size;
        USHORT loadCount;
        ULONG flags;
        uintptr_t sectionPointer;
        unsigned long long checkSum;
        std::vector<ExportInfo> exportInfo;
        std::vector<ImportInfo> importInfo;

    };

    

    
    struct ExportInfo {
        std::string exportName;
        uintptr_t exportAddress;
    };

    struct IndividualImport {
        std::string importName;
        uintptr_t importAddress;
    };

    struct ImportInfo {
        std::string dllName;
        std::vector<IndividualImport> imports;
    };

    namespace winapistructs {
        struct _STRING32
        {
            USHORT Length;                                                          //0x0
            USHORT MaximumLength;                                                   //0x2
            ULONG Buffer;                                                           //0x4
        };



        /*namespace AccessRights {
            constexpr DWORD ALL_ACCESS = 0x001F0FFF;
            constexpr DWORD CREATE_PROCESS = 0x0080;
            constexpr DWORD CREATE_THREAD = 0x0002;
            constexpr DWORD DUP_HANDLE = 0x0040;
            constexpr DWORD QUERY_INFORMATION = 0x0400;
            constexpr DWORD SET_QUOTA = 0x0100;
            constexpr DWORD SET_INFORMATION = 0x0200;
            constexpr DWORD TERMINATE = 0x0001;
            constexpr DWORD VM_OPERATION = 0x0008;
            constexpr DWORD VM_READ = 0x0010;
            constexpr DWORD VM_WRITE = 0x0020;
            constexpr DWORD _SYNCHRONIZE = 0x00100000;
        }*/

        namespace winapistructs {
#ifdef _WIN64
            typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
            {
                USHORT UniqueProcessId;
                USHORT CreatorBackTraceIndex;
                UCHAR ObjectTypeIndex;
                UCHAR HandleAttributes;
                USHORT HandleValue;
                PVOID Object;
                ULONG GrantedAccess;
            } SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
#else
            typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
            {
                USHORT UniqueProcessId;
                USHORT CreatorBackTraceIndex;
                UCHAR ObjectTypeIndex;
                UCHAR HandleAttributes;
                USHORT HandleValue;
                ULONG_PTR Object;
                ACCESS_MASK GrantedAccess;
            } SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;
#endif

            typedef struct _SYSTEM_HANDLE_INFORMATION
            {
                ULONG NumberOfHandles;
                SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
            } SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;



            typedef struct _LIST_ENTRY {
                struct _LIST_ENTRY* Flink;
                struct _LIST_ENTRY* Blink;
            } LIST_ENTRY, * PLIST_ENTRY, * __restrict PRLIST_ENTRY;

            typedef struct _UNICODE_STRING {
                USHORT Length;
                USHORT MaximumLength;
                PWCH   Buffer;
            } UNICODE_STRING, * PUNICODE_STRING;

            /*typedef struct _CLIENT_ID {
                HANDLE UniqueProcess;
                HANDLE UniqueThread;
            } CLIENT_ID, * PCLIENT_ID;

            typedef struct _OBJECT_ATTRIBUTES {
                ULONG           Length;
                HANDLE          RootDirectory;
                PUNICODE_STRING ObjectName;
                ULONG           Attributes;
                PVOID           SecurityDescriptor;
                PVOID           SecurityQualityOfService;
            }  OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;*/

            /*typedef enum _OBJECT_INFORMATION_CLASS {
                ObjectBasicInformation,
                ObjectNameInformation,
                ObjectTypeInformation,
                ObjectAllInformation,
                ObjectDataInformation
            } OBJECT_INFORMATION_CLASS;

            typedef enum _THREADINFOCLASS {
                ThreadIsIoPending = 16,
                ThreadNameInformation = 38
            } THREADINFOCLASS;*/

            typedef struct _PEB_LDR_DATA {
                unsigned long Length;
                unsigned char Initialized;
                void* SsHandle;
                LIST_ENTRY ModuleListLoadOrder;
                LIST_ENTRY ModuleListMemoryOrder;
                LIST_ENTRY ModuleListInitOrder;
            } PEB_LDR_DATA, * PPEB_LDR_DATA;

            typedef struct _RTL_USER_PROCESS_PARAMETERS {
                unsigned char Reserved1[16];
                void* Reserved2[10];
                UNICODE_STRING ImagePathName;
                UNICODE_STRING CommandLine;
            } RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;



            typedef struct _PEB {
                unsigned char Reserved1[2];
                unsigned char BeingDebugged;
                unsigned char Reserved2[1];
                void* Reserved3[2];
                PPEB_LDR_DATA Ldr;
                PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
                void* Reserved4[3];
                void* AtlThunkSListPtr;
                void* Reserved5;
                unsigned long Reserved6;
                void* Reserved7;
                unsigned long Reserved8;
                unsigned long AtlThunkSListPtr32;
                void* Reserved9[45];
                unsigned char Reserved10[96];
                PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
                unsigned char Reserved11[128];
                void* Reserved12[1];
                unsigned long SessionId;
            } PEB, * PPEB;

            typedef struct _LDR_DATA_TABLE_ENTRY
            {
                struct _LIST_ENTRY InLoadOrderLinks;                                    //0x0
                VOID* ExceptionTable;                                                   //0x10
                ULONG ExceptionTableSize;                                               //0x18
                VOID* GpValue;                                                          //0x20
                struct _NON_PAGED_DEBUG_INFO* NonPagedDebugInfo;                        //0x28
                VOID* DllBase;                                                          //0x30
                VOID* EntryPoint;                                                       //0x38
                ULONG SizeOfImage;                                                      //0x40
                struct _UNICODE_STRING FullDllName;                                     //0x48
                struct _UNICODE_STRING BaseDllName;                                     //0x58
                ULONG Flags;                                                            //0x68
                USHORT LoadCount;                                                       //0x6c
                union
                {
                    USHORT SignatureLevel : 4;                                            //0x6e
                    USHORT SignatureType : 3;                                             //0x6e
                    USHORT Unused : 9;                                                    //0x6e
                    USHORT EntireField;                                                 //0x6e
                } u1;                                                                   //0x6e
                VOID* SectionPointer;                                                   //0x70
                ULONG CheckSum;                                                         //0x78
                ULONG CoverageSectionSize;                                              //0x7c
                VOID* CoverageSection;                                                  //0x80
                VOID* LoadedImports;                                                    //0x88
                VOID* Spare;                                                            //0x90
                ULONG SizeOfImageNotRounded;                                            //0x98
                ULONG TimeDateStamp;                                                    //0x9c
            } LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

            typedef struct _IMAGE_DATA_DIRECTORY {
                unsigned long   VirtualAddress;
                unsigned long   Size;
            } IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

            typedef struct _IMAGE_OPTIONAL_HEADER {
                unsigned short    Magic;
                unsigned char    MajorLinkerVersion;
                unsigned char    MinorLinkerVersion;
                unsigned long   SizeOfCode;
                unsigned long   SizeOfInitializedData;
                unsigned long   SizeOfUninitializedData;
                unsigned long   AddressOfEntryPoint;
                unsigned long   BaseOfCode;
                unsigned long   BaseOfData;

                unsigned long   ImageBase;
                unsigned long   SectionAlignment;
                unsigned long   FileAlignment;
                unsigned short    MajorOperatingSystemVersion;
                unsigned short    MinorOperatingSystemVersion;
                unsigned short    MajorImageVersion;
                unsigned short    MinorImageVersion;
                unsigned short    MajorSubsystemVersion;
                unsigned short    MinorSubsystemVersion;
                unsigned long   Win32VersionValue;
                unsigned long   SizeOfImage;
                unsigned long   SizeOfHeaders;
                unsigned long   CheckSum;
                unsigned short    Subsystem;
                unsigned short    DllCharacteristics;
                unsigned long   SizeOfStackReserve;
                unsigned long   SizeOfStackCommit;
                unsigned long   SizeOfHeapReserve;
                unsigned long   SizeOfHeapCommit;
                unsigned long   LoaderFlags;
                unsigned long   NumberOfRvaAndSizes;
                IMAGE_DATA_DIRECTORY DataDirectory[16];
            } IMAGE_OPTIONAL_HEADER32, * PIMAGE_OPTIONAL_HEADER32;

            typedef struct _IMAGE_ROM_OPTIONAL_HEADER {
                unsigned short   Magic;
                unsigned char   MajorLinkerVersion;
                unsigned char   MinorLinkerVersion;
                unsigned long  SizeOfCode;
                unsigned long  SizeOfInitializedData;
                unsigned long  SizeOfUninitializedData;
                unsigned long  AddressOfEntryPoint;
                unsigned long  BaseOfCode;
                unsigned long  BaseOfData;
                unsigned long  BaseOfBss;
                unsigned long  GprMask;
                unsigned long  CprMask[4];
                unsigned long  GpValue;
            } IMAGE_ROM_OPTIONAL_HEADER, * PIMAGE_ROM_OPTIONAL_HEADER;

            typedef enum _SYSTEM_INFORMATION_CLASS {
                SystemBasicInformation,
                SystemProcessorInformation,
                SystemPerformanceInformation,
                SystemTimeOfDayInformation,
                SystemPathInformation,
                SystemProcessInformation,
                SystemCallCountInformation,
                SystemDeviceInformation,
                SystemProcessorPerformanceInformation,
                SystemFlagsInformation,
                SystemCallTimeInformation,
                SystemModuleInformation,
                SystemLocksInformation,
                SystemStackTraceInformation,
                SystemPagedPoolInformation,
                SystemNonPagedPoolInformation,
                SystemHandleInformation,
                SystemObjectInformation,
                SystemPageFileInformation,
                SystemVdmInstemulInformation,
                SystemVdmBopInformation,
                SystemFileCacheInformation,
                SystemPoolTagInformation,
                SystemInterruptInformation,
                SystemDpcBehaviorInformation,
                SystemFullMemoryInformation,
                SystemLoadGdiDriverInformation,
                SystemUnloadGdiDriverInformation,
                SystemTimeAdjustmentInformation,
                SystemSummaryMemoryInformation,
                SystemMirrorMemoryInformation,
                SystemPerformanceTraceInformation,
                SystemObsolete0,
                SystemExceptionInformation,
                SystemCrashDumpStateInformation,
                SystemKernelDebuggerInformation,
                SystemContextSwitchInformation,
                SystemRegistryQuotaInformation,
                SystemExtendServiceTableInformation,
                SystemPrioritySeperation,
                SystemVerifierAddDriverInformation,
                SystemVerifierRemoveDriverInformation,
                SystemProcessorIdleInformation,
                SystemLegacyDriverInformation,
                SystemCurrentTimeZoneInformation,
                SystemLookasideInformation,
                SystemTimeSlipNotification,
                SystemSessionCreate,
                SystemSessionDetach,
                SystemSessionInformation,
                SystemRangeStartInformation,
                SystemVerifierInformation,
                SystemVerifierThunkExtend,
                SystemSessionProcessInformation,
                SystemLoadGdiDriverInSystemSpace,
                SystemNumaProcessorMap,
                SystemPrefetcherInformation,
                SystemExtendedProcessInformation,
                SystemRecommendedSharedDataAlignment,
                SystemComPlusPackage,
                SystemNumaAvailableMemory,
                SystemProcessorPowerInformation,
                SystemEmulationBasicInformation,
                SystemEmulationProcessorInformation,
                SystemExtendedHandleInformation,
                SystemLostDelayedWriteInformation,
                SystemBigPoolInformation,
                SystemSessionPoolTagInformation,
                SystemSessionMappedViewInformation,
                SystemHotpatchInformation,
                SystemObjectSecurityMode,
                SystemWatchdogTimerHandler,
                SystemWatchdogTimerInformation,
                SystemLogicalProcessorInformation,
                SystemWow64SharedInformation,
                SystemRegisterFirmwareTableInformationHandler,
                SystemFirmwareTableInformation,
                SystemModuleInformationEx,
                SystemVerifierTriageInformation,
                SystemSuperfetchInformation,
                SystemMemoryListInformation,
                SystemFileCacheInformationEx,
                SystemThreadPriorityClientIdInformation,
                SystemProcessorIdleCycleTimeInformation,
                SystemVerifierCancellationInformation,
                SystemProcessorPowerInformationEx,
                SystemRefTraceInformation,
                SystemSpecialPoolInformation,
                SystemProcessIdInformation,
                SystemErrorPortInformation,
                SystemBootEnvironmentInformation,
                SystemHypervisorInformation,
                SystemVerifierInformationEx,
                SystemTimeZoneInformation,
                SystemImageFileExecutionOptionsInformation,
                SystemCoverageInformation,
                SystemPrefetchPatchInformation,
                SystemVerifierFaultsInformation,
                SystemSystemPartitionInformation,
                SystemSystemDiskInformation,
                SystemProcessorPerformanceDistribution,
                SystemNumaProximityNodeInformation,
                SystemDynamicTimeZoneInformation,
                SystemCodeIntegrityInformation,
                SystemProcessorMicrocodeUpdateInformation,
                SystemProcessorBrandString,
                SystemVirtualAddressInformation,
                SystemLogicalProcessorAndGroupInformation,
                SystemProcessorCycleTimeInformation,
                SystemStoreInformation,
                SystemRegistryAppendString,
                SystemAitSamplingValue,
                SystemVhdBootInformation,
                SystemCpuQuotaInformation,
                SystemNativeBasicInformation,
                SystemSpare1,
                SystemLowPriorityIoInformation,
                SystemTpmBootEntropyInformation,
                SystemVerifierCountersInformation,
                SystemPagedPoolInformationEx,
                SystemSystemPtesInformationEx,
                SystemNodeDistanceInformation,
                SystemAcpiAuditInformation,
                SystemBasicPerformanceInformation,
                SystemQueryPerformanceCounterInformation,
                SystemSessionBigPoolInformation,
                SystemBootGraphicsInformation,
                SystemScrubPhysicalMemoryInformation,
                SystemBadPageInformation,
                SystemProcessorProfileControlArea,
                SystemCombinePhysicalMemoryInformation,
                SystemEntropyInterruptTimingInformation,
                SystemConsoleInformation,
                SystemPlatformBinaryInformation,
                SystemPolicyInformation,
                SystemHypervisorProcessorCountInformation,
                SystemDeviceDataInformation,
                SystemDeviceDataEnumerationInformation,
                SystemMemoryTopologyInformation,
                SystemMemoryChannelInformation,
                SystemBootLogoInformation,
                SystemProcessorPerformanceInformationEx,
                SystemSpare0,
                SystemSecureBootPolicyInformation,
                SystemPageFileInformationEx,
                SystemSecureBootInformation,
                SystemEntropyInterruptTimingRawInformation,
                SystemPortableWorkspaceEfiLauncherInformation,
                SystemFullProcessInformation,
                SystemKernelDebuggerInformationEx,
                SystemBootMetadataInformation,
                SystemSoftRebootInformation,
                SystemElamCertificateInformation,
                SystemOfflineDumpConfigInformation,
                SystemProcessorFeaturesInformation,
                SystemRegistryReconciliationInformation,
                MaxSystemInfoClass
            } SYSTEM_INFORMATION_CLASS;

            typedef struct _IMAGE_OPTIONAL_HEADER64 {
                unsigned short        Magic;
                unsigned char        MajorLinkerVersion;
                unsigned char        MinorLinkerVersion;
                unsigned long       SizeOfCode;
                unsigned long       SizeOfInitializedData;
                unsigned long       SizeOfUninitializedData;
                unsigned long       AddressOfEntryPoint;
                unsigned long       BaseOfCode;
                unsigned __int64  ImageBase;
                unsigned long       SectionAlignment;
                unsigned long       FileAlignment;
                unsigned short        MajorOperatingSystemVersion;
                unsigned short        MinorOperatingSystemVersion;
                unsigned short        MajorImageVersion;
                unsigned short        MinorImageVersion;
                unsigned short        MajorSubsystemVersion;
                unsigned short        MinorSubsystemVersion;
                unsigned long       Win32VersionValue;
                unsigned long       SizeOfImage;
                unsigned long       SizeOfHeaders;
                unsigned long       CheckSum;
                unsigned short        Subsystem;
                unsigned short        DllCharacteristics;
                unsigned __int64   SizeOfStackReserve;
                unsigned __int64   SizeOfStackCommit;
                unsigned __int64   SizeOfHeapReserve;
                unsigned __int64   SizeOfHeapCommit;
                unsigned long       LoaderFlags;
                unsigned long       NumberOfRvaAndSizes;
                IMAGE_DATA_DIRECTORY DataDirectory[16];
            } IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

            typedef struct _IMAGE_FILE_HEADER {
                unsigned short    Machine;
                unsigned short    NumberOfSections;
                unsigned long   TimeDateStamp;
                unsigned long   PointerToSymbolTable;
                unsigned long   NumberOfSymbols;
                unsigned short    SizeOfOptionalHeader;
                unsigned short    Characteristics;
            } IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

            typedef struct _IMAGE_NT_HEADERS64 {
                unsigned long Signature;
                IMAGE_FILE_HEADER FileHeader;
                IMAGE_OPTIONAL_HEADER64 OptionalHeader;
            } IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

            typedef struct _IMAGE_NT_HEADERS {
                unsigned long Signature;
                IMAGE_FILE_HEADER FileHeader;
                IMAGE_OPTIONAL_HEADER32 OptionalHeader;
            } IMAGE_NT_HEADERS32, * PIMAGE_NT_HEADERS32;

            typedef struct _IMAGE_ROM_HEADERS {
                IMAGE_FILE_HEADER FileHeader;
                IMAGE_ROM_OPTIONAL_HEADER OptionalHeader;
            } IMAGE_ROM_HEADERS, * PIMAGE_ROM_HEADERS;

            typedef struct _IMAGE_EXPORT_DIRECTORY
            {
                unsigned long Characteristics;
                unsigned long TimeDateStamp;
                unsigned short MajorVersion;
                unsigned short MinorVersion;
                unsigned long Name;
                unsigned long Base;
                unsigned long NumberOfFunctions;
                unsigned long NumberOfNames;
                unsigned long AddressOfFunctions;
                unsigned long AddressOfNames;
                unsigned long AddressOfNameOrdinals;
            }IMAGE_EXPORT_DIRECTORY, * PIMAGE_EXPORT_DIRECTORY;

            typedef struct _IMAGE_DOS_HEADER {
                unsigned short   e_magic;
                unsigned short   e_cblp;
                unsigned short   e_cp;
                unsigned short   e_crlc;
                unsigned short   e_cparhdr;
                unsigned short   e_minalloc;
                unsigned short   e_maxalloc;
                unsigned short   e_ss;
                unsigned short   e_sp;
                unsigned short   e_csum;
                unsigned short   e_ip;
                unsigned short   e_cs;
                unsigned short   e_lfarlc;
                unsigned short   e_ovno;
                unsigned short   e_res[4];
                unsigned short   e_oemid;
                unsigned short   e_oeminfo;
                unsigned short   e_res2[10];
                unsigned short   e_lfanew;
            } IMAGE_DOS_HEADER, * PIMAGE_DOS_HEADER;
        };
    }

    namespace winapidefs {
        

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
            IN CLIENT_ID*          ClientId OPTIONAL
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
            _In_  CLIENT_ID*        ClientId
            );

        using _NtQueryInformationThread = NTSTATUS(NTAPI*)(
            _In_            HANDLE          ThreadHandle,
            _In_            THREADINFOCLASS ThreadInformationClass,
            _Inout_         PVOID           ThreadInformation,
            _In_            ULONG           ThreadInformationLength,
            _Out_opt_       PULONG          ReturnLength
            );

        using _NtQueryInformationProcess = NTSTATUS(NTAPI*)(
            IN HANDLE ProcessHandle,
            IN PROCESSINFOCLASS ProcessInformationClass,
            OUT PVOID ProcessInformation,
            IN ULONG ProcessInformationLength,
            OUT PULONG ReturnLength OPTIONAL
            );

        //typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported

        using PPS_POST_PROCESS_INIT_ROUTINE = void(__stdcall*)(void);

    }
    namespace winapi {
        using namespace winapidefs;
        extern HMODULE ntdll;
        extern _NtOpenProcess NtOpenProcess;
        extern _NtQuerySystemInformation NtQuerySystemInformation;
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
        extern _NtQueryObject NtQueryObject;
        extern _NtQueryInformationThread NtQueryInformationThread;
        extern _NtQueryInformationProcess NtQueryInformationProcess;
    };

    



