#pragma once
#include "global.h"
#include <wincred.h>
#include <Lmcons.h>
#include <sddl.h>
#include "resolve.h"

#define STATUS_INFO_LENGTH_MISMATCH                     0xc0000004
#define STATUS_PRIVILEDGE_FOUND                         (HANDLE)0x00518961
#define STATUS_BUFFER_TOO_SMALL			                ((NTSTATUS)0xC0000023L)
#define STATUS_BUFFER_OVERFLOW                          0x80000005

#define ws_lsass                                         L"lsass.exe"
#define ws_smss                                          L"smss.exe"
#define ws_winlogon                                      L"winlogon.exe"

#define ws_explorer                                      L"explorer.exe"
#define ws_TaskHost                                      L"taskhost.exe"
#define ws_TaskHostEx                                    L"taskhostex.exe"
#define ws_TaskHostW                                     L"taskhostw.exe"

#define ws_advapi32                                      L"advapi32.dll"
#define ws_crypt32                                       L"crypt32.dll"

#define szSeTrustedCredmanAccessPrivilege                L"SeTrustedCredManAccessPrivilege"

#define ws_SystemRoot                                    L"SYSTEMROOT"
#define ws_Temp                                          L"Temp"
#define ws_TempFileExtension                             L".tmp"
#define FolderSeparator		                             L"\\"
#define ws_NtPathStart				                     L"\\??\\"

#define ws_DomainTarget                                  L"Domain:target="
#define ws_DomainName                                    L"Domain:name="

#define FILE_NON_DIRECTORY_FILE			                 0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT	                 0x00000020

#define NtCurrentThread()                                ((HANDLE)(LONG_PTR)-2)
#define OBJ_CASE_INSENSITIVE                             0x00000040
#define	FILE_SUPERSEDE                                   0x00000000

typedef struct TPROCESS {
    HANDLE Pid;
    WCHAR* ProcessName;
    USHORT ProcessLength;
} TPROCESS, * PTPROCESS;

typedef struct IMPERSONATED {
    LPSTR SID;
    unsigned int SidSize;
} IMPERSONATED, * PIMPERSONATED;

typedef LONG 	KPRIORITY;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    PVOID RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID
{
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    ULONGLONG WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG Reserved1;
    ULONGLONG CycleTime;
    ULONGLONG CreateTime;
    ULONGLONG UserTime;
    ULONGLONG KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    //HANDLE ParentProcessId;
    //ULONG HandleCount;
    //ULONG Reserved2[2];
    // Padding here in 64-bit
    //VM_COUNTERS VirtualMemoryCounters;
    //size_t Reserved3;
    //IO_COUNTERS IoCounters;
    //SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS
{
    SystemBasicInformation = 0,
    SystemProcessorInformation = 1,             // obsolete...delete
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemPathInformation = 4,
    SystemProcessInformation = 5,
    SystemCallCountInformation = 6,
    SystemDeviceInformation = 7,
    SystemProcessorPerformanceInformation = 8,
    SystemFlagsInformation = 9,
    SystemCallTimeInformation = 10,
    SystemModuleInformation = 11,
    SystemLocksInformation = 12,
    SystemStackTraceInformation = 13,
    SystemPagedPoolInformation = 14,
    SystemNonPagedPoolInformation = 15,
    SystemHandleInformation = 16,
    SystemObjectInformation = 17,
    SystemPageFileInformation = 18,
    SystemVdmInstemulInformation = 19,
    SystemVdmBopInformation = 20,
    SystemFileCacheInformation = 21,
    SystemPoolTagInformation = 22,
    SystemInterruptInformation = 23,
    SystemDpcBehaviorInformation = 24,
    SystemFullMemoryInformation = 25,
    SystemLoadGdiDriverInformation = 26,
    SystemUnloadGdiDriverInformation = 27,
    SystemTimeAdjustmentInformation = 28,
    SystemSummaryMemoryInformation = 29,
    SystemMirrorMemoryInformation = 30,
    SystemPerformanceTraceInformation = 31,
    SystemObsolete0 = 32,
    SystemExceptionInformation = 33,
    SystemCrashDumpStateInformation = 34,
    SystemKernelDebuggerInformation = 35,
    SystemContextSwitchInformation = 36,
    SystemRegistryQuotaInformation = 37,
    SystemExtendServiceTableInformation = 38,
    SystemPrioritySeperation = 39,
    SystemVerifierAddDriverInformation = 40,
    SystemVerifierRemoveDriverInformation = 41,
    SystemProcessorIdleInformation = 42,
    SystemLegacyDriverInformation = 43,
    SystemCurrentTimeZoneInformation = 44,
    SystemLookasideInformation = 45,
    SystemTimeSlipNotification = 46,
    SystemSessionCreate = 47,
    SystemSessionDetach = 48,
    SystemSessionInformation = 49,
    SystemRangeStartInformation = 50,
    SystemVerifierInformation = 51,
    SystemVerifierThunkExtend = 52,
    SystemSessionProcessInformation = 53,
    SystemLoadGdiDriverInSystemSpace = 54,
    SystemNumaProcessorMap = 55,
    SystemPrefetcherInformation = 56,
    SystemExtendedProcessInformation = 57,
    SystemRecommendedSharedDataAlignment = 58,
    SystemComPlusPackage = 59,
    SystemNumaAvailableMemory = 60,
    SystemProcessorPowerInformation = 61,
    SystemEmulationBasicInformation = 62,
    SystemEmulationProcessorInformation = 63,
    SystemExtendedHandleInformation = 64,
    SystemLostDelayedWriteInformation = 65,
    SystemBigPoolInformation = 66,
    SystemSessionPoolTagInformation = 67,
    SystemSessionMappedViewInformation = 68,
    SystemHotpatchInformation = 69,
    SystemObjectSecurityMode = 70,
    SystemWatchdogTimerHandler = 71,
    SystemWatchdogTimerInformation = 72,
    SystemLogicalProcessorInformation = 73,
    SystemWow64SharedInformation = 74,
    SystemRegisterFirmwareTableInformationHandler = 75,
    SystemFirmwareTableInformation = 76,
    SystemModuleInformationEx = 77,
    SystemVerifierTriageInformation = 78,
    SystemSuperfetchInformation = 79,
    SystemMemoryListInformation = 80,
    SystemFileCacheInformationEx = 81,
    MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum

} SYSTEM_INFORMATION_CLASS;

typedef enum _THREADINFOCLASS
{
    ThreadBasicInformation, // q: THREAD_BASIC_INFORMATION
    ThreadTimes, // q: KERNEL_USER_TIMES
    ThreadPriority, // s: KPRIORITY (requires SeIncreaseBasePriorityPrivilege)
    ThreadBasePriority, // s: KPRIORITY
    ThreadAffinityMask, // s: KAFFINITY
    ThreadImpersonationToken, // s: HANDLE
    ThreadDescriptorTableEntry, // q: DESCRIPTOR_TABLE_ENTRY (or WOW64_DESCRIPTOR_TABLE_ENTRY)
    ThreadEnableAlignmentFaultFixup, // s: BOOLEAN
    ThreadEventPair,
    ThreadQuerySetWin32StartAddress, // q: ULONG_PTR
    ThreadZeroTlsCell, // s: ULONG // TlsIndex // 10
    ThreadPerformanceCount, // q: LARGE_INTEGER
    ThreadAmILastThread, // q: ULONG
    ThreadIdealProcessor, // s: ULONG
    ThreadPriorityBoost, // qs: ULONG
    ThreadSetTlsArrayAddress, // s: ULONG_PTR
    ThreadIsIoPending, // q: ULONG
    ThreadHideFromDebugger, // q: BOOLEAN; s: void
    ThreadBreakOnTermination, // qs: ULONG
    ThreadSwitchLegacyState, // s: void // NtCurrentThread // NPX/FPU
    ThreadIsTerminated, // q: ULONG // 20
    ThreadLastSystemCall, // q: THREAD_LAST_SYSCALL_INFORMATION
    ThreadIoPriority, // qs: IO_PRIORITY_HINT (requires SeIncreaseBasePriorityPrivilege)
    ThreadCycleTime, // q: THREAD_CYCLE_TIME_INFORMATION
    ThreadPagePriority, // qs: PAGE_PRIORITY_INFORMATION
    ThreadActualBasePriority, // s: LONG (requires SeIncreaseBasePriorityPrivilege)
    ThreadTebInformation, // q: THREAD_TEB_INFORMATION (requires THREAD_GET_CONTEXT + THREAD_SET_CONTEXT)
    ThreadCSwitchMon,
    ThreadCSwitchPmu,
    ThreadWow64Context, // qs: WOW64_CONTEXT
    ThreadGroupInformation, // qs: GROUP_AFFINITY // 30
    ThreadUmsInformation, // q: THREAD_UMS_INFORMATION
    ThreadCounterProfiling, // q: BOOLEAN; s: THREAD_PROFILING_INFORMATION?
    ThreadIdealProcessorEx, // qs: PROCESSOR_NUMBER; s: previous PROCESSOR_NUMBER on return
    ThreadCpuAccountingInformation, // q: BOOLEAN; s: HANDLE (NtOpenSession) // NtCurrentThread // since WIN8
    ThreadSuspendCount, // q: ULONG // since WINBLUE
    ThreadHeterogeneousCpuPolicy, // q: KHETERO_CPU_POLICY // since THRESHOLD
    ThreadContainerId, // q: GUID
    ThreadNameInformation, // qs: THREAD_NAME_INFORMATION
    ThreadSelectedCpuSets,
    ThreadSystemThreadInformation, // q: SYSTEM_THREAD_INFORMATION // 40
    ThreadActualGroupAffinity, // q: GROUP_AFFINITY // since THRESHOLD2
    ThreadDynamicCodePolicyInfo, // q: ULONG; s: ULONG (NtCurrentThread)
    ThreadExplicitCaseSensitivity, // qs: ULONG; s: 0 disables, otherwise enables
    ThreadWorkOnBehalfTicket, // RTL_WORK_ON_BEHALF_TICKET_EX
    ThreadSubsystemInformation, // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
    ThreadDbgkWerReportActive, // s: ULONG; s: 0 disables, otherwise enables
    ThreadAttachContainer, // s: HANDLE (job object) // NtCurrentThread
    ThreadManageWritesToExecutableMemory, // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
    ThreadPowerThrottlingState, // POWER_THROTTLING_THREAD_STATE
    ThreadWorkloadClass, // THREAD_WORKLOAD_CLASS // since REDSTONE5 // 50
    ThreadCreateStateChange, // since WIN11
    ThreadApplyStateChange,
    ThreadStrongerBadHandleChecks, // since 22H1
    ThreadEffectiveIoPriority, // q: IO_PRIORITY_HINT
    ThreadEffectivePagePriority, // q: ULONG
    MaxThreadInfoClass
} THREADINFOCLASS;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES); \
    (p)->RootDirectory = r; \
    (p)->Attributes = a; \
    (p)->ObjectName = n; \
    (p)->SecurityDescriptor = s; \
    (p)->SecurityQualityOfService = NULL; \
    }

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG         NumberOfLinks;
    BOOLEAN       DeletePending;
    BOOLEAN       Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1,
    FileFullDirectoryInformation,                   // 2
    FileBothDirectoryInformation,                   // 3
    FileBasicInformation,                           // 4
    FileStandardInformation,                        // 5
    FileInternalInformation,                        // 6
    FileEaInformation,                              // 7
    FileAccessInformation,                          // 8
    FileNameInformation,                            // 9
    FileRenameInformation,                          // 10
    FileLinkInformation,                            // 11
    FileNamesInformation,                           // 12
    FileDispositionInformation,                     // 13
    FilePositionInformation,                        // 14
    FileFullEaInformation,                          // 15
    FileModeInformation,                            // 16
    FileAlignmentInformation,                       // 17
    FileAllInformation,                             // 18
    FileAllocationInformation,                      // 19
    FileEndOfFileInformation,                       // 20
    FileAlternateNameInformation,                   // 21
    FileStreamInformation,                          // 22
    FilePipeInformation,                            // 23
    FilePipeLocalInformation,                       // 24
    FilePipeRemoteInformation,                      // 25
    FileMailslotQueryInformation,                   // 26
    FileMailslotSetInformation,                     // 27
    FileCompressionInformation,                     // 28
    FileObjectIdInformation,                        // 29
    FileCompletionInformation,                      // 30
    FileMoveClusterInformation,                     // 31
    FileQuotaInformation,                           // 32
    FileReparsePointInformation,                    // 33
    FileNetworkOpenInformation,                     // 34
    FileAttributeTagInformation,                    // 35
    FileTrackingInformation,                        // 36
    FileIdBothDirectoryInformation,                 // 37
    FileIdFullDirectoryInformation,                 // 38
    FileValidDataLengthInformation,                 // 39
    FileShortNameInformation,                       // 40
    FileIoCompletionNotificationInformation,        // 41
    FileIoStatusBlockRangeInformation,              // 42
    FileIoPriorityHintInformation,                  // 43
    FileSfioReserveInformation,                     // 44
    FileSfioVolumeInformation,                      // 45
    FileHardLinkInformation,                        // 46
    FileProcessIdsUsingFileInformation,             // 47
    FileNormalizedNameInformation,                  // 48
    FileNetworkPhysicalNameInformation,             // 49
    FileIdGlobalTxDirectoryInformation,             // 50
    FileIsRemoteDeviceInformation,                  // 51
    FileUnusedInformation,                          // 52
    FileNumaNodeInformation,                        // 53
    FileStandardLinkInformation,                    // 54
    FileRemoteProtocolInformation,                  // 55

        //
        //  These are special versions of these operations (defined earlier)
        //  which can be used by kernel mode drivers only to bypass security
        //  access checks for Rename and HardLink operations.  These operations
        //  are only recognized by the IOManager, a file system should never
        //  receive these.
        //

        FileRenameInformationBypassAccessCheck,         // 56
        FileLinkInformationBypassAccessCheck,           // 57

            //
            // End of special information classes reserved for IOManager.
            //

            FileVolumeNameInformation,                      // 58
            FileIdInformation,                              // 59
            FileIdExtdDirectoryInformation,                 // 60
            FileReplaceCompletionInformation,               // 61
            FileHardLinkFullIdInformation,                  // 62
            FileIdExtdBothDirectoryInformation,             // 63
            FileDispositionInformationEx,                   // 64
            FileRenameInformationEx,                        // 65
            FileRenameInformationExBypassAccessCheck,       // 66
            FileDesiredStorageClassInformation,             // 67
            FileStatInformation,                            // 68
            FileMemoryPartitionInformation,                 // 69
            FileStatLxInformation,                          // 70
            FileCaseSensitiveInformation,                   // 71
            FileLinkInformationEx,                          // 72
            FileLinkInformationExBypassAccessCheck,         // 73
            FileStorageReserveIdInformation,                // 74
            FileCaseSensitiveInformationForceAccessCheck,   // 75

            FileMaximumInformation
} FILE_INFORMATION_CLASS, * PFILE_INFORMATION_CLASS;

typedef VOID(NTAPI* PIO_APC_ROUTINE)(
    _In_ PVOID ApcContext,
    _In_ PIO_STATUS_BLOCK IoStatusBlock,
    _In_ ULONG Reserved
    );

typedef struct CRED_BACKUP_FILE_HEADER {
    DWORD version;
    DWORD CredentialsSize;
    DWORD unknwn;
} CRED_BACKUP_FILE_HEADER, * PCRED_BACKUP_FILE_HEADER;


typedef struct _KULL_M_CRED_ATTRIBUTE {
    DWORD Flags;

    DWORD dwKeyword;
    LPWSTR Keyword;

    DWORD ValueSize;
    LPBYTE Value;
} KULL_M_CRED_ATTRIBUTE, * PKULL_M_CRED_ATTRIBUTE;

typedef struct _KULL_M_CRED_BLOB {
    DWORD	credFlags;
    DWORD	credSize;
    DWORD	credUnk0;

    DWORD Type;
    DWORD Flags;
    FILETIME LastWritten;
    DWORD	unkFlagsOrSize;
    DWORD	Persist;
    DWORD	AttributeCount;
    DWORD	unk0;
    DWORD	unk1;

    DWORD	dwTargetName;
    LPWSTR	TargetName;

    DWORD	dwTargetAlias;
    LPWSTR	TargetAlias;

    DWORD	dwComment;
    LPWSTR	Comment;

    DWORD	dwUnkData;
    LPWSTR	UnkData;

    DWORD	dwUserName;
    LPWSTR	UserName;

    DWORD	CredentialBlobSize;
    LPBYTE	CredentialBlob;

    PKULL_M_CRED_ATTRIBUTE* Attributes;

} KULL_M_CRED_BLOB, * PKULL_M_CRED_BLOB;

typedef BOOL(WINAPI* pCredBackupCredentials) (
    HANDLE Token,
    LPCWSTR Path,
    PVOID Password,
    DWORD PasswordSize,
    DWORD Flags);

typedef __kernel_entry NTSTATUS(WINAPI* pRtlAllocateAndInitializeSid)(
     PSID_IDENTIFIER_AUTHORITY IdentifierAuthority,
     UCHAR SubAuthorityCount,
     ULONG SubAuthority0,
     ULONG SubAuthority1,
     ULONG SubAuthority2,
     ULONG SubAuthority3,
     ULONG SubAuthority4,
     ULONG SubAuthority5,
     ULONG SubAuthority6,
     ULONG SubAuthority7,
     PSID* Sid
);

typedef __kernel_entry NTSTATUS (WINAPI* pRtlFreeSid)(
      PSID Sid
);

typedef __kernel_entry NTSTATUS(WINAPI* pNtQuerySystemInformation)(
     SYSTEM_INFORMATION_CLASS SystemInformationClass,
     PVOID SystemInformation,
     ULONG SystemInformationLength,
     PULONG ReturnLength
);

typedef __kernel_entry NTSTATUS(WINAPI* pNtOpenProcess)(
     PHANDLE ProcessHandle,
     ACCESS_MASK DesiredAccess,
     POBJECT_ATTRIBUTES ObjectAttributes,
     PCLIENT_ID ClientId
);

typedef __kernel_entry NTSTATUS (WINAPI* pNtOpenProcessToken)(
     HANDLE ProcessHandle,
     ACCESS_MASK DesiredAccess,
     PHANDLE TokenHandle
);

typedef __kernel_entry NTSTATUS(WINAPI* pNtDuplicateToken)(
     HANDLE ExistingTokenHandle,
     ACCESS_MASK DesiredAccess,
     POBJECT_ATTRIBUTES ObjectAttributes,
     BOOLEAN EffectiveOnly,
     TOKEN_TYPE Type,
     PHANDLE NewTokenHandle
);

typedef __kernel_entry NTSTATUS(WINAPI* pNtAdjustPrivilegesToken)(
     HANDLE TokenHandle,
     BOOLEAN DisableAllPrivileges,
     PTOKEN_PRIVILEGES NewState,
     ULONG BufferLength,
     PTOKEN_PRIVILEGES PreviousState,
     PULONG ReturnLength
);

typedef __kernel_entry NTSTATUS(WINAPI* pNtClose)(
    HANDLE Handle
);

typedef __kernel_entry NTSTATUS(WINAPI* pNtQueryInformationToken) (
     HANDLE TokenHandle,
     TOKEN_INFORMATION_CLASS TokenInformationClass,
     PVOID TokenInformation,
     ULONG TokenInformationLength,
     PULONG ReturnLength
);

typedef __kernel_entry NTSYSCALLAPI NTSTATUS(WINAPI* pNtSetInformationThread) (
    HANDLE          ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID           ThreadInformation,
    ULONG           ThreadInformationLength
    );

typedef __kernel_entry NTSTATUS(WINAPI* pNtDeleteFile) (
    POBJECT_ATTRIBUTES ObjectAttributes
);

typedef __kernel_entry NTSTATUS(WINAPI* pNtOpenFile)(
    PHANDLE            FileHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK   IoStatusBlock,
    ULONG              ShareAccess,
    ULONG              OpenOptions
    );

typedef __kernel_entry NTSTATUS(WINAPI* pNtQueryInformationFile) (
     HANDLE FileHandle,
     PIO_STATUS_BLOCK IoStatusBlock,
     PVOID FileInformation,
     ULONG Length,
     FILE_INFORMATION_CLASS FileInformationClass
);

typedef __kernel_entry NTSTATUS(WINAPI* pNtReadFile) (
     HANDLE FileHandle,
     HANDLE Event,
     PIO_APC_ROUTINE ApcRoutine,
     PVOID ApcContext,
     PIO_STATUS_BLOCK IoStatusBlock,
     PVOID Buffer,
     ULONG Length,
     PLARGE_INTEGER ByteOffset,
     PULONG Key
);

typedef __kernel_entry NTSTATUS (WINAPI* pNtCreateFile) (
     PHANDLE            FileHandle,
     ACCESS_MASK        DesiredAccess,
     POBJECT_ATTRIBUTES ObjectAttributes,
     PIO_STATUS_BLOCK   IoStatusBlock,
     PLARGE_INTEGER     AllocationSize,
     ULONG              FileAttributes,
     ULONG              ShareAccess,
     ULONG              CreateDisposition,
     ULONG              CreateOptions,
     PVOID              EaBuffer,
     ULONG              EaLength
);

typedef __kernel_entry ULONG (WINAPI* pRtlGetCurrentDirectory_U) (
    ULONG  	MaximumLength,
    PWSTR  	Buffer
);

typedef NTSTATUS(WINAPI* pRtlQueryEnvironmentVariable_U) (
    PVOID                Environment OPTIONAL,
    PUNICODE_STRING      VariableName,
    PUNICODE_STRING     VariableValue
    );

typedef BOOL (WINAPI* CheckTokenMembership_)(
     HANDLE TokenHandle,
     PSID   SidToCheck,
     PBOOL  IsMember
);

typedef BOOL (WINAPI* LookupPrivilegeValueW_)(
     LPCWSTR lpSystemName,
     LPCWSTR lpName,
     PLUID   lpLuid
);

typedef BOOL (WINAPI* ConvertSidToStringSidA_)(
     PSID  Sid,
     LPSTR* StringSid
);

typedef BOOL (WINAPI* LookupAccountSidA_)(
      LPCSTR        lpSystemName,
      PSID          Sid,
      LPSTR         Name,
      LPDWORD       cchName,
      LPSTR         ReferencedDomainName,
      LPDWORD       cchReferencedDomainName,
      PSID_NAME_USE peUse
);

typedef BOOL (WINAPI* CryptUnprotectData_)(
     DATA_BLOB* pDataIn,
     LPWSTR* ppszDataDescr,
     DATA_BLOB* pOptionalEntropy,
     PVOID                     pvReserved,
     CRYPTPROTECT_PROMPTSTRUCT* pPromptStruct,
     DWORD                     dwFlags,
     DATA_BLOB* pDataOut
);

typedef BOOL (WINAPI* WriteFile_) (
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

BOOL bResolveFunctions(void);
void doBackup(LPCWSTR lpFile);
