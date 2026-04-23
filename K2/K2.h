#pragma once

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>

#define K2_TAG '2SKK'
#define K2_MAX_STACK_FRAMES 16
#define K2_MAX_NAME_CHARS 64
#define K2_MAX_EXPECTED_EXPORTS 4
#define K2_MODULE_CACHE_SLOTS 16
#define K2_DETECTION_CACHE_SLOTS 32
#define K2_DUPLICATE_WINDOW_100NS (5ULL * 1000ULL * 1000ULL * 10ULL)
#define K2_SYSCALL_STACK_FLAG_USER_MODE 0x1UL

#ifndef MEM_IMAGE
#define MEM_IMAGE 0x01000000UL
#endif

typedef struct _K2_PEB_LDR_DATA {
    UCHAR Reserved1[8];
    PVOID Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} K2_PEB_LDR_DATA, *PK2_PEB_LDR_DATA;

typedef struct _K2_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
} K2_LDR_DATA_TABLE_ENTRY, *PK2_LDR_DATA_TABLE_ENTRY;

typedef struct _K2_PEB {
    UCHAR Reserved1[2];
    UCHAR BeingDebugged;
    UCHAR Reserved2[1];
    PVOID Reserved3[2];
    PK2_PEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
} K2_PEB, *PK2_PEB;

typedef struct _K2_RTL_USER_PROCESS_PARAMETERS {
    UCHAR Reserved1[16];
    PVOID Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} K2_RTL_USER_PROCESS_PARAMETERS, *PK2_RTL_USER_PROCESS_PARAMETERS;

typedef struct _K2_EVENT_SPEC {
    PCSTR EventName;
    BOOLEAN StrictExportMatch;
    ULONG ExportCount;
    PCSTR Exports[K2_MAX_EXPECTED_EXPORTS];
} K2_EVENT_SPEC, *PK2_EVENT_SPEC;

typedef struct _K2_EXPORT_RESOLUTION {
    PCSTR Name;
    PVOID Base;
    SIZE_T Span;
} K2_EXPORT_RESOLUTION, *PK2_EXPORT_RESOLUTION;

typedef struct _K2_SYSCALL_ANALYSIS {
    BOOLEAN Frame0InNtdll;
    BOOLEAN Frame0InWin32u;
    BOOLEAN Frame0InExpectedExport;
    BOOLEAN Frame0InDifferentNtdllExport;
    BOOLEAN Frame0InvalidUserAddress;
    BOOLEAN CallerFrameExecutable;
    BOOLEAN CallerFramePrivate;
    BOOLEAN CallerFrameWritable;
    BOOLEAN CallerFrameImage;
    BOOLEAN NtdllLookupFailed;
    BOOLEAN UserStackUnavailable;
    BOOLEAN StrictExportMatch;
    ULONG FrameCount;
    ULONG ExpectedExportCount;
    CHAR ProcessName[K2_MAX_NAME_CHARS];
    PVOID NtdllBase;
    PVOID Win32uBase;
    PVOID Frame0;
    PVOID Frame1;
    K2_EXPORT_RESOLUTION ExpectedExports[K2_MAX_EXPECTED_EXPORTS];
    PVOID ResolvedExportBase;
    SIZE_T ResolvedExportSpan;
    CHAR ResolvedExportName[K2_MAX_NAME_CHARS];
    PVOID Frames[K2_MAX_STACK_FRAMES];
    MEMORY_BASIC_INFORMATION CallerMbi;
} K2_SYSCALL_ANALYSIS, *PK2_SYSCALL_ANALYSIS;

typedef struct _K2_FRAME_RESOLUTION {
    PVOID Address;
    PVOID ModuleBase;
    SIZE_T ModuleSize;
    ULONG ModuleRva;
    ULONG ExportOffset;
    BOOLEAN ModuleResolved;
    BOOLEAN ExportResolved;
    CHAR ModuleName[K2_MAX_NAME_CHARS];
    CHAR ExportName[K2_MAX_NAME_CHARS];
} K2_FRAME_RESOLUTION, *PK2_FRAME_RESOLUTION;

typedef struct _K2_PROCESS_MODULE_CACHE_ENTRY {
    HANDLE ProcessId;
    PVOID NtdllBase;
    PVOID Win32uBase;
} K2_PROCESS_MODULE_CACHE_ENTRY, *PK2_PROCESS_MODULE_CACHE_ENTRY;

typedef struct _K2_DETECTION_CACHE_ENTRY {
    ULONG Signature;
    ULONGLONG LastSeenTime;
} K2_DETECTION_CACHE_ENTRY, *PK2_DETECTION_CACHE_ENTRY;

extern NTKERNELAPI PPEB PsGetProcessPeb(_In_ PEPROCESS Process);
extern NTKERNELAPI PVOID PsGetProcessWow64Process(_In_ PEPROCESS Process);
extern NTKERNELAPI PUCHAR PsGetProcessImageFileName(_In_ PEPROCESS Process);

VOID
K2Log(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    );

VOID
K2InitializeAnalysisCache(
    VOID
    );

VOID
K2InitializeModuleCache(
    VOID
    );

VOID
K2InspectCurrentThread(
    _In_ const K2_EVENT_SPEC* Spec
    );

VOID
K2ProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    );

VOID
K2ThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    );

OB_PREOP_CALLBACK_STATUS
K2PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    );

ULONG
K2CaptureUserFrames(
    _Out_writes_(FrameCount) PVOID* Frames,
    _In_ ULONG FrameCount
    );

PVOID
K2GetCurrentProcessNtdllBase(
    VOID
    );

PVOID
K2GetCurrentProcessWin32uBase(
    VOID
    );

BOOLEAN
K2FindNamedExport(
    _In_ PVOID ModuleBase,
    _In_z_ PCSTR ExportName,
    _Out_ PVOID* ExportBase,
    _Out_opt_ PSIZE_T ExportSpan
    );

BOOLEAN
K2ResolveExportForAddress(
    _In_ PVOID ModuleBase,
    _In_ PVOID Address,
    _Out_opt_ PVOID* ExportBase,
    _Out_opt_ PSIZE_T ExportSpan,
    _Out_writes_opt_(K2_MAX_NAME_CHARS) PCHAR ExportName
    );

BOOLEAN
K2ResolveUserFrame(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_ PK2_FRAME_RESOLUTION Resolution
    );

BOOLEAN
K2QueryAddressMemory(
    _In_ PVOID Address,
    _Out_ PMEMORY_BASIC_INFORMATION Mbi
    );

VOID
K2InvalidateProcessModuleCache(
    _In_ HANDLE ProcessId
    );

BOOLEAN
K2IsLikelyUserAddress(
    _In_ PVOID Address
    );

BOOLEAN
K2IsRangeWithinImage(
    _In_ SIZE_T ImageSize,
    _In_ ULONG Rva,
    _In_ SIZE_T Length
    );

BOOLEAN
K2IsExecutableProtection(
    _In_ ULONG Protect
    );

BOOLEAN
K2IsWritableProtection(
    _In_ ULONG Protect
    );

BOOLEAN
K2IsSuspiciousCallerMemory(
    _In_ const MEMORY_BASIC_INFORMATION* Mbi
    );

PCSTR
K2MemoryTypeToString(
    _In_ ULONG Type
    );

VOID
K2CopyProcessName(
    _Out_writes_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength
    );

VOID
K2CopyAnsiString(
    _Out_writes_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength,
    _In_opt_z_ PCSTR Source
    );

VOID
K2CopyUnicodeBaseNameToAnsi(
    _Out_writes_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength,
    _In_ PCUNICODE_STRING Source
    );

VOID
K2AppendReason(
    _Inout_updates_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength,
    _In_z_ PCSTR Reason
    );

BOOLEAN
K2EndsWithUnicodeInsensitive(
    _In_ PCUNICODE_STRING Value,
    _In_ PCUNICODE_STRING Suffix
    );

BOOLEAN
K2StringsEqualInsensitiveA(
    _In_z_ PCSTR Left,
    _In_z_ PCSTR Right
    );
