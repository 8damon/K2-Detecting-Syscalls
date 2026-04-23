#include "K2.h"

static FAST_MUTEX g_ModuleCacheLock;
static K2_PROCESS_MODULE_CACHE_ENTRY g_ModuleCache[K2_MODULE_CACHE_SLOTS] = { 0 };

static
PVOID
K2FindNtdllBaseInProcess(
    _In_ PEPROCESS Process
    );

static
PVOID
K2FindModuleBaseInProcess(
    _In_ PEPROCESS Process,
    _In_ PCUNICODE_STRING ModuleName
    );

static
BOOLEAN
K2ResolveImageBackedUserAddress(
    _In_ PVOID Address,
    _Out_ PK2_FRAME_RESOLUTION Resolution
    );

static
BOOLEAN
K2LookupProcessModuleCache(
    _In_ HANDLE ProcessId,
    _Out_opt_ PVOID* NtdllBase,
    _Out_opt_ PVOID* Win32uBase
    );

static
VOID
K2StoreProcessModuleCache(
    _In_ HANDLE ProcessId,
    _In_opt_ PVOID NtdllBase,
    _In_opt_ PVOID Win32uBase
    );

static
BOOLEAN
K2PopulateCurrentProcessModuleCache(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Out_opt_ PVOID* NtdllBase,
    _Out_opt_ PVOID* Win32uBase
    );

static
BOOLEAN
K2PopulateFrameResolution(
    _In_ PVOID ModuleBase,
    _In_ PVOID Address,
    _Out_ PK2_FRAME_RESOLUTION Resolution,
    _In_opt_ PCUNICODE_STRING ModuleName
    );

static
BOOLEAN
K2QueryProcessModuleForAddress(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_ PK2_FRAME_RESOLUTION Resolution
    );

VOID
K2InitializeModuleCache(
    VOID
    )
{
    ExInitializeFastMutex(&g_ModuleCacheLock);
}

ULONG
K2CaptureUserFrames(
    _Out_writes_(FrameCount) PVOID* Frames,
    _In_ ULONG FrameCount
    )
{
    __try {
        return RtlWalkFrameChain(Frames, FrameCount, K2_SYSCALL_STACK_FLAG_USER_MODE);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

PVOID
K2GetCurrentProcessNtdllBase(
    VOID
    )
{
    PEPROCESS process;
    PVOID ntdllBase;

    process = PsGetCurrentProcess();
    if (process == NULL || PsGetProcessWow64Process(process) != NULL) {
        return NULL;
    }

    if (K2LookupProcessModuleCache(PsGetCurrentProcessId(), &ntdllBase, NULL)) {
        return ntdllBase;
    }

    if (!K2PopulateCurrentProcessModuleCache(process, PsGetCurrentProcessId(), &ntdllBase, NULL)) {
        return NULL;
    }

    return ntdllBase;
}

PVOID
K2GetCurrentProcessWin32uBase(
    VOID
    )
{
    PEPROCESS process;
    PVOID win32uBase;

    process = PsGetCurrentProcess();
    if (process == NULL || PsGetProcessWow64Process(process) != NULL) {
        return NULL;
    }

    if (K2LookupProcessModuleCache(PsGetCurrentProcessId(), NULL, &win32uBase)) {
        return win32uBase;
    }

    if (!K2PopulateCurrentProcessModuleCache(process, PsGetCurrentProcessId(), NULL, &win32uBase)) {
        return NULL;
    }

    return win32uBase;
}

static
BOOLEAN
K2PopulateCurrentProcessModuleCache(
    _In_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Out_opt_ PVOID* NtdllBase,
    _Out_opt_ PVOID* Win32uBase
    )
{
    UNICODE_STRING win32uName = RTL_CONSTANT_STRING(L"win32u.dll");
    PVOID localNtdllBase;
    PVOID localWin32uBase;

    localNtdllBase = K2FindNtdllBaseInProcess(Process);
    localWin32uBase = K2FindModuleBaseInProcess(Process, &win32uName);
    K2StoreProcessModuleCache(ProcessId, localNtdllBase, localWin32uBase);

    if (NtdllBase != NULL) {
        *NtdllBase = localNtdllBase;
    }

    if (Win32uBase != NULL) {
        *Win32uBase = localWin32uBase;
    }

    return localNtdllBase != NULL || localWin32uBase != NULL;
}

static
PVOID
K2FindNtdllBaseInProcess(
    _In_ PEPROCESS Process
    )
{
    UNICODE_STRING ntdllName = RTL_CONSTANT_STRING(L"ntdll.dll");
    return K2FindModuleBaseInProcess(Process, &ntdllName);
}

static
PVOID
K2FindModuleBaseInProcess(
    _In_ PEPROCESS Process,
    _In_ PCUNICODE_STRING ModuleName
    )
{
    KAPC_STATE apcState;
    PK2_PEB peb;
    PK2_PEB_LDR_DATA ldr;
    PLIST_ENTRY head;
    PLIST_ENTRY entry;
    PVOID result;

    result = NULL;
    peb = (PK2_PEB)PsGetProcessPeb(Process);
    if (peb == NULL) {
        return NULL;
    }

    KeStackAttachProcess(Process, &apcState);
    __try {
        ProbeForRead(peb, sizeof(*peb), sizeof(UCHAR));
        ldr = peb->Ldr;
        if (ldr == NULL) {
            __leave;
        }

        ProbeForRead(ldr, sizeof(*ldr), sizeof(UCHAR));
        head = &ldr->InMemoryOrderModuleList;
        for (entry = head->Flink; entry != head; entry = entry->Flink) {
            PK2_LDR_DATA_TABLE_ENTRY module;

            ProbeForRead(entry, sizeof(*entry), sizeof(UCHAR));
            module = CONTAINING_RECORD(entry, K2_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            ProbeForRead(module, sizeof(*module), sizeof(UCHAR));
            if (module->DllBase == NULL || module->FullDllName.Buffer == NULL) {
                continue;
            }

            ProbeForRead(module->FullDllName.Buffer, module->FullDllName.Length, sizeof(WCHAR));
            if (K2EndsWithUnicodeInsensitive(&module->FullDllName, ModuleName)) {
                result = module->DllBase;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result = NULL;
    }
    KeUnstackDetachProcess(&apcState);

    return result;
}

BOOLEAN
K2ResolveUserFrame(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_ PK2_FRAME_RESOLUTION Resolution
    )
{
    RtlZeroMemory(Resolution, sizeof(*Resolution));
    Resolution->Address = Address;

    if (K2QueryProcessModuleForAddress(Process, Address, Resolution)) {
        return TRUE;
    }

    return K2ResolveImageBackedUserAddress(Address, Resolution);
}

static
BOOLEAN
K2QueryProcessModuleForAddress(
    _In_ PEPROCESS Process,
    _In_ PVOID Address,
    _Out_ PK2_FRAME_RESOLUTION Resolution
    )
{
    KAPC_STATE apcState;
    PK2_PEB peb;
    PK2_PEB_LDR_DATA ldr;
    PLIST_ENTRY head;
    PLIST_ENTRY entry;
    BOOLEAN resolved;

    resolved = FALSE;
    peb = (PK2_PEB)PsGetProcessPeb(Process);
    if (peb == NULL) {
        return FALSE;
    }

    KeStackAttachProcess(Process, &apcState);
    __try {
        ProbeForRead(peb, sizeof(*peb), sizeof(UCHAR));
        ldr = peb->Ldr;
        if (ldr == NULL) {
            __leave;
        }

        ProbeForRead(ldr, sizeof(*ldr), sizeof(UCHAR));
        head = &ldr->InMemoryOrderModuleList;
        for (entry = head->Flink; entry != head; entry = entry->Flink) {
            PK2_LDR_DATA_TABLE_ENTRY module;

            ProbeForRead(entry, sizeof(*entry), sizeof(UCHAR));
            module = CONTAINING_RECORD(entry, K2_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            ProbeForRead(module, sizeof(*module), sizeof(UCHAR));
            if (module->DllBase == NULL || module->FullDllName.Buffer == NULL) {
                continue;
            }

            ProbeForRead(module->FullDllName.Buffer, module->FullDllName.Length, sizeof(WCHAR));
            if (K2PopulateFrameResolution(module->DllBase, Address, Resolution, &module->FullDllName)) {
                resolved = TRUE;
                break;
            }
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        resolved = FALSE;
    }
    KeUnstackDetachProcess(&apcState);

    return resolved;
}

static
BOOLEAN
K2PopulateFrameResolution(
    _In_ PVOID ModuleBase,
    _In_ PVOID Address,
    _Out_ PK2_FRAME_RESOLUTION Resolution,
    _In_opt_ PCUNICODE_STRING ModuleName
    )
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    CHAR exportName[K2_MAX_NAME_CHARS];
    PVOID exportBase;
    SIZE_T exportSpan;

    __try {
        dos = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dos, sizeof(*dos), sizeof(UCHAR));
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }

        nt = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dos->e_lfanew);
        ProbeForRead(nt, sizeof(*nt), sizeof(UCHAR));
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            Address < ModuleBase ||
            Address >= (PVOID)((PUCHAR)ModuleBase + nt->OptionalHeader.SizeOfImage)) {
            return FALSE;
        }

        Resolution->ModuleBase = ModuleBase;
        Resolution->ModuleSize = nt->OptionalHeader.SizeOfImage;
        Resolution->ModuleRva = (ULONG)((PUCHAR)Address - (PUCHAR)ModuleBase);
        Resolution->ModuleResolved = TRUE;
        if (ModuleName != NULL && ModuleName->Buffer != NULL) {
            K2CopyUnicodeBaseNameToAnsi(Resolution->ModuleName, sizeof(Resolution->ModuleName), ModuleName);
        } else {
            (VOID)RtlStringCbPrintfA(Resolution->ModuleName, sizeof(Resolution->ModuleName), "image@%p", ModuleBase);
        }

        exportName[0] = '\0';
        exportBase = NULL;
        exportSpan = 0;
        if (K2ResolveExportForAddress(ModuleBase, Address, &exportBase, &exportSpan, exportName) &&
            exportName[0] != '\0') {
            K2CopyAnsiString(Resolution->ExportName, sizeof(Resolution->ExportName), exportName);
            Resolution->ExportOffset = (ULONG)((PUCHAR)Address - (PUCHAR)exportBase);
            Resolution->ExportResolved = TRUE;
        }

        return TRUE;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

static
BOOLEAN
K2ResolveImageBackedUserAddress(
    _In_ PVOID Address,
    _Out_ PK2_FRAME_RESOLUTION Resolution
    )
{
    MEMORY_BASIC_INFORMATION mbi;

    if (!K2QueryAddressMemory(Address, &mbi) ||
        (mbi.Type & MEM_IMAGE) == 0 ||
        mbi.AllocationBase == NULL) {
        return FALSE;
    }

    return K2PopulateFrameResolution(mbi.AllocationBase, Address, Resolution, NULL);
}

BOOLEAN
K2ResolveExportForAddress(
    _In_ PVOID ModuleBase,
    _In_ PVOID Address,
    _Out_opt_ PVOID* ExportBase,
    _Out_opt_ PSIZE_T ExportSpan,
    _Out_writes_opt_(K2_MAX_NAME_CHARS) PCHAR ExportName
    )
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_EXPORT_DIRECTORY exports;
    PULONG functionTable;
    PULONG nameTable;
    PUSHORT ordinalTable;
    ULONG i;
    ULONG bestRva;
    ULONG nextRva;
    const CHAR* bestName;
    ULONG addressRva;

    if (ExportBase != NULL) {
        *ExportBase = NULL;
    }
    if (ExportSpan != NULL) {
        *ExportSpan = 0;
    }
    if (ExportName != NULL) {
        ExportName[0] = '\0';
    }

    __try {
        dos = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dos, sizeof(*dos), sizeof(UCHAR));
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }

        nt = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dos->e_lfanew);
        ProbeForRead(nt, sizeof(*nt), sizeof(UCHAR));
        if (nt->Signature != IMAGE_NT_SIGNATURE ||
            Address < ModuleBase ||
            Address >= (PVOID)((PUCHAR)ModuleBase + nt->OptionalHeader.SizeOfImage)) {
            return FALSE;
        }

        if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
            !K2IsRangeWithinImage(
                nt->OptionalHeader.SizeOfImage,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {
            return FALSE;
        }

        exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        ProbeForRead(exports, sizeof(*exports), sizeof(UCHAR));
        if (!K2IsRangeWithinImage(nt->OptionalHeader.SizeOfImage, exports->AddressOfFunctions, sizeof(ULONG) * exports->NumberOfFunctions) ||
            !K2IsRangeWithinImage(nt->OptionalHeader.SizeOfImage, exports->AddressOfNames, sizeof(ULONG) * exports->NumberOfNames) ||
            !K2IsRangeWithinImage(nt->OptionalHeader.SizeOfImage, exports->AddressOfNameOrdinals, sizeof(USHORT) * exports->NumberOfNames)) {
            return FALSE;
        }

        functionTable = (PULONG)((PUCHAR)ModuleBase + exports->AddressOfFunctions);
        nameTable = (PULONG)((PUCHAR)ModuleBase + exports->AddressOfNames);
        ordinalTable = (PUSHORT)((PUCHAR)ModuleBase + exports->AddressOfNameOrdinals);
        ProbeForRead(functionTable, sizeof(ULONG) * exports->NumberOfFunctions, sizeof(ULONG));
        ProbeForRead(nameTable, sizeof(ULONG) * exports->NumberOfNames, sizeof(ULONG));
        ProbeForRead(ordinalTable, sizeof(USHORT) * exports->NumberOfNames, sizeof(USHORT));

        addressRva = (ULONG)((PUCHAR)Address - (PUCHAR)ModuleBase);
        bestRva = 0;
        nextRva = nt->OptionalHeader.SizeOfImage;
        bestName = NULL;
        for (i = 0; i < exports->NumberOfNames; ++i) {
            USHORT ordinal;
            ULONG candidateRva;
            const CHAR* candidateName;

            ordinal = ordinalTable[i];
            if (ordinal >= exports->NumberOfFunctions) {
                continue;
            }

            candidateRva = functionTable[ordinal];
            if (candidateRva == 0 || candidateRva >= nt->OptionalHeader.SizeOfImage || !K2IsRangeWithinImage(nt->OptionalHeader.SizeOfImage, nameTable[i], sizeof(CHAR))) {
                continue;
            }

            candidateName = (const CHAR*)((PUCHAR)ModuleBase + nameTable[i]);
            ProbeForRead((PVOID)candidateName, 1, sizeof(CHAR));
            if (candidateRva <= addressRva && candidateRva >= bestRva) {
                bestRva = candidateRva;
                bestName = candidateName;
            }
            if (candidateRva > addressRva && candidateRva < nextRva) {
                nextRva = candidateRva;
            }
        }

        if (bestName == NULL) {
            return FALSE;
        }

        if (ExportBase != NULL) {
            *ExportBase = (PUCHAR)ModuleBase + bestRva;
        }
        if (ExportSpan != NULL) {
            *ExportSpan = nextRva > bestRva ? (SIZE_T)(nextRva - bestRva) : 1;
        }
        if (ExportName != NULL) {
            K2CopyAnsiString(ExportName, K2_MAX_NAME_CHARS, bestName);
        }

        return addressRva >= bestRva && addressRva < nextRva;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

BOOLEAN
K2FindNamedExport(
    _In_ PVOID ModuleBase,
    _In_z_ PCSTR ExportName,
    _Out_ PVOID* ExportBase,
    _Out_opt_ PSIZE_T ExportSpan
    )
{
    PIMAGE_DOS_HEADER dos;
    PIMAGE_NT_HEADERS64 nt;
    PIMAGE_EXPORT_DIRECTORY exports;
    PULONG functionTable;
    PULONG nameTable;
    PUSHORT ordinalTable;
    ULONG i;
    ULONG bestRva;
    ULONG nextRva;

    *ExportBase = NULL;
    if (ExportSpan != NULL) {
        *ExportSpan = 0;
    }

    __try {
        dos = (PIMAGE_DOS_HEADER)ModuleBase;
        ProbeForRead(dos, sizeof(*dos), sizeof(UCHAR));
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            return FALSE;
        }

        nt = (PIMAGE_NT_HEADERS64)((PUCHAR)ModuleBase + dos->e_lfanew);
        ProbeForRead(nt, sizeof(*nt), sizeof(UCHAR));
        if (nt->Signature != IMAGE_NT_SIGNATURE) {
            return FALSE;
        }

        if (nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 ||
            nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size < sizeof(IMAGE_EXPORT_DIRECTORY) ||
            !K2IsRangeWithinImage(
                nt->OptionalHeader.SizeOfImage,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress,
                nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)) {
            return FALSE;
        }

        exports = (PIMAGE_EXPORT_DIRECTORY)((PUCHAR)ModuleBase + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        ProbeForRead(exports, sizeof(*exports), sizeof(UCHAR));
        if (!K2IsRangeWithinImage(nt->OptionalHeader.SizeOfImage, exports->AddressOfFunctions, sizeof(ULONG) * exports->NumberOfFunctions) ||
            !K2IsRangeWithinImage(nt->OptionalHeader.SizeOfImage, exports->AddressOfNames, sizeof(ULONG) * exports->NumberOfNames) ||
            !K2IsRangeWithinImage(nt->OptionalHeader.SizeOfImage, exports->AddressOfNameOrdinals, sizeof(USHORT) * exports->NumberOfNames)) {
            return FALSE;
        }

        functionTable = (PULONG)((PUCHAR)ModuleBase + exports->AddressOfFunctions);
        nameTable = (PULONG)((PUCHAR)ModuleBase + exports->AddressOfNames);
        ordinalTable = (PUSHORT)((PUCHAR)ModuleBase + exports->AddressOfNameOrdinals);
        ProbeForRead(functionTable, sizeof(ULONG) * exports->NumberOfFunctions, sizeof(ULONG));
        ProbeForRead(nameTable, sizeof(ULONG) * exports->NumberOfNames, sizeof(ULONG));
        ProbeForRead(ordinalTable, sizeof(USHORT) * exports->NumberOfNames, sizeof(USHORT));

        for (i = 0; i < exports->NumberOfNames; ++i) {
            const CHAR* candidateName;
            USHORT ordinal;

            if (!K2IsRangeWithinImage(nt->OptionalHeader.SizeOfImage, nameTable[i], sizeof(CHAR))) {
                continue;
            }

            candidateName = (const CHAR*)((PUCHAR)ModuleBase + nameTable[i]);
            ProbeForRead((PVOID)candidateName, 1, sizeof(CHAR));
            if (!K2StringsEqualInsensitiveA(candidateName, ExportName)) {
                continue;
            }

            ordinal = ordinalTable[i];
            if (ordinal >= exports->NumberOfFunctions) {
                return FALSE;
            }

            bestRva = functionTable[ordinal];
            if (bestRva == 0 || bestRva >= nt->OptionalHeader.SizeOfImage) {
                return FALSE;
            }

            nextRva = nt->OptionalHeader.SizeOfImage;
            for (ULONG j = 0; j < exports->NumberOfFunctions; ++j) {
                ULONG candidateRva;

                candidateRva = functionTable[j];
                if (candidateRva > bestRva && candidateRva < nextRva) {
                    nextRva = candidateRva;
                }
            }

            *ExportBase = (PUCHAR)ModuleBase + bestRva;
            if (ExportSpan != NULL) {
                *ExportSpan = nextRva > bestRva ? (SIZE_T)(nextRva - bestRva) : 1;
            }

            return TRUE;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }

    return FALSE;
}

BOOLEAN
K2QueryAddressMemory(
    _In_ PVOID Address,
    _Out_ PMEMORY_BASIC_INFORMATION Mbi
    )
{
    SIZE_T returnedLength;
    NTSTATUS status;

    RtlZeroMemory(Mbi, sizeof(*Mbi));
    if (!K2IsLikelyUserAddress(Address)) {
        return FALSE;
    }

    status = ZwQueryVirtualMemory(
        ZwCurrentProcess(),
        Address,
        MemoryBasicInformation,
        Mbi,
        sizeof(*Mbi),
        &returnedLength);

    return NT_SUCCESS(status) &&
           returnedLength >= sizeof(*Mbi) &&
           Mbi->State == MEM_COMMIT;
}

static
BOOLEAN
K2LookupProcessModuleCache(
    _In_ HANDLE ProcessId,
    _Out_opt_ PVOID* NtdllBase,
    _Out_opt_ PVOID* Win32uBase
    )
{
    ULONG i;
    BOOLEAN found;

    if (NtdllBase != NULL) {
        *NtdllBase = NULL;
    }
    if (Win32uBase != NULL) {
        *Win32uBase = NULL;
    }

    found = FALSE;
    ExAcquireFastMutex(&g_ModuleCacheLock);
    for (i = 0; i < RTL_NUMBER_OF(g_ModuleCache); ++i) {
        if (g_ModuleCache[i].ProcessId != ProcessId) {
            continue;
        }

        if (NtdllBase != NULL) {
            *NtdllBase = g_ModuleCache[i].NtdllBase;
            found = found || (g_ModuleCache[i].NtdllBase != NULL);
        }
        if (Win32uBase != NULL) {
            *Win32uBase = g_ModuleCache[i].Win32uBase;
            found = found || (g_ModuleCache[i].Win32uBase != NULL);
        }
        break;
    }
    ExReleaseFastMutex(&g_ModuleCacheLock);

    return found;
}

static
VOID
K2StoreProcessModuleCache(
    _In_ HANDLE ProcessId,
    _In_opt_ PVOID NtdllBase,
    _In_opt_ PVOID Win32uBase
    )
{
    ULONG i;
    ULONG emptyIndex;

    emptyIndex = RTL_NUMBER_OF(g_ModuleCache);
    ExAcquireFastMutex(&g_ModuleCacheLock);
    for (i = 0; i < RTL_NUMBER_OF(g_ModuleCache); ++i) {
        if (g_ModuleCache[i].ProcessId == ProcessId) {
            if (NtdllBase != NULL) {
                g_ModuleCache[i].NtdllBase = NtdllBase;
            }
            if (Win32uBase != NULL) {
                g_ModuleCache[i].Win32uBase = Win32uBase;
            }

            ExReleaseFastMutex(&g_ModuleCacheLock);
            return;
        }

        if (g_ModuleCache[i].ProcessId == NULL && emptyIndex == RTL_NUMBER_OF(g_ModuleCache)) {
            emptyIndex = i;
        }
    }

    if (emptyIndex == RTL_NUMBER_OF(g_ModuleCache)) {
        emptyIndex = HandleToULong(ProcessId) % RTL_NUMBER_OF(g_ModuleCache);
    }

    g_ModuleCache[emptyIndex].ProcessId = ProcessId;
    g_ModuleCache[emptyIndex].NtdllBase = NtdllBase;
    g_ModuleCache[emptyIndex].Win32uBase = Win32uBase;
    ExReleaseFastMutex(&g_ModuleCacheLock);
}

VOID
K2InvalidateProcessModuleCache(
    _In_ HANDLE ProcessId
    )
{
    ULONG i;

    ExAcquireFastMutex(&g_ModuleCacheLock);
    for (i = 0; i < RTL_NUMBER_OF(g_ModuleCache); ++i) {
        if (g_ModuleCache[i].ProcessId != ProcessId) {
            continue;
        }

        RtlZeroMemory(&g_ModuleCache[i], sizeof(g_ModuleCache[i]));
        break;
    }
    ExReleaseFastMutex(&g_ModuleCacheLock);
}
