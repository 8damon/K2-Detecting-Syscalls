#include "K2.h"

static volatile LONG g_DetectionSequence = 0;
static FAST_MUTEX g_DetectionCacheLock;
static K2_DETECTION_CACHE_ENTRY g_DetectionCache[K2_DETECTION_CACHE_SLOTS] = { 0 };

static
VOID
K2LogDetectionDetails(
    _In_ const K2_EVENT_SPEC* Spec,
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    );

static
BOOLEAN
K2AnalyzeCurrentUserStack(
    _In_ const K2_EVENT_SPEC* Spec,
    _Out_ PK2_SYSCALL_ANALYSIS Analysis
    );

static
BOOLEAN
K2ShouldLogDetection(
    _In_z_ PCSTR EventName,
    _In_z_ PCSTR Reasons,
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    );

static
ULONG
K2HashDetectionSignature(
    _In_z_ PCSTR EventName,
    _In_z_ PCSTR Reasons,
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    );

static
BOOLEAN
K2TryResolveExpectedExport(
    _In_ PVOID ModuleBase,
    _In_opt_z_ PCSTR ExportName,
    _Out_ PK2_EXPORT_RESOLUTION Export
    );

static
VOID
K2ResolveExpectedExports(
    _In_ PVOID NtdllBase,
    _In_ const K2_EVENT_SPEC* Spec,
    _Out_ PK2_SYSCALL_ANALYSIS Analysis
    );

static
PVOID
K2InferNtdllBaseFromFrame(
    _In_ PVOID Frame,
    _In_ const K2_EVENT_SPEC* Spec
    );

static
BOOLEAN
K2AddressInRange(
    _In_ PVOID Address,
    _In_opt_ PVOID Base,
    _In_ SIZE_T Span
    );

static
BOOLEAN
K2FrameMatchesExpectedExport(
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    );

static
VOID
K2PopulateCallerAnalysis(
    _Inout_ PK2_SYSCALL_ANALYSIS Analysis
    );

static
VOID
K2BuildDetectionReasons(
    _Out_writes_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength,
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    );

static
VOID
K2LogStackFrame(
    _In_ ULONG Index,
    _In_ PVOID Address
    );

static
BOOLEAN
K2ShouldFlagAnalysis(
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    );

VOID
K2InitializeAnalysisCache(
    VOID
    )
{
    ExInitializeFastMutex(&g_DetectionCacheLock);
}

VOID
K2InspectCurrentThread(
    _In_ const K2_EVENT_SPEC* Spec
    )
{
    K2_SYSCALL_ANALYSIS analysis;

    if (Spec == NULL || !K2AnalyzeCurrentUserStack(Spec, &analysis)) {
        return;
    }

    K2LogDetectionDetails(Spec, &analysis);
}

static
VOID
K2LogDetectionDetails(
    _In_ const K2_EVENT_SPEC* Spec,
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    )
{
    static const PCSTR g_ExportLabels[K2_MAX_EXPECTED_EXPORTS] = { "expected", "alt", "alt2", "alt3" };
    CHAR reasons[128];
    LONG detectionId;
    ULONG i;

    K2BuildDetectionReasons(reasons, sizeof(reasons), Analysis);
    if (!K2ShouldLogDetection(Spec->EventName, reasons, Analysis)) {
        return;
    }

    detectionId = InterlockedIncrement(&g_DetectionSequence);

    K2Log("============================================================\n");
    K2Log("id=%ld event=%s process=%s\n", detectionId, Spec->EventName, Analysis->ProcessName);
    K2Log("  pid=%p tid=%p frameCount=%lu\n", PsGetCurrentProcessId(), PsGetCurrentThreadId(), Analysis->FrameCount);
    K2Log("  reasons=%s\n", reasons);
    K2Log("  ntdll=%p frame0=%p\n", Analysis->NtdllBase, Analysis->Frame0);
    K2Log(
        "  resolved=%s base=%p span=0x%Ix\n",
        Analysis->ResolvedExportName[0] != '\0' ? Analysis->ResolvedExportName : "n/a",
        Analysis->ResolvedExportBase,
        Analysis->ResolvedExportSpan);

    for (i = 0; i < Analysis->ExpectedExportCount; ++i) {
        K2Log(
            "  %s=%s base=%p span=0x%Ix\n",
            g_ExportLabels[i],
            Analysis->ExpectedExports[i].Name != NULL ? Analysis->ExpectedExports[i].Name : "n/a",
            Analysis->ExpectedExports[i].Base,
            Analysis->ExpectedExports[i].Span);
    }

    K2Log(
        "  caller=%p type=%s(0x%lx)\n",
        Analysis->Frame1,
        K2MemoryTypeToString(Analysis->CallerMbi.Type),
        Analysis->CallerMbi.Type);
    K2Log(
        "  callerProtect=0x%lx exec=%u private=%u writable=%u image=%u\n",
        Analysis->CallerMbi.Protect,
        Analysis->CallerFrameExecutable,
        Analysis->CallerFramePrivate,
        Analysis->CallerFrameWritable,
        Analysis->CallerFrameImage);

    for (i = 0; i < Analysis->FrameCount && i < RTL_NUMBER_OF(Analysis->Frames); ++i) {
        K2LogStackFrame(i, Analysis->Frames[i]);
    }

    K2Log("============================================================\n");
}

static
BOOLEAN
K2AnalyzeCurrentUserStack(
    _In_ const K2_EVENT_SPEC* Spec,
    _Out_ PK2_SYSCALL_ANALYSIS Analysis
    )
{
    PVOID frames[K2_MAX_STACK_FRAMES];
    ULONG frameCount;
    PVOID exportBase;
    SIZE_T exportSpan;

    RtlZeroMemory(Analysis, sizeof(*Analysis));
    Analysis->StrictExportMatch = Spec->StrictExportMatch;
    Analysis->ExpectedExportCount = Spec->ExportCount;

    K2CopyProcessName(Analysis->ProcessName, sizeof(Analysis->ProcessName));
    frameCount = K2CaptureUserFrames(frames, RTL_NUMBER_OF(frames));
    if (frameCount == 0) {
        Analysis->UserStackUnavailable = TRUE;
        return FALSE;
    }

    Analysis->FrameCount = frameCount;
    RtlCopyMemory(Analysis->Frames, frames, sizeof(PVOID) * frameCount);
    Analysis->Frame0 = frames[0];
    Analysis->Frame1 = frameCount > 1 ? frames[1] : NULL;
    Analysis->Frame0InvalidUserAddress = !K2IsLikelyUserAddress(Analysis->Frame0);
    if (Analysis->Frame0InvalidUserAddress) {
        return Spec->StrictExportMatch;
    }

    Analysis->NtdllBase = K2GetCurrentProcessNtdllBase();
    Analysis->Win32uBase = K2GetCurrentProcessWin32uBase();
    if (Analysis->NtdllBase == NULL) {
        Analysis->NtdllBase = K2InferNtdllBaseFromFrame(Analysis->Frame0, Spec);
    }

    if (Analysis->NtdllBase == NULL) {
        Analysis->NtdllLookupFailed = TRUE;
        return TRUE;
    }

    K2ResolveExpectedExports(Analysis->NtdllBase, Spec, Analysis);

    exportBase = NULL;
    exportSpan = 0;
    if (K2ResolveExportForAddress(Analysis->NtdllBase, Analysis->Frame0, &exportBase, &exportSpan, Analysis->ResolvedExportName)) {
        Analysis->Frame0InNtdll = TRUE;
        Analysis->ResolvedExportBase = exportBase;
        Analysis->ResolvedExportSpan = exportSpan;
        Analysis->Frame0InExpectedExport = !Spec->StrictExportMatch || K2FrameMatchesExpectedExport(Analysis);
        Analysis->Frame0InDifferentNtdllExport = Spec->StrictExportMatch && !Analysis->Frame0InExpectedExport;
    }

    if (Analysis->Win32uBase != NULL &&
        K2ResolveExportForAddress(Analysis->Win32uBase, Analysis->Frame0, NULL, NULL, NULL)) {
        Analysis->Frame0InWin32u = TRUE;
    }

    K2PopulateCallerAnalysis(Analysis);
    return K2ShouldFlagAnalysis(Analysis);
}

static
BOOLEAN
K2TryResolveExpectedExport(
    _In_ PVOID ModuleBase,
    _In_opt_z_ PCSTR ExportName,
    _Out_ PK2_EXPORT_RESOLUTION Export
    )
{
    Export->Name = ExportName;
    Export->Base = NULL;
    Export->Span = 0;

    return ExportName != NULL && K2FindNamedExport(ModuleBase, ExportName, &Export->Base, &Export->Span);
}

static
VOID
K2ResolveExpectedExports(
    _In_ PVOID NtdllBase,
    _In_ const K2_EVENT_SPEC* Spec,
    _Out_ PK2_SYSCALL_ANALYSIS Analysis
    )
{
    ULONG i;

    for (i = 0; i < Spec->ExportCount && i < RTL_NUMBER_OF(Analysis->ExpectedExports); ++i) {
        (VOID)K2TryResolveExpectedExport(NtdllBase, Spec->Exports[i], &Analysis->ExpectedExports[i]);
    }
}

static
PVOID
K2InferNtdllBaseFromFrame(
    _In_ PVOID Frame,
    _In_ const K2_EVENT_SPEC* Spec
    )
{
    MEMORY_BASIC_INFORMATION mbi;
    K2_EXPORT_RESOLUTION exportResolution;
    ULONG i;

    if (!K2QueryAddressMemory(Frame, &mbi) ||
        (mbi.Type & MEM_IMAGE) == 0 ||
        mbi.AllocationBase == NULL) {
        return NULL;
    }

    for (i = 0; i < Spec->ExportCount; ++i) {
        if (K2TryResolveExpectedExport(mbi.AllocationBase, Spec->Exports[i], &exportResolution)) {
            return mbi.AllocationBase;
        }
    }

    return NULL;
}

static
BOOLEAN
K2AddressInRange(
    _In_ PVOID Address,
    _In_opt_ PVOID Base,
    _In_ SIZE_T Span
    )
{
    return Base != NULL &&
           Span != 0 &&
           Address >= Base &&
           Address < (PVOID)((PUCHAR)Base + Span);
}

static
BOOLEAN
K2FrameMatchesExpectedExport(
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    )
{
    ULONG i;

    for (i = 0; i < Analysis->ExpectedExportCount; ++i) {
        if (K2AddressInRange(Analysis->Frame0, Analysis->ExpectedExports[i].Base, Analysis->ExpectedExports[i].Span)) {
            return TRUE;
        }
    }

    return FALSE;
}

static
VOID
K2PopulateCallerAnalysis(
    _Inout_ PK2_SYSCALL_ANALYSIS Analysis
    )
{
    if (Analysis->Frame1 == NULL || !K2QueryAddressMemory(Analysis->Frame1, &Analysis->CallerMbi)) {
        return;
    }

    Analysis->CallerFrameExecutable = K2IsExecutableProtection(Analysis->CallerMbi.Protect);
    Analysis->CallerFramePrivate = ((Analysis->CallerMbi.Type & MEM_PRIVATE) != 0);
    Analysis->CallerFrameWritable = K2IsWritableProtection(Analysis->CallerMbi.Protect);
    Analysis->CallerFrameImage = ((Analysis->CallerMbi.Type & MEM_IMAGE) != 0);
}

static
VOID
K2BuildDetectionReasons(
    _Out_writes_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength,
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    )
{
    Buffer[0] = '\0';

    if (Analysis->UserStackUnavailable) {
        K2AppendReason(Buffer, BufferLength, "no-user-stack");
    }
    if (Analysis->NtdllLookupFailed) {
        K2AppendReason(Buffer, BufferLength, "no-ntdll");
    }
    if (Analysis->Frame0InvalidUserAddress) {
        K2AppendReason(Buffer, BufferLength, "invalid-user-frame");
    }
    if (!Analysis->Frame0InNtdll && !Analysis->Frame0InWin32u && !Analysis->NtdllLookupFailed) {
        K2AppendReason(Buffer, BufferLength, "frame0-outside-ntdll");
    }
    if (Analysis->StrictExportMatch && Analysis->Frame0InDifferentNtdllExport) {
        K2AppendReason(Buffer, BufferLength, "indirect-export");
    }
    if (Analysis->CallerFramePrivate) {
        K2AppendReason(Buffer, BufferLength, "private-caller");
    }
    if (Analysis->CallerFrameWritable) {
        K2AppendReason(Buffer, BufferLength, "wx-caller");
    }
    if (Analysis->CallerFrameExecutable && !Analysis->CallerFrameImage) {
        K2AppendReason(Buffer, BufferLength, "non-image-exec");
    }
    if (Buffer[0] == '\0') {
        K2AppendReason(Buffer, BufferLength, "policy-hit");
    }
}

static
VOID
K2LogStackFrame(
    _In_ ULONG Index,
    _In_ PVOID Address
    )
{
    K2_FRAME_RESOLUTION frame;
    MEMORY_BASIC_INFORMATION frameMbi;

    K2Log("  STACK[%lu] frame=%p\n", Index, Address);

    RtlZeroMemory(&frame, sizeof(frame));
    if (K2ResolveUserFrame(PsGetCurrentProcess(), Address, &frame) && frame.ModuleResolved) {
        K2Log("    module=%s+0x%lx\n", frame.ModuleName, frame.ModuleRva);
        if (frame.ExportResolved) {
            K2Log("    export=%s!%s+0x%lx\n", frame.ModuleName, frame.ExportName, frame.ExportOffset);
        }
        return;
    }

    RtlZeroMemory(&frameMbi, sizeof(frameMbi));
    if (!K2QueryAddressMemory(Address, &frameMbi)) {
        K2Log("    module=unmapped-or-invalid\n");
        return;
    }

    K2Log("    module=unmapped-or-non-image\n");
    K2Log(
        "    regionBase=%p type=%s(0x%lx) protect=0x%lx\n",
        frameMbi.BaseAddress,
        K2MemoryTypeToString(frameMbi.Type),
        frameMbi.Type,
        frameMbi.Protect);
    K2Log(
        "    classification=exec:%u private:%u writable:%u image:%u\n",
        K2IsExecutableProtection(frameMbi.Protect),
        ((frameMbi.Type & MEM_PRIVATE) != 0),
        K2IsWritableProtection(frameMbi.Protect),
        ((frameMbi.Type & MEM_IMAGE) != 0));
}

static
BOOLEAN
K2ShouldFlagAnalysis(
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    )
{
    if (!Analysis->StrictExportMatch) {
        if (!Analysis->Frame0InNtdll && !Analysis->Frame0InWin32u) {
            return Analysis->CallerFrameExecutable &&
                   (Analysis->CallerFramePrivate || Analysis->CallerFrameWritable || !Analysis->CallerFrameImage);
        }

        return Analysis->CallerFrameExecutable && K2IsSuspiciousCallerMemory(&Analysis->CallerMbi);
    }

    if (!Analysis->Frame0InNtdll) {
        if (Analysis->Frame0InWin32u) {
            return Analysis->CallerFrameExecutable && K2IsSuspiciousCallerMemory(&Analysis->CallerMbi);
        }

        return TRUE;
    }

    if (Analysis->Frame0InDifferentNtdllExport) {
        return TRUE;
    }

    return Analysis->CallerFrameExecutable && K2IsSuspiciousCallerMemory(&Analysis->CallerMbi);
}

static
BOOLEAN
K2ShouldLogDetection(
    _In_z_ PCSTR EventName,
    _In_z_ PCSTR Reasons,
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    )
{
    ULONG signature;
    ULONGLONG now;
    ULONG i;
    ULONG slot;

    signature = K2HashDetectionSignature(EventName, Reasons, Analysis);
    now = KeQueryInterruptTime();
    slot = signature % RTL_NUMBER_OF(g_DetectionCache);

    ExAcquireFastMutex(&g_DetectionCacheLock);
    for (i = 0; i < RTL_NUMBER_OF(g_DetectionCache); ++i) {
        ULONG index;

        index = (slot + i) % RTL_NUMBER_OF(g_DetectionCache);
        if (g_DetectionCache[index].Signature == signature) {
            if ((now - g_DetectionCache[index].LastSeenTime) < K2_DUPLICATE_WINDOW_100NS) {
                ExReleaseFastMutex(&g_DetectionCacheLock);
                return FALSE;
            }

            g_DetectionCache[index].LastSeenTime = now;
            ExReleaseFastMutex(&g_DetectionCacheLock);
            return TRUE;
        }

        if (g_DetectionCache[index].Signature == 0) {
            g_DetectionCache[index].Signature = signature;
            g_DetectionCache[index].LastSeenTime = now;
            ExReleaseFastMutex(&g_DetectionCacheLock);
            return TRUE;
        }
    }

    g_DetectionCache[slot].Signature = signature;
    g_DetectionCache[slot].LastSeenTime = now;
    ExReleaseFastMutex(&g_DetectionCacheLock);
    return TRUE;
}

static
ULONG
K2HashDetectionSignature(
    _In_z_ PCSTR EventName,
    _In_z_ PCSTR Reasons,
    _In_ const K2_SYSCALL_ANALYSIS* Analysis
    )
{
    ULONG hash;
    const UCHAR* cursor;

    hash = 2166136261u;
    for (cursor = (const UCHAR*)EventName; *cursor != '\0'; ++cursor) {
        hash ^= *cursor;
        hash *= 16777619u;
    }

    for (cursor = (const UCHAR*)Reasons; *cursor != '\0'; ++cursor) {
        hash ^= *cursor;
        hash *= 16777619u;
    }

    hash ^= HandleToULong(PsGetCurrentProcessId());
    hash *= 16777619u;
    hash ^= PtrToUlong(Analysis->Frame0);
    hash *= 16777619u;
    hash ^= PtrToUlong(Analysis->Frame1);
    hash *= 16777619u;

    return hash == 0 ? 1u : hash;
}
