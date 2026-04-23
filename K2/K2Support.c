#include "K2.h"
#include <stdarg.h>

VOID
K2Log(
    _In_z_ _Printf_format_string_ PCSTR Format,
    ...
    )
{
    va_list args;

    va_start(args, Format);
    vDbgPrintExWithPrefix("[K2] ", DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, Format, args);
    va_end(args);
}

BOOLEAN
K2IsLikelyUserAddress(
    _In_ PVOID Address
    )
{
    ULONG_PTR value;

    value = (ULONG_PTR)Address;
#if defined(_WIN64)
    return value != 0 && value <= 0x00007FFFFFFFFFFFULL;
#else
    return value >= 0x10000UL && value <= 0x7FFFFFFFUL;
#endif
}

BOOLEAN
K2IsRangeWithinImage(
    _In_ SIZE_T ImageSize,
    _In_ ULONG Rva,
    _In_ SIZE_T Length
    )
{
    return Rva < ImageSize && Length <= (ImageSize - Rva);
}

BOOLEAN
K2IsExecutableProtection(
    _In_ ULONG Protect
    )
{
    Protect &= 0xff;

    return Protect == PAGE_EXECUTE ||
           Protect == PAGE_EXECUTE_READ ||
           Protect == PAGE_EXECUTE_READWRITE ||
           Protect == PAGE_EXECUTE_WRITECOPY;
}

BOOLEAN
K2IsWritableProtection(
    _In_ ULONG Protect
    )
{
    Protect &= 0xff;

    return Protect == PAGE_EXECUTE_READWRITE ||
           Protect == PAGE_EXECUTE_WRITECOPY;
}

BOOLEAN
K2IsSuspiciousCallerMemory(
    _In_ const MEMORY_BASIC_INFORMATION* Mbi
    )
{
    if (!K2IsExecutableProtection(Mbi->Protect)) {
        return FALSE;
    }

    return ((Mbi->Type & MEM_PRIVATE) != 0) ||
           K2IsWritableProtection(Mbi->Protect) ||
           ((Mbi->Protect & 0xff) == PAGE_EXECUTE);
}

PCSTR
K2MemoryTypeToString(
    _In_ ULONG Type
    )
{
    if ((Type & MEM_IMAGE) != 0) {
        return "image";
    }
    if ((Type & MEM_PRIVATE) != 0) {
        return "private";
    }
    if ((Type & MEM_MAPPED) != 0) {
        return "mapped";
    }

    return "unknown";
}

VOID
K2CopyProcessName(
    _Out_writes_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength
    )
{
    PEPROCESS process;
    PK2_PEB peb;
    PK2_RTL_USER_PROCESS_PARAMETERS processParameters;
    KAPC_STATE apcState;
    BOOLEAN copied;

    copied = FALSE;
    process = PsGetCurrentProcess();
    if (BufferLength == 0) {
        return;
    }

    Buffer[0] = '\0';
    if (process == NULL || PsGetProcessWow64Process(process) != NULL) {
        K2CopyAnsiString(Buffer, BufferLength, process != NULL ? (PCSTR)PsGetProcessImageFileName(process) : NULL);
        return;
    }

    peb = (PK2_PEB)PsGetProcessPeb(process);
    if (peb == NULL) {
        K2CopyAnsiString(Buffer, BufferLength, (PCSTR)PsGetProcessImageFileName(process));
        return;
    }

    KeStackAttachProcess(process, &apcState);
    __try {
        ProbeForRead(peb, sizeof(*peb), sizeof(UCHAR));
        processParameters = (PK2_RTL_USER_PROCESS_PARAMETERS)peb->ProcessParameters;
        if (processParameters == NULL) {
            __leave;
        }

        ProbeForRead(processParameters, sizeof(*processParameters), sizeof(UCHAR));
        if (processParameters->ImagePathName.Buffer == NULL || processParameters->ImagePathName.Length == 0) {
            __leave;
        }

        ProbeForRead(processParameters->ImagePathName.Buffer, processParameters->ImagePathName.Length, sizeof(WCHAR));
        K2CopyUnicodeBaseNameToAnsi(Buffer, BufferLength, &processParameters->ImagePathName);
        copied = (Buffer[0] != '\0');
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        copied = FALSE;
    }
    KeUnstackDetachProcess(&apcState);

    if (!copied) {
        K2CopyAnsiString(Buffer, BufferLength, (PCSTR)PsGetProcessImageFileName(process));
    }
}

VOID
K2CopyAnsiString(
    _Out_writes_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength,
    _In_opt_z_ PCSTR Source
    )
{
    if (BufferLength == 0) {
        return;
    }

    Buffer[0] = '\0';
    if (Source != NULL) {
        (VOID)RtlStringCbPrintfA(Buffer, BufferLength, "%s", Source);
    }
}

VOID
K2CopyUnicodeBaseNameToAnsi(
    _Out_writes_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength,
    _In_ PCUNICODE_STRING Source
    )
{
    USHORT i;
    USHORT start;
    SIZE_T outIndex;

    if (BufferLength == 0) {
        return;
    }

    Buffer[0] = '\0';
    if (Source == NULL || Source->Buffer == NULL || Source->Length == 0) {
        return;
    }

    start = 0;
    for (i = 0; i < (USHORT)(Source->Length / sizeof(WCHAR)); ++i) {
        WCHAR ch;

        ch = Source->Buffer[i];
        if (ch == L'\\' || ch == L'/') {
            start = (USHORT)(i + 1);
        }
    }

    outIndex = 0;
    for (i = start; i < (USHORT)(Source->Length / sizeof(WCHAR)) && outIndex + 1 < BufferLength; ++i) {
        WCHAR ch;

        ch = Source->Buffer[i];
        Buffer[outIndex++] = (ch <= 0x7f) ? (CHAR)ch : '?';
    }

    Buffer[outIndex] = '\0';
}

VOID
K2AppendReason(
    _Inout_updates_(BufferLength) PCHAR Buffer,
    _In_ SIZE_T BufferLength,
    _In_z_ PCSTR Reason
    )
{
    size_t currentLength;
    NTSTATUS status;

    currentLength = 0;
    status = RtlStringCbLengthA(Buffer, BufferLength, &currentLength);
    if (!NT_SUCCESS(status)) {
        Buffer[0] = '\0';
        currentLength = 0;
    }

    if (Buffer[0] == '\0') {
        status = RtlStringCbPrintfA(Buffer, BufferLength, "%s", Reason);
    } else {
        status = RtlStringCbPrintfA(Buffer + currentLength, BufferLength - currentLength, ",%s", Reason);
    }

    UNREFERENCED_PARAMETER(status);
}

BOOLEAN
K2EndsWithUnicodeInsensitive(
    _In_ PCUNICODE_STRING Value,
    _In_ PCUNICODE_STRING Suffix
    )
{
    USHORT start;
    USHORT i;

    if (Value->Length < Suffix->Length) {
        return FALSE;
    }

    start = (USHORT)((Value->Length - Suffix->Length) / sizeof(WCHAR));
    for (i = 0; i < (USHORT)(Suffix->Length / sizeof(WCHAR)); ++i) {
        WCHAR left;
        WCHAR right;

        left = RtlUpcaseUnicodeChar(Value->Buffer[start + i]);
        right = RtlUpcaseUnicodeChar(Suffix->Buffer[i]);
        if (left != right) {
            return FALSE;
        }
    }

    return TRUE;
}

BOOLEAN
K2StringsEqualInsensitiveA(
    _In_z_ PCSTR Left,
    _In_z_ PCSTR Right
    )
{
    SIZE_T index;

    for (index = 0;; ++index) {
        CHAR left;
        CHAR right;

        left = Left[index];
        right = Right[index];
        if (left >= 'a' && left <= 'z') {
            left = (CHAR)(left - ('a' - 'A'));
        }
        if (right >= 'a' && right <= 'z') {
            right = (CHAR)(right - ('a' - 'A'));
        }
        if (left != right) {
            return FALSE;
        }
        if (left == '\0') {
            return TRUE;
        }
    }
}
