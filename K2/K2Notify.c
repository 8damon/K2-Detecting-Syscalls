#include "K2.h"

static const K2_EVENT_SPEC g_ProcessCreateSpec = {
    "process-create",
    FALSE,
    1,
    { "NtCreateUserProcess" }
};

static const K2_EVENT_SPEC g_ThreadCreateSpec = {
    "thread-create",
    FALSE,
    2,
    { "NtCreateThreadEx", "NtCreateThread" }
};

static const K2_EVENT_SPEC g_ProcessOpenSpec = {
    "process-open",
    TRUE,
    3,
    { "NtOpenProcess", "NtCreateUserProcess", "ZwAlpcOpenSenderProcess" }
};

static const K2_EVENT_SPEC g_ThreadOpenSpec = {
    "thread-open",
    TRUE,
    4,
    { "NtOpenThread", "NtCreateUserProcess", "NtCreateThreadEx", "ZwAlpcOpenSenderThread" }
};

static const K2_EVENT_SPEC g_ProcessDuplicateSpec = {
    "process-dup",
    FALSE,
    1,
    { "NtDuplicateObject" }
};

static const K2_EVENT_SPEC g_ThreadDuplicateSpec = {
    "thread-dup",
    FALSE,
    1,
    { "NtDuplicateObject" }
};

VOID
K2ProcessNotifyEx(
    _Inout_ PEPROCESS Process,
    _In_ HANDLE ProcessId,
    _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
    )
{
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo == NULL) {
        K2InvalidateProcessModuleCache(ProcessId);
        return;
    }

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return;
    }

    K2InspectCurrentThread(&g_ProcessCreateSpec);
}

VOID
K2ThreadNotify(
    _In_ HANDLE ProcessId,
    _In_ HANDLE ThreadId,
    _In_ BOOLEAN Create
    )
{
    UNREFERENCED_PARAMETER(ProcessId);
    UNREFERENCED_PARAMETER(ThreadId);

    if (!Create || KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return;
    }

    K2InspectCurrentThread(&g_ThreadCreateSpec);
}

OB_PREOP_CALLBACK_STATUS
K2PreOperationCallback(
    _In_ PVOID RegistrationContext,
    _Inout_ POB_PRE_OPERATION_INFORMATION OperationInformation
    )
{
    BOOLEAN isProcess;

    UNREFERENCED_PARAMETER(RegistrationContext);

    if (OperationInformation->KernelHandle || OperationInformation->Object == NULL) {
        return OB_PREOP_SUCCESS;
    }

    if (OperationInformation->ObjectType != *PsProcessType &&
        OperationInformation->ObjectType != *PsThreadType) {
        return OB_PREOP_SUCCESS;
    }

    if (KeGetCurrentIrql() > PASSIVE_LEVEL) {
        return OB_PREOP_SUCCESS;
    }

    isProcess = (OperationInformation->ObjectType == *PsProcessType);
    if (OperationInformation->Operation == OB_OPERATION_HANDLE_CREATE) {
        K2InspectCurrentThread(isProcess ? &g_ProcessOpenSpec : &g_ThreadOpenSpec);
    } else if (OperationInformation->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        K2InspectCurrentThread(isProcess ? &g_ProcessDuplicateSpec : &g_ThreadDuplicateSpec);
    }

    return OB_PREOP_SUCCESS;
}
