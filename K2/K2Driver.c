#include "K2.h"

static PVOID g_ObRegistrationHandle = NULL;
static UNICODE_STRING g_Altitude = RTL_CONSTANT_STRING(L"321000");
static OB_OPERATION_REGISTRATION g_OperationRegistrations[2] = { 0 };

static
VOID
K2Unload(
    _In_ PDRIVER_OBJECT DriverObject
    );

static
NTSTATUS
K2RegisterCallbacks(
    VOID
    );

static
VOID
K2UnregisterCallbacks(
    VOID
    );

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->DriverUnload = K2Unload;
    K2InitializeModuleCache();
    K2InitializeAnalysisCache();

    status = K2RegisterCallbacks();
    if (!NT_SUCCESS(status)) {
        K2Log("callback registration failed: 0x%08X\n", status);
        return status;
    }

    K2Log("loaded\n");
    return STATUS_SUCCESS;
}

static
VOID
K2Unload(
    _In_ PDRIVER_OBJECT DriverObject
    )
{
    UNREFERENCED_PARAMETER(DriverObject);

    K2UnregisterCallbacks();
    K2Log("unloaded\n");
}

static
NTSTATUS
K2RegisterCallbacks(
    VOID
    )
{
    NTSTATUS status;
    OB_CALLBACK_REGISTRATION registration;

    status = PsSetCreateProcessNotifyRoutineEx(K2ProcessNotifyEx, FALSE);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = PsSetCreateThreadNotifyRoutine(K2ThreadNotify);
    if (!NT_SUCCESS(status)) {
        PsSetCreateProcessNotifyRoutineEx(K2ProcessNotifyEx, TRUE);
        return status;
    }

    RtlZeroMemory(g_OperationRegistrations, sizeof(g_OperationRegistrations));
    g_OperationRegistrations[0].ObjectType = PsProcessType;
    g_OperationRegistrations[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistrations[0].PreOperation = K2PreOperationCallback;
    g_OperationRegistrations[1].ObjectType = PsThreadType;
    g_OperationRegistrations[1].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    g_OperationRegistrations[1].PreOperation = K2PreOperationCallback;

    RtlZeroMemory(&registration, sizeof(registration));
    registration.Version = ObGetFilterVersion();
    registration.OperationRegistrationCount = RTL_NUMBER_OF(g_OperationRegistrations);
    registration.Altitude = g_Altitude;
    registration.OperationRegistration = g_OperationRegistrations;

    status = ObRegisterCallbacks(&registration, &g_ObRegistrationHandle);
    if (!NT_SUCCESS(status)) {
        PsRemoveCreateThreadNotifyRoutine(K2ThreadNotify);
        PsSetCreateProcessNotifyRoutineEx(K2ProcessNotifyEx, TRUE);
        g_ObRegistrationHandle = NULL;
        return status;
    }

    return STATUS_SUCCESS;
}

static
VOID
K2UnregisterCallbacks(
    VOID
    )
{
    if (g_ObRegistrationHandle != NULL) {
        ObUnRegisterCallbacks(g_ObRegistrationHandle);
        g_ObRegistrationHandle = NULL;
    }

    PsRemoveCreateThreadNotifyRoutine(K2ThreadNotify);
    PsSetCreateProcessNotifyRoutineEx(K2ProcessNotifyEx, TRUE);
}
