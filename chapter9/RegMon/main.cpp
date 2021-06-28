// Includes
// ------------------------------------------------------------------------

#include <ntddk.h>

// Macros
// ------------------------------------------------------------------------

// Print debug message macro for DebugView
#define DEBUG_PREFIX "[DBG]: "
#define PRINT(_x_, ...) DbgPrint(DEBUG_PREFIX _x_, ##__VA_ARGS__);

// Globals
// ------------------------------------------------------------------------

// Random fractional altitude to prevent collision
UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"123456.762389");

// Configuration Manager(Cm) registry callback registration cookie
LARGE_INTEGER cmCallbackRegCookie;

// Filter for Cm callback routine - internal registry path, UM equivalent of HKEY_LOCAL_MACHINE
WCHAR regFilterName[] = L"\\REGISTRY\\MACHINE\\";

// EX_CALLBACK_FUNCTION callback routine that gets called by kernel for registry operations
// Called both before and after registry operation is completed by Configuration Manager
// Runs at IRQL=0(PASSIVE_LEVEL)
// ------------------------------------------------------------------------

NTSTATUS registry_notification_callback(PVOID callbackContext, PVOID pArgument1, PVOID pArgument2) {
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(callbackContext);

	// Init some important stuff
	REG_NOTIFY_CLASS regNotifyClass;
	PREG_SET_VALUE_KEY_INFORMATION pRegSetValueKeyInformation = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	PCUNICODE_STRING regKeyName = NULL;
	PUNICODE_STRING regValueName = NULL;
	DWORD32 regDataType = 0;
	DWORD32 regDataSize = 0;
	UCHAR regData[1024 + 1] = { 0 };
	DWORD32 pid = 0;
	DWORD32 tid = 0;

	// Get REG_NOTIFY_CLASS enumeration from Argument1 to determine type of operation
	regNotifyClass = (REG_NOTIFY_CLASS)PtrToUlong(pArgument1);

	// Check if operation type is pre-notification call of thread attempting to set value entry for key
	switch (regNotifyClass) {
	// Handle RegNtPreSetValueKey operation
	case RegNtPreSetValueKey:
		// Get pointer to REG_SET_VALUE_KEY_INFORMATION structure from associated Argument2
		pRegSetValueKeyInformation = (PREG_SET_VALUE_KEY_INFORMATION)pArgument2;

		// Get full key name from registry key object
		status = CmCallbackGetKeyObjectIDEx(&cmCallbackRegCookie, pRegSetValueKeyInformation->Object, NULL, &regKeyName, 0);
		if (status != STATUS_SUCCESS) {
			PRINT("CmCallbackGetKeyObjectIDEx error: %X\n", status);
			break;
		}

		// Check if HKEY_LOCAL_MACHINE registry write, else drop it
		if (wcsncmp(regKeyName->Buffer, regFilterName, ARRAYSIZE(regFilterName) - 1) == 0) {
			// Get registry value name
			regValueName = pRegSetValueKeyInformation->ValueName;

			// Get caller's PID - callback called in context of thread requesting registry operation
			pid = HandleToULong(PsGetCurrentProcessId());

			// Get caller's TID
			tid = HandleToULong(PsGetCurrentThreadId());

			// Get type of registry data
			regDataType = pRegSetValueKeyInformation->Type;

			// Get size of registry data
			regDataSize = pRegSetValueKeyInformation->DataSize;

			// Get registry data
			RtlCopyMemory(regData, pRegSetValueKeyInformation->Data, min(regDataSize, 1024 * sizeof(UCHAR)));

			// [DBG]
			PRINT("Key name: %wZ\n", regKeyName);
			PRINT("Value name: %wZ\n", regValueName);
			PRINT("Caller PID: %d\n", pid);
			PRINT("Caller TID: %d\n", tid);
			switch (regDataType) {
			case REG_DWORD:
				PRINT("REG_DWORD: 0x%08X\n", *(PDWORD32)regData);
				break;
			case REG_QWORD:
				PRINT("REG_QWORD: 0x%016llX\n", *(PDWORD64)regData);
				break;
			case REG_SZ:
			case REG_EXPAND_SZ:
				PRINT("REG_SZ/REG_EXPAND_SZ: %ws\n", (PWCHAR)regData);
				break;
			default:
				PRINT("REG_BINARY/etc.: \n");
				break;
			}
		}

		break;
	default:
		break;
	}

	// Free allocation for object name nt!_UNICODE_STRING buffer
	if (regKeyName)
		CmCallbackReleaseKeyObjectIDEx(regKeyName);

	return STATUS_SUCCESS;
}

// Driver unload routine
// ------------------------------------------------------------------------

void driver_unload(PDRIVER_OBJECT pDriverObject) {
	// [DBG]
	PRINT("Driver unloaded!\n");

	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDriverObject);

	// Deregister configuration manager callback routine
	CmUnRegisterCallback(cmCallbackRegCookie);
}

// Driver entry point
// ------------------------------------------------------------------------

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING registryPath) {
	// [DBG]
	PRINT("Driver loaded!\n");

	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(registryPath);

	// Init some important stuff
	NTSTATUS status = STATUS_SUCCESS;

	// Set routine to be called on driver unload
	pDriverObject->DriverUnload = driver_unload;

	// Register callback routine for registry operation notifications
	status = CmRegisterCallbackEx(registry_notification_callback, &altitude, pDriverObject, NULL, &cmCallbackRegCookie, NULL);
	if (status != STATUS_SUCCESS) {
		PRINT("CmRegisterCallbackEx error: %X\n", status);
		return status;
	}
	PRINT("Configuration Manager callback routine registered!\n");

	return STATUS_SUCCESS;
}