// Includes
// ------------------------------------------------------------------------

#include <ntddk.h>

// Macros
// ------------------------------------------------------------------------

// Print debug message macro for DebugView
#define DEBUG_PREFIX "[DBG]: "
#define PRINT(_x_, ...) DbgPrint(DEBUG_PREFIX _x_, ##__VA_ARGS__);

// Maximum number of processes that can be protected by driver
#define MAX_PROCESS_COUNT 256

// Globals
// ------------------------------------------------------------------------

// Device object name and symbolic link object name
UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\ProcessProtect");
UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\ProcessProtect");

// Random fractional altitude to prevent collision
UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"123456.762389");

// DWORD global array to store PID of processes protected by driver 
DWORD32 processProtectList[MAX_PROCESS_COUNT];

// Total number of processes protected by driver
USHORT processProtectedCount;

// Object Manager(Ob) object callbacks registration handle
PVOID obCallbackRegHandle;

// Allocate fast mutex to protect shared resources from concurrent access by multiple threads
FAST_MUTEX fastMutex;

// OB_PRE_OPERATION_CALLBACK callback routine that gets called by kernel for process handle operations
// Called before Create/Open/Duplicate process handle operation is completed
// Runs at IRQL=0(PASSIVE_LEVEL)
// ------------------------------------------------------------------------

OB_PREOP_CALLBACK_STATUS process_ob_pre_op_callback(PVOID registrationContext, POB_PRE_OPERATION_INFORMATION pObPreOperationInformation) {
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(registrationContext);
	UNREFERENCED_PARAMETER(pObPreOperationInformation);

	return OB_PREOP_SUCCESS;
}

// IRP_MJ_CREATE/IRP_MJ_CLOSE dispatch routine
// ------------------------------------------------------------------------

NTSTATUS driver_create_close(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDeviceObject);

	// Set IRP status and information
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	// Complete IRP
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// Driver unload routine
// ------------------------------------------------------------------------

void driver_unload(PDRIVER_OBJECT pDriverObject) {
	// [DBG]
	PRINT("Driver unloaded!\n");

	// Deregister object manager callback routine(s)
	ObUnRegisterCallbacks(obCallbackRegHandle);

	// Delete symbolic link object first to prevent dangling indirection
	IoDeleteSymbolicLink(&symbolicLink);

	// Delete device object
	IoDeleteDevice(pDriverObject->DeviceObject);
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
	PDEVICE_OBJECT pDeviceObject = NULL;
	BOOLEAN symbolicLinkCreated = FALSE;
	OB_OPERATION_REGISTRATION obOperationRegistrationArray[1] = { 0 };
	OB_CALLBACK_REGISTRATION obCallbackRegistration = { 0 };

	// Set routine to be called on driver unload
	pDriverObject->DriverUnload = driver_unload;

	// Set dispatch routine to be called to obtain handle/close handle to device object
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = driver_create_close;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = driver_create_close;

	// Create device object
	status = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (status != STATUS_SUCCESS) {
		PRINT("IoCreateDevice error: %X\n", status);
		goto cleanup;
	}
	PRINT("Device object created!\n");

	// Create symbolic link object pointing to device object for UM access
	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
	if (status != STATUS_SUCCESS) {
		PRINT("IoCreateSymbolicLink error: %X\n", status);
		goto cleanup;
	}
	symbolicLinkCreated = TRUE;
	PRINT("Symbolic link created!\n");

	// Initialize fast mutex
	ExInitializeFastMutex(&fastMutex);

	// Populate first OB_OPERATION_REGISTRATION structure
	obOperationRegistrationArray[0].ObjectType = PsProcessType; // process handle operations
	obOperationRegistrationArray[0].Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE; // Create/Open and Duplicate operations
	obOperationRegistrationArray[0].PreOperation = process_ob_pre_op_callback; // set pre-operation callback routine
	obOperationRegistrationArray[0].PostOperation = NULL; // no post-operation callback routine

	// Populate OB_CALLBACK_REGISTRATION structure
	obCallbackRegistration.Version = OB_FLT_REGISTRATION_VERSION; // constant
	obCallbackRegistration.OperationRegistrationCount = sizeof(obOperationRegistrationArray) / sizeof(OB_OPERATION_REGISTRATION); // operation count
	obCallbackRegistration.Altitude = altitude; // set driver altitude
	obCallbackRegistration.RegistrationContext = NULL; // no registration context
	obCallbackRegistration.OperationRegistration = obOperationRegistrationArray; // set OB_OPERATION_REGISTRATION array

	// Register callback routine for process handle operation notifications
	status = ObRegisterCallbacks(&obCallbackRegistration, &obCallbackRegHandle);
	if (status != STATUS_SUCCESS) {
		PRINT("ObRegisterCallbacks error: %X\n", status);
		goto cleanup;
	}
	PRINT("Object Manager callback routine(s) registered!\n");

	return STATUS_SUCCESS;

	// Cleanup
cleanup:
	if (obCallbackRegHandle)
		ObUnRegisterCallbacks(obCallbackRegHandle);

	if (symbolicLinkCreated)
		IoDeleteSymbolicLink(&symbolicLink);

	if (pDeviceObject)
		IoDeleteDevice(pDeviceObject);

	return status;
}