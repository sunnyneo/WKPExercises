// Includes
// ------------------------------------------------------------------------

#include <ntddk.h>

// Macros
// ------------------------------------------------------------------------

// Print debug message macro for DebugView
#define DEBUG_PREFIX "[DBG]: "
#define PRINT(_x_, ...) DbgPrint(DEBUG_PREFIX _x_, ##__VA_ARGS__);

// Maximum number of processes that can be protected by driver
#define MAX_PROCESS_COUNT 10

// Access mask macro required for handle to terminate process
#define PROCESS_TERMINATE 1

// Device type macro
#define FILE_DEVICE_PROCESSPROTECT 0x8000

// IOCTL macro for protecting a process by PID - 80002000
#define IOCTL_PROCESS_PROTECT_BY_PID CTL_CODE(FILE_DEVICE_PROCESSPROTECT, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOCTL macro for unprotecting a process by PID - 80002004
#define IOCTL_PROCESS_UNPROTECT_BY_PID CTL_CODE(FILE_DEVICE_PROCESSPROTECT, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

// IOCTL macro for clearing all processes protected from UM termination from list - 8000200B
#define IOCTL_PROCESS_PROTECT_CLEAR CTL_CODE(FILE_DEVICE_PROCESSPROTECT, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)

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

	// Init some important stuff
	PEPROCESS pEprocess = NULL;
	DWORD32 pid = 0;

	// Check if kernel handle, if true then ignore
	if (pObPreOperationInformation->KernelHandle)
		return OB_PREOP_SUCCESS;

	// Get pointer to target process object
	pEprocess = (PEPROCESS)pObPreOperationInformation->Object;

	// Get PID of target process
	pid = HandleToULong(PsGetProcessId(pEprocess));

	// Acquire ownership of fast mutex, raises current CPU IRQL to 1(APC_LEVEL)
	ExAcquireFastMutex(&fastMutex);

	// Use SEH since it is important to release fast mutex no matter what happens
	__try {
		// Loop over process protect list
		for (int i = 0; i < MAX_PROCESS_COUNT; i++) {
			// Check if target PID matches any of the processes protected
			if (processProtectList[i] == pid) {
				// Remove PROCESS_TERMINATE access mask bit from caller's request
				pObPreOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
				break;
			}
		}
	}
	__finally {
		// Release ownership of fast mutex, lowers current CPU IRQL to 0(DISPATCH_LEVEL)
		ExReleaseFastMutex(&fastMutex);
	}

	return OB_PREOP_SUCCESS;
}

// IRP_MJ_DEVICE_CONTROL dispatch routine
// ------------------------------------------------------------------------

NTSTATUS driver_device_control(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDeviceObject);

	// Init some important stuff
	PIO_STACK_LOCATION pIoStackLocation = NULL;
	DWORD32 ioctl = 0;
	DWORD32 inputBufferLength = 0;
	PDWORD32 pBuffer = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD32 bytesTransferred = sizeof(DWORD32);
	DWORD32 pid = 0;

	// Get caller's I/O stack location in IRP
	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	// Get IOCTL
	ioctl = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;

	// Check if requested IOCTL operation is implemented
	switch (ioctl) {
	// Protect a process from UM termination by its PID
	case IOCTL_PROCESS_PROTECT_BY_PID:
		// Get length of input buffer
		inputBufferLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		if (inputBufferLength % sizeof(ULONG) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			bytesTransferred = 0;
			break;
		}

		// Get pointer to kernel-mode buffer for read operation using Buffered I/O
		pBuffer = (PDWORD32)pIrp->AssociatedIrp.SystemBuffer;

		// Get PID from system buffer
		pid = pBuffer[0];
		if (pid == 0) {
			status = STATUS_INVALID_PARAMETER;
			bytesTransferred = 0;
			break;
		}

		// Acquire ownership of fast mutex, raises current CPU IRQL to 1(APC_LEVEL) 
		ExAcquireFastMutex(&fastMutex);

		// Use SEH since it is important to release fast mutex no matter what happens
		__try {
			// Check if process protect list is already filled
			if (processProtectedCount == MAX_PROCESS_COUNT) {
				status = STATUS_TOO_MANY_NAMES;
				bytesTransferred = 0;
				PRINT("Process protect list is already filled error: %X\n", status);
				break;
			}

			// Loop over process protect list
			for (int i = 0; i < MAX_PROCESS_COUNT; i++) {
				// Check for empty slot in process protect list
				if (processProtectList[i] == 0) {
					// Insert PID into global process protect array
					processProtectList[i] = pid;
					PRINT("Added process to protection list: %d\n", pid);

					// Increment total processes protected count 
					processProtectedCount = processProtectedCount + 1;
					break;
				}
			}
		}
		__finally {
			// Release ownership of fast mutex, lowers current CPU IRQL to 0(DISPATCH_LEVEL)
			ExReleaseFastMutex(&fastMutex);
		}

		break;
	// Unprotect a process from UM termination by its PID
	case IOCTL_PROCESS_UNPROTECT_BY_PID:
		// Get length of input buffer
		inputBufferLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		if (inputBufferLength % sizeof(ULONG) != 0) {
			status = STATUS_INVALID_BUFFER_SIZE;
			bytesTransferred = 0;
			break;
		}

		// Get pointer to kernel-mode buffer for read operation using Buffered I/O
		pBuffer = (PDWORD32)pIrp->AssociatedIrp.SystemBuffer;

		// Get PID from system buffer
		pid = pBuffer[0];
		if (pid == 0) {
			status = STATUS_INVALID_PARAMETER;
			bytesTransferred = 0;
			break;
		}

		// Acquire ownership of fast mutex, raises current CPU IRQL to 1(APC_LEVEL) 
		ExAcquireFastMutex(&fastMutex);

		// Use SEH since it is important to release fast mutex no matter what happens
		__try {
			// Check if process protect list is empty
			if (processProtectedCount == 0) {
				status = STATUS_NOT_FOUND;
				bytesTransferred = 0;
				PRINT("Process protect list is empty error: %X\n", status);
				break;
			}

			// Loop over process protect list
			for (int i = 0; i < MAX_PROCESS_COUNT; i++) {
				// Check if process protect list contains target PID
				if (processProtectList[i] == pid) {
					// Remove PID from global process protect array
					processProtectList[i] = 0;
					PRINT("Removed process from protection list: %d\n", pid);

					// Decrement total processes protected count 
					processProtectedCount = processProtectedCount - 1;
					break;
				}
			}
		}
		__finally {
			// Release ownership of fast mutex, lowers current CPU IRQL to 0(DISPATCH_LEVEL)
			ExReleaseFastMutex(&fastMutex);
		}

		break;
	// Clear all processes protected from UM termination from global array
	case IOCTL_PROCESS_PROTECT_CLEAR:
		// Acquire ownership of fast mutex, raises current CPU IRQL to 1(APC_LEVEL) 
		ExAcquireFastMutex(&fastMutex);

		// Use SEH since it is important to release fast mutex no matter what happens
		__try {
			// Empty process protect global array
			RtlSecureZeroMemory(processProtectList, sizeof(processProtectList));
			PRINT("Cleared process protect list\n");

			// Set processes protected count to 0
			processProtectedCount = 0;
		}
		__finally {
			// Release ownership of fast mutex, lowers current CPU IRQL to 0(DISPATCH_LEVEL)
			ExReleaseFastMutex(&fastMutex);
		}

		bytesTransferred = 0;
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		bytesTransferred = 0;
		break;
	}

	// Set IRP status and information
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = bytesTransferred;

	// Complete IRP
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
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

	// Set dispatch routine to be called to handle IOCTL operations
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver_device_control;

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