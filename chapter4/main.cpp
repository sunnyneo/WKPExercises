// Includes
// ------------------------------------------------------------------------

#include <ntifs.h>
#include <ntddk.h>

// Macros
// ------------------------------------------------------------------------

// Print debug message macro for DebugView
#define DEBUG_PREFIX "[DBG]: "
#define PRINT(_x_, ...) DbgPrint(DEBUG_PREFIX _x_, ##__VA_ARGS__);

// Device type macro
#define FILE_DEVICE_PRIORITYBOOSTER 0x8000

// IOCTL macro for changing priority of target thread - 80002003
#define IOCTL_SET_THREAD_PRIORITY CTL_CODE(FILE_DEVICE_PRIORITYBOOSTER, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)

// Structs/Enums
// ------------------------------------------------------------------------

// Input buffer
typedef struct _THREAD_DATA {
	USHORT ThreadId;
	USHORT Priority;
} THREAD_DATA, *PTHREAD_DATA;

// Globals
// ------------------------------------------------------------------------

// Device object name and symbolic link object name
UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\PriorityBooster");
UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\PriorityBooster");

// Driver unload routine
// ------------------------------------------------------------------------

void driver_unload(PDRIVER_OBJECT pDriverObject) {
	// [DBG]
	PRINT("Driver unloaded!\n");

	// Delete symbolic link object first to prevent dangling indirection
	IoDeleteSymbolicLink(&symbolicLink);

	// Delete device object
	IoDeleteDevice(pDriverObject->DeviceObject);
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

// Change target thread's priority
// ------------------------------------------------------------------------

NTSTATUS set_thread_priority(PTHREAD_DATA pThreadData) {
	// Init some important stuff
	USHORT threadId = 0;
	USHORT newThreadPriority = 0;
	NTSTATUS status;
	PETHREAD pEthread = NULL;
	USHORT oldThreadPriority = 0;

	// Get TID and requested thread priority
	threadId = pThreadData->ThreadId;
	newThreadPriority = pThreadData->Priority;

	// Check if requested priority value is valid
	if (newThreadPriority < 1 || newThreadPriority > 31) {
		PRINT("Invalid thread priority requested!\n");
		status = STATUS_INVALID_PARAMETER;
		return status;
	}
	PRINT("Valid thread priority value received!\n")

	// Get thread object of target thread
	status = PsLookupThreadByThreadId((HANDLE)threadId, &pEthread);
	if (status != STATUS_SUCCESS) {
		PRINT("PsLookupThreadByThreadId error: %X\n", status);
		return status;
	}
	PRINT("Got nt!_PETHREAD structure of target thread!\n");

	// Change run-time priority of target thread
	oldThreadPriority = (USHORT)KeSetPriorityThread(pEthread, newThreadPriority);

	// Decrement reference count of target thread object
	ObDereferenceObject(pEthread);

	PRINT("Successfully changed priority of target thread: %d from %d to %d!\n", threadId, oldThreadPriority, newThreadPriority);

	return status;
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
	PTHREAD_DATA pThreadData = NULL;
	NTSTATUS status;

	// Get caller's I/O stack location in IRP
	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	// Get IOCTL
	ioctl = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;

	// Check if requested IOCTL operation is implemented
	switch (ioctl) {
	// Change target thread's priority
	case IOCTL_SET_THREAD_PRIORITY:
		// Get length of input buffer
		inputBufferLength = pIoStackLocation->Parameters.DeviceIoControl.InputBufferLength;
		if (inputBufferLength < sizeof(THREAD_DATA)) {
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		// Get input buffer
		pThreadData = (PTHREAD_DATA)pIoStackLocation->Parameters.DeviceIoControl.Type3InputBuffer;
		if (pThreadData == NULL) {
			status = STATUS_INVALID_PARAMETER;
			break;
		}

		// Pass along input buffer to change target thread's priority
		status = set_thread_priority(pThreadData);
		break;
	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}

	// Set IRP status and information
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;

	// Complete IRP
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

// Driver entry point
// ------------------------------------------------------------------------

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING registryPath) {
	// [DBG]
	PRINT("Driver loaded!\n");

	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(registryPath);

	// Init some important stuff
	NTSTATUS status;
	PDEVICE_OBJECT pDeviceObject = NULL;

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
		return status;
	}
	PRINT("Device object created!\n");

	// Create symbolic link object pointing to device object for UM access
	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
	if (status != STATUS_SUCCESS) {
		PRINT("IoCreateSymbolicLink error: %X\n", status);
		IoDeleteDevice(pDeviceObject);
		return status;
	}
	PRINT("Symbolic link created!\n");

	return STATUS_SUCCESS;
}