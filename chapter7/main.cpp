// Includes
// ------------------------------------------------------------------------

#include "pch.h"

// Macros
// ------------------------------------------------------------------------

// Print debug message macro for DebugView
#define DEBUG_PREFIX "[DBG]: "
#define PRINT(_x_, ...) DbgPrint(DEBUG_PREFIX _x_, ##__VA_ARGS__);

// Device type macro
#define FILE_DEVICE_ZERO 0x8000

// IOCTL macro for obtaining total number of bytes read and written from/to device - 80002000
#define IOCTL_ZERO_GET_STATS CTL_CODE(FILE_DEVICE_ZERO, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Structs/Enums
// ------------------------------------------------------------------------

// Output buffer
typedef struct _ZERO_DATA {
	DWORD64 TotalRead;
	DWORD64 TotalWritten;
} ZERO_DATA, * PZERO_DATA;

// Globals
// ------------------------------------------------------------------------

// Device object name and symbolic link object name
UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Zero");
UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\Zero");

// Total number of bytes read from device since driver load
LONG64 totalBytesRead = 0;

// Total number of bytes written to device since driver load
LONG64 totalBytesWritten = 0;

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

// IRP_MJ_READ dispatch routine
// ------------------------------------------------------------------------

NTSTATUS driver_read(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDeviceObject);

	// Init some important stuff
	PIO_STACK_LOCATION pIoStackLocation = NULL;
	DWORD32 bufferLength = 0;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD32 bytesTransferred = 0;
	PVOID pBuffer = NULL;

	// Get caller's I/O stack location in IRP
	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	// Get length of read buffer
	bufferLength = pIoStackLocation->Parameters.Read.Length;
	if (bufferLength == 0) {
		status = STATUS_INVALID_BUFFER_SIZE;
		PRINT("Read buffer length error: %X\n", status);
		goto cleanup;
	}
	bytesTransferred = bufferLength;

	// Map locked user-mode buffer to system space and return its kernel-mode VA
	pBuffer = MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	if (pBuffer == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		bytesTransferred = 0;
		PRINT("MmGetSystemAddressForMdlSafe error: %X\n", status);
		goto cleanup;
	}

	// Secure zero out read buffer
	RtlSecureZeroMemory(pBuffer, bufferLength);

	// Atomically add number of bytes read to global variable
	InterlockedAdd64(&totalBytesRead, bytesTransferred);

	// Cleanup
cleanup:
	// Set IRP status and information
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = bytesTransferred;

	// Complete IRP
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return status;
}

// IRP_MJ_WRITE dispatch routine
// ------------------------------------------------------------------------

NTSTATUS driver_write(PDEVICE_OBJECT pDeviceObject, PIRP pIrp) {
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDeviceObject);

	// Init some important stuff
	PIO_STACK_LOCATION pIoStackLocation = NULL;
	DWORD32 bufferLength = 0;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD32 bytesTransferred = 0;

	// Get caller's I/O stack location in IRP
	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	// Get length of write buffer
	bufferLength = pIoStackLocation->Parameters.Write.Length;
	bytesTransferred = bufferLength;

	// Atomically add number of bytes written to global variable
	InterlockedAdd64(&totalBytesWritten, bytesTransferred);

	// Set IRP status and information
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = bytesTransferred;

	// Complete IRP
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

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
	DWORD32 outputBufferLength = 0;
	PZERO_DATA pZeroData = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD32 bytesTransferred = sizeof(ZERO_DATA);

	// Get caller's I/O stack location in IRP
	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	// Get IOCTL
	ioctl = pIoStackLocation->Parameters.DeviceIoControl.IoControlCode;

	// Check if requested IOCTL operation is implemented
	switch (ioctl) {
	// Get total number of bytes read/written
	case IOCTL_ZERO_GET_STATS:
		// Get length of output buffer
		outputBufferLength = pIoStackLocation->Parameters.DeviceIoControl.OutputBufferLength;
		if (outputBufferLength < sizeof(ZERO_DATA)) {
			status = STATUS_BUFFER_TOO_SMALL;
			bytesTransferred = 0;
			break;
		}

		// Get pointer to kernel-mode buffer for write operation using Buffered I/O
		pZeroData = (PZERO_DATA)pIrp->AssociatedIrp.SystemBuffer;

		// Populate system buffer
		pZeroData->TotalRead = totalBytesRead;
		pZeroData->TotalWritten = totalBytesWritten;
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

	// Set dispatch routine to be called to read from device object
	pDriverObject->MajorFunction[IRP_MJ_READ] = driver_read;

	// Set dispatch routine to be called to write to device object
	pDriverObject->MajorFunction[IRP_MJ_WRITE] = driver_write;

	// Set dispatch routine to be called to handle IOCTL operations
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = driver_device_control;

	// Create device object
	status = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (status != STATUS_SUCCESS) {
		PRINT("IoCreateDevice error: %X\n", status);
		return status;
	}
	PRINT("Device object created!\n");

	// Set up Direct I/O
	pDeviceObject->Flags |= DO_DIRECT_IO;

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