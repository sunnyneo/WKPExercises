// Includes
// ------------------------------------------------------------------------

#include <ntddk.h>

// Macros
// ------------------------------------------------------------------------

// Print debug message macro for DebugView
#define DEBUG_PREFIX "[DBG]: "
#define PRINT(_x_, ...) DbgPrint(DEBUG_PREFIX _x_, ##__VA_ARGS__);

// Pool tag macro in reverse order due to Little Endianness
#define POOL_TAG 'SYS'

// Structs/Enums
// ------------------------------------------------------------------------

// Supported notification event types
typedef enum _NOTIFICATION_EVENT_TYPE {
	None,
	ProcessCreate,
	ProcessExit
} NOTIFICATION_EVENT_TYPE;

// Hold information common to all event types
typedef struct _EVENT_DATA_HEADER {
	NOTIFICATION_EVENT_TYPE Type;
	USHORT Size;
	LARGE_INTEGER Time;
} EVENT_DATA_HEADER, * PEVENT_DATA_HEADER;

// Hold process creation event data
typedef struct _PROCESS_CREATE_DATA {
	EVENT_DATA_HEADER Header;
	DWORD32 ProcessId;
	DWORD32 ParentProcessId;
	USHORT CommandLineLength;
	USHORT CommandLineOffset;
} PROCESS_CREATE_DATA, * PPROCESS_CREATE_DATA;

// Hold process termination event data
typedef struct _PROCESS_EXIT_DATA {
	EVENT_DATA_HEADER Header;
	DWORD32 ProcessId;
} PROCESS_EXIT_DATA, * PPROCESS_EXIT_DATA;

// Represent notification event
// Templated struct to keep events generic
template<typename T>
struct FULL_EVENT {
	LIST_ENTRY Entry;
	T Data;
};

// Globals
// ------------------------------------------------------------------------

// Device object name and symbolic link object name
UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\SysMon");
UNICODE_STRING symbolicLink = RTL_CONSTANT_STRING(L"\\DosDevices\\SysMon");

// ListHead of circular doubly linked list that stores notification events
LIST_ENTRY eventHead;

// Total number of events
USHORT eventCount;

// Allocate fast mutex to protect list from concurrent access by multiple threads
FAST_MUTEX fastMutex;

// Add notification event to end of circular doubly linked list storing events in FIFO manner
// ------------------------------------------------------------------------

void push_event(PLIST_ENTRY pListEntry) {
	// Init some important stuff
	PLIST_ENTRY pRemovedEventEntry = NULL;
	FULL_EVENT<EVENT_DATA_HEADER>* pFullEventHeader = NULL;

	// Acquire ownership of fast mutex, raises current CPU IRQL to 1(APC_LEVEL)
	ExAcquireFastMutex(&fastMutex);

	// Use SEH since it is important to release fast mutex no matter what happens
	__try {
		// Limit events in list since no guarantee they are being consumed properly
		if (eventCount > 1024) {
			// Too many events, remove beginning entry/oldest event from list
			pRemovedEventEntry = RemoveHeadList(&eventHead);

			// Decrement number of events in list by one
			eventCount--;

			// Get start address of full event from LIST_ENTRY member
			pFullEventHeader = CONTAINING_RECORD(pRemovedEventEntry, FULL_EVENT<EVENT_DATA_HEADER>, Entry);

			// Free full event
			ExFreePool(pFullEventHeader);
		}

		// Else, add latest event to end of list
		InsertTailList(&eventHead, pListEntry);

		// Increment number of events in list by one
		eventCount++;
	}
	__finally {
		// Release ownership of fast mutex, lowers current CPU IRQL to 0(DISPATCH_LEVEL)
		ExReleaseFastMutex(&fastMutex);
	}
}

// PCREATE_PROCESS_NOTIFY_ROUTINE_EX callback routine that gets called by kernel for process creation and exit notifications
// Runs at IRQL=0(PASSIVE_LEVEL)
// ------------------------------------------------------------------------

void process_notification_callback(PEPROCESS pEprocess, HANDLE pid, PPS_CREATE_NOTIFY_INFO pPsCreateNotifyInfo) {
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pEprocess);

	// Init some important stuff
	USHORT allocSize = 0;
	USHORT commandLineSize = 0;
	FULL_EVENT<PROCESS_CREATE_DATA>* pFullEventProcessCreate = NULL;
	PPROCESS_CREATE_DATA pProcessCreateData;
	LARGE_INTEGER currentTime = { 0 };
	FULL_EVENT<PROCESS_EXIT_DATA>* pFullEventProcessExit = NULL;
	PPROCESS_EXIT_DATA pProcessExitData;

	// Handle process creation event
	if (pPsCreateNotifyInfo) {
		// Calculate total size of allocation based on command line length(if any)
		allocSize = sizeof(FULL_EVENT<PROCESS_CREATE_DATA>);
		if (pPsCreateNotifyInfo->CommandLine) {
			commandLineSize = pPsCreateNotifyInfo->CommandLine->Length;
			allocSize = allocSize + commandLineSize;
		}

		// Allocate memory from Paged pool for full event representing process creation event
		pFullEventProcessCreate = (FULL_EVENT<PROCESS_CREATE_DATA>*)ExAllocatePoolWithTag(PagedPool, allocSize, POOL_TAG);
		if (pFullEventProcessCreate == NULL) {
			PRINT("ExAllocatePoolWithTag 1 error: %X\n", STATUS_INSUFFICIENT_RESOURCES);
			return;
		}

		// Get PROCESS_CREATE_DATA structure from full event
		// Can also use C++ reference
		pProcessCreateData = &(pFullEventProcessCreate->Data);

		// Get precise current system time in UTC
		// Only available since Windows 8, for earlier versions, use KeQuerySystemTime
		KeQuerySystemTimePrecise(&currentTime);

		// Populate PROCESS_CREATE_DATA structure
		pProcessCreateData->Header.Type = ProcessCreate;
		pProcessCreateData->Header.Size = sizeof(PROCESS_CREATE_DATA) + commandLineSize;
		pProcessCreateData->Header.Time = currentTime;
		pProcessCreateData->ProcessId = HandleToULong(pid);
		pProcessCreateData->ParentProcessId = HandleToULong(pPsCreateNotifyInfo->ParentProcessId);
		if (commandLineSize > 0) {
			// Copy command line string to address at end of base structure
			RtlCopyMemory((UCHAR*)pProcessCreateData + sizeof(*pProcessCreateData), pPsCreateNotifyInfo->CommandLine->Buffer, commandLineSize);
			pProcessCreateData->CommandLineLength = commandLineSize / sizeof(WCHAR);	// Store command line length in WCHARs
			pProcessCreateData->CommandLineOffset = sizeof(*pProcessCreateData); // Store offset from beginning of structure
		}
		else {
			// No command line
			pProcessCreateData->CommandLineLength = 0;
		}

		// Add event to end of linked list
		push_event(&pFullEventProcessCreate->Entry);
	}
	// Handle process termination event
	else {
		// Allocate memory from Paged pool for full event representing process termination event
		pFullEventProcessExit = (FULL_EVENT<PROCESS_EXIT_DATA>*)ExAllocatePoolWithTag(PagedPool, sizeof(FULL_EVENT<PROCESS_EXIT_DATA>), POOL_TAG);
		if (pFullEventProcessExit == NULL) {
			PRINT("ExAllocatePoolWithTag 2 error: %X\n", STATUS_INSUFFICIENT_RESOURCES);
			return;
		}

		// Get PROCESS_EXIT_DATA structure from full event
		pProcessExitData = &(pFullEventProcessExit->Data);

		// Get precise current system time in UTC
		// Only available since Windows 8, for earlier versions, use KeQuerySystemTime
		KeQuerySystemTimePrecise(&currentTime);

		// Populate PROCESS_EXIT_DATA structure
		pProcessExitData->Header.Type = ProcessExit;
		pProcessExitData->Header.Size = sizeof(PROCESS_EXIT_DATA);
		pProcessExitData->Header.Time = currentTime;
		pProcessExitData->ProcessId = HandleToULong(pid);

		// Add event to end of linked list
		push_event(&pFullEventProcessExit->Entry);
	}
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
	PUCHAR pBuffer = NULL;
	PLIST_ENTRY pRemovedEventEntry = NULL;
	FULL_EVENT<EVENT_DATA_HEADER>* pFullEventHeader = NULL;
	USHORT dataSize = 0;

	// Get caller's I/O stack location in IRP
	pIoStackLocation = IoGetCurrentIrpStackLocation(pIrp);

	// Get length of read buffer
	bufferLength = pIoStackLocation->Parameters.Read.Length;
	if (bufferLength == 0) {
		status = STATUS_INVALID_BUFFER_SIZE;
		PRINT("Read buffer length error: %X\n", status);
		goto cleanup;
	}

	// Map locked user-mode buffer to system space and return its kernel-mode VA
	pBuffer = (PUCHAR)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);
	if (pBuffer == NULL) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		bytesTransferred = 0;
		PRINT("MmGetSystemAddressForMdlSafe error: %X\n", status);
		goto cleanup;
	}

	// Acquire ownership of fast mutex, raises current CPU IRQL to 1(APC_LEVEL) 
	ExAcquireFastMutex(&fastMutex);

	// Use SEH since it is important to release fast mutex no matter what happens
	__try {
		// Infinite loop to continue pulling items from head of list and copy to user's buffer until it is full or list is empty
		while (true) {
			// Check if list is already empty, then break
			// Can also check eventCount
			if (IsListEmpty(&eventHead))
				break;

			// Remove beginning entry/oldest event from list
			pRemovedEventEntry = RemoveHeadList(&eventHead);

			// Get start address of full event from LIST_ENTRY member
			pFullEventHeader = CONTAINING_RECORD(pRemovedEventEntry, FULL_EVENT<EVENT_DATA_HEADER>, Entry);

			// Get size of event data
			dataSize = pFullEventHeader->Data.Size;

			// Check if user's buffer remaining length is smaller than event data length
			if (bufferLength < dataSize) {
				// User's buffer is full, insert recently removed event back, then break
				InsertHeadList(&eventHead, pRemovedEventEntry);
				break;
			}

			// Else proceed to copy event data to user's buffer
			// Decrement number of events in list by one
			eventCount--;

			// Copy event data to user's buffer
			RtlCopyMemory(pBuffer, &pFullEventHeader->Data, dataSize);

			// Update user's buffer length
			bufferLength = bufferLength - dataSize;

			// Update user's buffer address
			pBuffer = pBuffer + dataSize;

			// Update total bytes transferred to client
			bytesTransferred = bytesTransferred + dataSize;

			// Free full event as it is consumed by client
			ExFreePool(pFullEventHeader);
		}
	}
	__finally {
		// Release ownership of fast mutex, lowers current CPU IRQL to 0(DISPATCH_LEVEL)
		ExReleaseFastMutex(&fastMutex);
	}

	// Cleanup
cleanup:
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

	// Init some important stuff
	PLIST_ENTRY pRemovedEventEntry = NULL;
	FULL_EVENT<EVENT_DATA_HEADER>* pFullEventHeader = NULL;

	// Deregister process notification callback routine
	PsSetCreateProcessNotifyRoutineEx(process_notification_callback, TRUE);

	// Empty events from list(if any)
	while (!IsListEmpty(&eventHead)) {
		// Remove beginning entry/oldest event from list
		pRemovedEventEntry = RemoveHeadList(&eventHead);

		// Get start address of full event from LIST_ENTRY member
		pFullEventHeader = CONTAINING_RECORD(pRemovedEventEntry, FULL_EVENT<EVENT_DATA_HEADER>, Entry);

		// Free full event
		ExFreePool(pFullEventHeader);
	}

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
	BOOLEAN processCallbackRegistered = FALSE;

	// Set routine to be called on driver unload
	pDriverObject->DriverUnload = driver_unload;

	// Set dispatch routine to be called to obtain handle/close handle to device object
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = driver_create_close;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = driver_create_close;

	// Set dispatch routine to be called to read from device object
	pDriverObject->MajorFunction[IRP_MJ_READ] = driver_read;

	// Create exclusive device object
	status = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, TRUE, &pDeviceObject);
	if (status != STATUS_SUCCESS) {
		PRINT("IoCreateDevice error: %X\n", status);
		goto cleanup;
	}
	PRINT("Device object created!\n");

	// Set up Direct I/O
	pDeviceObject->Flags |= DO_DIRECT_IO;

	// Create symbolic link object pointing to device object for UM access
	status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
	if (status != STATUS_SUCCESS) {
		PRINT("IoCreateSymbolicLink error: %X\n", status);
		goto cleanup;
	}
	symbolicLinkCreated = TRUE;
	PRINT("Symbolic link created!\n");

	// Initialize list head to make an empty list
	InitializeListHead(&eventHead);

	// Initialize fast mutex
	ExInitializeFastMutex(&fastMutex);

	// Register callback routine for process creation/termination notifications
	status = PsSetCreateProcessNotifyRoutineEx(process_notification_callback, FALSE);
	if (status != STATUS_SUCCESS) {
		PRINT("PsSetCreateProcessNotifyRoutineEx error: %X\n", status);
		goto cleanup;
	}
	processCallbackRegistered = TRUE;
	PRINT("Process callback routine registered!\n");

	return STATUS_SUCCESS;

	// Cleanup
cleanup:
	if (processCallbackRegistered)
		PsSetCreateProcessNotifyRoutineEx(process_notification_callback, TRUE);

	if (symbolicLinkCreated)
		IoDeleteSymbolicLink(&symbolicLink);

	if (pDeviceObject)
		IoDeleteDevice(pDeviceObject);

	return status;
}