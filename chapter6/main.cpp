// Includes
// ------------------------------------------------------------------------

#include <ntddk.h>

// Macros
// ------------------------------------------------------------------------

// Print debug message macro for DebugView
#define DEBUG_PREFIX "[DBG]: "
#define PRINT(_x_, ...) DbgPrint(DEBUG_PREFIX _x_, ##__VA_ARGS__);

// Relative time is in 100 nanosecond intervals and is negative
#define DELAY_ONE_MILLISECOND (-10000LL)

// Globals
// ------------------------------------------------------------------------

UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\Chapter6");
KTIMER ktimer;
KDPC kdpc;
PIO_WORKITEM pIoWorkitem;
LONG activeTasks = 0;

// Driver unload routine
// ------------------------------------------------------------------------

void driver_unload(PDRIVER_OBJECT pDriverObject) {
	// [DBG]
	PRINT("Driver unloaded!\n");

	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDriverObject);

	// Free work item if not queued already
	IoFreeWorkItem(pIoWorkitem);

	// Dequeue kernel timer object from system timer queue and cancel DPC object
	KeCancelTimer(&ktimer);

	// Delete device object
	IoDeleteDevice(pDriverObject->DeviceObject);
}

// IO_WORKITEM_ROUTINE WorkItem routine that is queued into kernel provided thread pool for execution by some system worker thread
// Runs at IRQL=0(PASSIVE_LEVEL)
// ------------------------------------------------------------------------

void workitem_callback(PDEVICE_OBJECT pDeviceObject, PVOID context) {
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDeviceObject);
	UNREFERENCED_PARAMETER(context);

	// Avoid calling subroutine for second time if previous one hasn't finished processing
	do {
		// [DBG]
		PRINT("In WorkItem routine executing at IRQL=%d\n", KeGetCurrentIrql());

		// Atomically decrement active number of tasks to signal ready and process next callback
		InterlockedDecrement(&activeTasks);
	} while (activeTasks != 0);
}

// KDEFERRED_ROUTINE DPC routine that is inserted into processor's DPC queue upon timer expiration to execute as soon as conditions permit
// Runs at IRQL=2(DISPATCH_LEVEL)
// ------------------------------------------------------------------------

void dpc_callback(PKDPC pKdpc, PVOID deferredContext, PVOID systemArg1, PVOID systemArg2) {
	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pKdpc);
	UNREFERENCED_PARAMETER(deferredContext);
	UNREFERENCED_PARAMETER(systemArg1);
	UNREFERENCED_PARAMETER(systemArg2);

	// [DBG]
	PRINT("In DPC routine executing at IRQL=%d\n", KeGetCurrentIrql());

	// Atomically increment active number of work item to be queued everytime this function is called 
	InterlockedIncrement(&activeTasks);

	// Check if work item was previously queued, if not proceed to queue it
	// Queuing work item that is already in queue can cause system data structure corruption!
	if (activeTasks == 1) {
		// Queue WorkItem routine to be executed by some specified type of system worker thread
		// DelayedWorkQueue = ordinary system worker thread, priority = 12
		IoQueueWorkItem(pIoWorkitem, workitem_callback, DelayedWorkQueue, NULL);
	}
}

// Initialize and start kernel timer to call DPC callback routine upon expiration of set interval
// ------------------------------------------------------------------------

void start_timer(DWORD32 milliseconds) {
	// Init some important stuff
	LARGE_INTEGER largeInteger = { 0 };
	
	// Initialize kernel notification timer object to non-signaled state
	KeInitializeTimer(&ktimer);

	// Initialize DPC object and register CustomTimerDpc routine for that object
	KeInitializeDpc(&kdpc, dpc_callback, NULL);

	// Set relative DueTime at which timer is to expire and set DPC routine to call upon expiration
	largeInteger.QuadPart = DELAY_ONE_MILLISECOND * milliseconds;
	KeSetTimer(&ktimer, largeInteger, &kdpc);
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

	// Create device object for later association with work item
	status = IoCreateDevice(pDriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (status != STATUS_SUCCESS) {
		PRINT("IoCreateDevice error: %X\n", status);
		return status;
	}
	PRINT("Device object created!\n");

	// Allocate and initialize work item
	// Slightly risky alternative: Use ExInitializeWorkItem + ExQueueWorkItem to avoid creating device object
	pIoWorkitem = IoAllocateWorkItem(pDriverObject->DeviceObject);
	if (pIoWorkitem == NULL) {
		PRINT("IoAllocateWorkItem error: %X\n", STATUS_INSUFFICIENT_RESOURCES);
		IoDeleteDevice(pDeviceObject);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	PRINT("Work Item allocated and initialized!\n");

	// Initialize and start kernel timer set to expire after 6 seconds
	start_timer(6000);

	return STATUS_SUCCESS;
}