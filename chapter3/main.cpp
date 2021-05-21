#include <ntddk.h>

// Macros
// ------------------------------------------------------------------------

// Print debug message macro for DebugView
#define DEBUG_PREFIX "[DBG]: "
#define PRINT(_x_, ...) DbgPrint(DEBUG_PREFIX _x_, ##__VA_ARGS__);

// Pool tag macro in reverse order due to Little Endianness
#define POOL_TAG 'PKW'

// Globals
// ------------------------------------------------------------------------

UNICODE_STRING gRegistryPath;

// Driver unload routine
// ------------------------------------------------------------------------

void driver_unload(PDRIVER_OBJECT pDriverObject) {
	// [DBG]
	PRINT("Driver unloaded!\n");

	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDriverObject);

	// Free allocation for global nt!_UNICODE_STRING buffer
	ExFreePool(gRegistryPath.Buffer);
}

// Copy driver service registry key path to global variable
// ------------------------------------------------------------------------

void copy_registry_path(PUNICODE_STRING registryPath) {
	// Init some important stuff
	USHORT registryPathSize = 0;
	
	// Get length of service key path
	registryPathSize = registryPath->Length;

	// Allocate memory for global destination nt!_UNICODE_STRING buffer
	gRegistryPath.Buffer = (PWCHAR)ExAllocatePoolWithTag(PagedPool, registryPathSize, POOL_TAG);
	if (gRegistryPath.Buffer == NULL) {
		PRINT("ExAllocatePoolWithTag error: %X\n", STATUS_INSUFFICIENT_RESOURCES);
		return;
	}

	// Set MaximumLength member of global destination nt!_UNICODE_STRING
	gRegistryPath.MaximumLength = registryPathSize;

	// Copy service key path to global destination nt!_UNICODE_STRING
	RtlCopyUnicodeString(&gRegistryPath, registryPath);

	// [DBG]
	PRINT("Copied service key path: %wZ\n", &gRegistryPath);
}

// Driver entry point
// ------------------------------------------------------------------------

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING registryPath) {
	// [DBG]
	PRINT("Driver loaded!\n");

	// Suppress W4 warning - C4100
	//UNREFERENCED_PARAMETER(registryPath);

	// Set routine to be called on driver unload
	pDriverObject->DriverUnload = driver_unload;

	// Copy registry path
	copy_registry_path(registryPath);

	return STATUS_SUCCESS;
}