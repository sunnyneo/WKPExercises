// Includes
// ------------------------------------------------------------------------

#include <ntddk.h>

// Macros
// ------------------------------------------------------------------------

// Print debug message macro for DebugView
#define DEBUG_PREFIX "[DBG]: "
#define PRINT(_x_, ...) DbgPrint(DEBUG_PREFIX _x_, ##__VA_ARGS__);

// Driver unload routine
// ------------------------------------------------------------------------

void driver_unload(PDRIVER_OBJECT pDriverObject) {
	// [DBG]
	PRINT("Driver unloaded!\n");

	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(pDriverObject);
}

// Get OS major version, minor version and build number
// ------------------------------------------------------------------------

void get_os_version() {
	// Init some important stuff
	NTSTATUS status;
	RTL_OSVERSIONINFOW rtlOsVersionInfoW = { 0 };

	// Call RtlGetVersion
	rtlOsVersionInfoW.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
	status = RtlGetVersion(&rtlOsVersionInfoW);
	if (status != STATUS_SUCCESS) {
		PRINT("RtlGetVersion error: %X\n", status);
		return;
	}

	// [DBG]
	PRINT("OS Major Version Number: %d\n", rtlOsVersionInfoW.dwMajorVersion);
	PRINT("OS Minor Version Number: %d\n", rtlOsVersionInfoW.dwMinorVersion);
	PRINT("OS Build Number: %d\n", rtlOsVersionInfoW.dwBuildNumber);
}

// Driver entry point
// ------------------------------------------------------------------------

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING registryPath) {
	// [DBG]
	PRINT("Driver loaded!\n");

	// Suppress W4 warning - C4100
	UNREFERENCED_PARAMETER(registryPath);

	// Set routine to be called on driver unload
	pDriverObject->DriverUnload = driver_unload;

	// Get OS version
	get_os_version();

	return STATUS_SUCCESS;
}