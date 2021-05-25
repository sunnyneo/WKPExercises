// Includes
// ------------------------------------------------------------------------

#include <Windows.h>
#include <stdio.h>

// Macros
// ------------------------------------------------------------------------

// Symbolic link object name macro for UM access to device object
#define DEVICE_SYMBOLIC_LINK L"\\\\.\\PriorityBooster"

// IOCTL macro for changing priority of target thread
#define IOCTL_SET_THREAD_PRIORITY 0x80002003

// Structs/Enums
// ------------------------------------------------------------------------

// Input buffer
typedef struct _THREAD_DATA {
	USHORT ThreadId;
	USHORT Priority;
} THREAD_DATA, * PTHREAD_DATA;

// Entry point
// ------------------------------------------------------------------------

int main(int argc, const char* argv[]) {
	// Init some important stuff
	HANDLE deviceHandle = NULL;
	THREAD_DATA threadData = { 0 };
	BOOL ret = 0;

	// Check if number of command line args meets minimum requirement
	if (argc < 3) {
		printf("Usage: chapter4_client.exe <TID> <run-time priority value>\n");
		return 0;
	}

	// Get handle to device object
	deviceHandle = CreateFileW(DEVICE_SYMBOLIC_LINK, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (deviceHandle == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW error: %d\n", GetLastError());
		goto cleanup;
	}
	printf("[+] Got handle to device object: %d\n", deviceHandle);

	// Set the operator input values to the input buffer
	threadData.ThreadId = atoi(argv[1]);
	threadData.Priority = atoi(argv[2]);

	// Send thread priority change IOCTL to driver
	ret = DeviceIoControl(deviceHandle, IOCTL_SET_THREAD_PRIORITY, &threadData, sizeof(THREAD_DATA), NULL, 0, NULL, NULL);
	if (ret == 0) {
		printf("[-] DeviceIoControl error: %d\n", GetLastError());
		goto cleanup;
	}
	printf("[+] Successfully changed priority of target thread!\n");

	// Cleanup
cleanup:
	if (deviceHandle)
		CloseHandle(deviceHandle);

	return 0;
}