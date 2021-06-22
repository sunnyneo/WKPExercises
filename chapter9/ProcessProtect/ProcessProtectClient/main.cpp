// Includes
// ------------------------------------------------------------------------

#include <Windows.h>
#include <stdio.h>

// Macros
// ------------------------------------------------------------------------

// Symbolic link object name macro for UM access to device object
#define DEVICE_SYMBOLIC_LINK L"\\\\.\\ProcessProtect"

// IOCTL macro for protecting a process by PID
#define IOCTL_PROCESS_PROTECT_BY_PID 0x80002000

// IOCTL macro for unprotecting a process by PID
#define IOCTL_PROCESS_UNPROTECT_BY_PID 0x80002004

// IOCTL macro for clearing all processes protected from UM termination from list
#define IOCTL_PROCESS_PROTECT_CLEAR 0x8000200B

// Entry point
// ------------------------------------------------------------------------

int wmain(int argc, const wchar_t* argv[]) {
	// Init some important stuff
	HANDLE deviceHandle = NULL;
	BOOL ret = 0;
	DWORD bytesTransferred = 0;
	DWORD pid = 0;
	HANDLE processHandle = NULL;

	// Check if number of command line args meets minimum requirement
	if (argc < 2) {
		printf("To protect a process from UM termination: ProcessProtectClient.exe -p <PID>\n");
		printf("To unprotect a process from UM termination: ProcessProtectClient.exe -u <PID>\n");
		printf("To clear all the processes from protection list: ProcessProtectClient.exe -c\n");
		printf("To test process protection by attempting to terminate it: ProcessProtectClient.exe -t <PID>\n");
		return 0;
	}

	// Get handle to device object
	deviceHandle = CreateFileW(DEVICE_SYMBOLIC_LINK, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (deviceHandle == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW error: %d\n", GetLastError());
		goto cleanup;
	}
	printf("[+] Got handle to device object: %d\n", deviceHandle);

	// User asked to add a process to protection list
	if (wcscmp(argv[1], L"-p") == 0 && argc == 3) {
		// Add PID to process protect list
		pid = _wtoi(argv[2]);
		ret = DeviceIoControl(deviceHandle, IOCTL_PROCESS_PROTECT_BY_PID, &pid, sizeof(DWORD), NULL, 0, &bytesTransferred, NULL);
		if (ret == 0) {
			printf("[-] DeviceIoControl error: %d\n", GetLastError());
			goto cleanup;
		}

		// Check if driver's IRP_MJ_DEVICE_CONTROL dispatch routine is working as intended
		if (bytesTransferred != sizeof(DWORD)) {
			printf("[-] Wrong number of bytes written to device: %d\n", bytesTransferred);
			goto cleanup;
		}
		printf("[+] Successfully added process to protection list!\n");
	}
	// User asked to remove a process to protection list
	else if (wcscmp(argv[1], L"-u") == 0 && argc == 3) {
		// Remove PID from process protect list
		pid = _wtoi(argv[2]);
		ret = DeviceIoControl(deviceHandle, IOCTL_PROCESS_UNPROTECT_BY_PID, &pid, sizeof(DWORD), NULL, 0, &bytesTransferred, NULL);
		if (ret == 0) {
			printf("[-] DeviceIoControl error: %d\n", GetLastError());
			goto cleanup;
		}

		// Check if driver's IRP_MJ_DEVICE_CONTROL dispatch routine is working as intended
		if (bytesTransferred != sizeof(DWORD)) {
			printf("[-] Wrong number of bytes written to device: %d\n", bytesTransferred);
			goto cleanup;
		}
		printf("[+] Successfully removed process from protection list!\n");
	}
	// Clear process protection list maintained by driver
	else if (wcscmp(argv[1], L"-c") == 0) {
		// Remove PID from process protect list
		ret = DeviceIoControl(deviceHandle, IOCTL_PROCESS_PROTECT_CLEAR, NULL, 0, NULL, 0, &bytesTransferred, NULL);
		if (ret == 0) {
			printf("[-] DeviceIoControl error: %d\n", GetLastError());
			goto cleanup;
		}

		// Check if driver's IRP_MJ_DEVICE_CONTROL dispatch routine is working as intended
		if (bytesTransferred != 0) {
			printf("[-] Wrong number of bytes written to device: %d\n", bytesTransferred);
			goto cleanup;
		}
		printf("[+] Successfully cleared process protection list!\n");
	}
	// Test process protection by trying to terminate process
	else if (wcscmp(argv[1], L"-t") == 0 && argc == 3) {
		// Get handle to process with PROCESS_ALL_ACCESS access mask
		pid = _wtoi(argv[2]);
		processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (processHandle == NULL) {
			printf("[-] OpenProcess error: %d\n", GetLastError());
			goto cleanup;
		}
		printf("[+] Got handle to process object: %d\n", processHandle);

		// Kill process
		ret = TerminateProcess(processHandle, 0);
		if (ret == 0) {
			printf("[-] TerminateProcess error: %d\n", GetLastError());
			goto cleanup;
		}
		printf("[+] Terminated process successfully!\n");
	}
	// Incorrect command line args
	else
		printf("Incorrect args! Quitting...\n");

	// Cleanup
cleanup:
	if (deviceHandle)
		CloseHandle(deviceHandle);

	if (processHandle)
		CloseHandle(processHandle);

	return 0;
}