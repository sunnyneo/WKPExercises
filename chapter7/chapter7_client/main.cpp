// Includes
// ------------------------------------------------------------------------

#include <Windows.h>
#include <stdio.h>

// Macros
// ------------------------------------------------------------------------

// Symbolic link object name macro for UM access to device object
#define DEVICE_SYMBOLIC_LINK L"\\\\.\\Zero"

// IOCTL macro for obtaining total number of bytes read and written from/to device
#define IOCTL_ZERO_GET_STATS 0x80002000

// Structs/Enums
// ------------------------------------------------------------------------

// Output buffer
typedef struct _ZERO_DATA {
	DWORD64 TotalRead;
	DWORD64 TotalWritten;
} ZERO_DATA, * PZERO_DATA;

// Entry point
// ------------------------------------------------------------------------

int main(int argc, const char* argv[]) {
	// Init some important stuff
	HANDLE deviceHandle = NULL;
	BYTE readBuffer[64] = { 0 };
	BOOL ret = 0;
	DWORD bytesTransferred = 0;
	DWORD total = 0;
	BYTE writeBuffer[1024] = { 0 };
	ZERO_DATA zeroData = { 0 };

	// Get handle to device object
	deviceHandle = CreateFileW(DEVICE_SYMBOLIC_LINK, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (deviceHandle == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW error: %d\n", GetLastError());
		goto cleanup;
	}
	printf("[+] Got handle to device object: %d\n", deviceHandle);

	// Populate read buffer with some data
	for (int i = 0; i < sizeof(readBuffer); i++) {
		readBuffer[i] = i + 1;
	}

	// Read data from device to read buffer
	ret = ReadFile(deviceHandle, readBuffer, sizeof(readBuffer), &bytesTransferred, NULL);
	if (ret == 0) {
		printf("[-] ReadFile error: %d\n", GetLastError());
		goto cleanup;
	}

	// Check if driver's IRP_MJ_READ dispatch routine is working as intended
	if (bytesTransferred != sizeof(readBuffer)) {
		printf("[-] Wrong number of bytes read from device: %d\n", bytesTransferred);
		goto cleanup;
	}
	for (int i = 0; i < sizeof(readBuffer); i++) {
		total = total + readBuffer[i];
	}
	if (total != 0) {
		printf("[-] Wrong data read from device: %d\n", total);
		goto cleanup;
	}
	printf("[+] Successfully read zeroed out buffer from device!\n");

	// Write data to device from write buffer
	ret = WriteFile(deviceHandle, writeBuffer, sizeof(writeBuffer), &bytesTransferred, NULL);
	if (ret == 0) {
		printf("[-] WriteFile error: %d\n", GetLastError());
		goto cleanup;
	}

	// Check if driver's IRP_MJ_WRITE dispatch routine is working as intended
	if (bytesTransferred != sizeof(writeBuffer)) {
		printf("[-] Wrong number of bytes written to device: %d\n", bytesTransferred);
		goto cleanup;
	}
	printf("[+] Successfully written data to device!\n");

	// Get total number of bytes read and written from/to device since driver load
	ret = DeviceIoControl(deviceHandle, IOCTL_ZERO_GET_STATS, NULL, 0, &zeroData, sizeof(ZERO_DATA), &bytesTransferred, NULL);
	if (ret == 0) {
		printf("[-] DeviceIoControl error: %d\n", GetLastError());
		goto cleanup;
	}
	
	// Check if driver's IRP_MJ_DEVICE_CONTROL dispatch routine is working as intended
	if (bytesTransferred != sizeof(ZERO_DATA)) {
		printf("[-] Wrong output buffer received from device: %d\n", bytesTransferred);
		goto cleanup;
	}
	printf("[+] Total number of bytes read from device since driver load: %d\n", zeroData.TotalRead);
	printf("[+] Total number of bytes written to device since driver load: %d\n", zeroData.TotalWritten);

	// Cleanup
cleanup:
	if (deviceHandle)
		CloseHandle(deviceHandle);

	return 0;
}