// Includes
// ------------------------------------------------------------------------

#include <Windows.h>
#include <stdio.h>
#include <string>

// Macros
// ------------------------------------------------------------------------

// Symbolic link object name macro for UM access to device object
#define DEVICE_SYMBOLIC_LINK L"\\\\.\\SysMon"

// Maximum image file name size macro for image load callbacks
#define MAX_IMAGE_FILE_NAME_SIZE 300

// Structs/Enums
// ------------------------------------------------------------------------

// Supported notification event types
typedef enum _NOTIFICATION_EVENT_TYPE {
	None,
	ProcessCreate,
	ProcessExit,
	ThreadCreate,
	ThreadExit,
	ImageLoad
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

// Hold thread creation/termination event data
typedef struct _THREAD_CREATE_EXIT_DATA {
	EVENT_DATA_HEADER Header;
	DWORD32 ThreadId;
	DWORD32 ProcessId;
} THREAD_CREATE_EXIT_DATA, * PTHREAD_CREATE_EXIT_DATA;

// Hold image load/map(EXE/DLL/SYS) event data
typedef struct _IMAGE_LOAD_DATA {
	EVENT_DATA_HEADER Header;
	DWORD32 ProcessId;
	PVOID LoadAddress;
	DWORD64 ImageFileSize;
	WCHAR ImageFileName[MAX_IMAGE_FILE_NAME_SIZE + 1];
} IMAGE_LOAD_DATA, * PIMAGE_LOAD_DATA;

// Print event time to console in human-readable fashion
// ------------------------------------------------------------------------

void print_time(PLARGE_INTEGER pLargeInteger) {
	// Init some important stuff
	SYSTEMTIME systemtime;

	// Convert file time to system time format
	FileTimeToSystemTime((FILETIME*)pLargeInteger, &systemtime);

	// Print system time to console
	printf("%02d:%02d:%02d.%03d: ", systemtime.wHour, systemtime.wMinute, systemtime.wSecond, systemtime.wMilliseconds);
}

// Process read buffer and print notification event information to console
// ------------------------------------------------------------------------

void print_event_info(PBYTE pBuffer, DWORD bufferSize) {
	// Init some important stuff
	DWORD count = bufferSize;
	PEVENT_DATA_HEADER pEventDataHeader = NULL;
	PPROCESS_EXIT_DATA pProcessExitData = NULL;
	PPROCESS_CREATE_DATA pProcessCreateData = NULL;
	std::wstring commandLine = L"";
	PTHREAD_CREATE_EXIT_DATA pThreadCreateExitData = NULL;
	PIMAGE_LOAD_DATA pImageLoadData = NULL;

	// Loop till there are events in read buffer
	while (count > 0) {
		// Get pointer to event data header from read buffer
		pEventDataHeader = (EVENT_DATA_HEADER*)pBuffer;

		// Check which type of notification event we have received
		switch (pEventDataHeader->Type) {
		// Process create event
		case ProcessCreate: {
			// Print event time to console
			print_time(&(pEventDataHeader->Time));

			// Get pointer to process create data from read buffer
			pProcessCreateData = (PROCESS_CREATE_DATA*)pBuffer;

			// Extract command line string using its length and offset from beginning of structure
			// Command line characters follow process create data structure in memory 
			commandLine = std::wstring((WCHAR*)(pBuffer + pProcessCreateData->CommandLineOffset), pProcessCreateData->CommandLineLength);

			// Print process create data to console
			printf("Process %d Created. Command line: %ws\n", pProcessCreateData->ProcessId, commandLine.c_str());
			break;
		}
		// Process exit event
		case ProcessExit: {
			// Print event time to console
			print_time(&(pEventDataHeader->Time));

			// Get pointer to process exit data from read buffer
			pProcessExitData = (PROCESS_EXIT_DATA*)pBuffer;

			// Print process exit data to console
			printf("Process %d Exited\n", pProcessExitData->ProcessId);
			break;
		}
		// Thread create event
		case ThreadCreate: {
			// Print event time to console
			print_time(&(pEventDataHeader->Time));

			// Get pointer to thread create data from read buffer
			pThreadCreateExitData = (THREAD_CREATE_EXIT_DATA*)pBuffer;

			// Print thread create data to console
			printf("Thread %d Created in process %d\n", pThreadCreateExitData->ThreadId, pThreadCreateExitData->ProcessId);
			break;
		}
		// Thread exit event
		case ThreadExit: {
			// Print event time to console
			print_time(&(pEventDataHeader->Time));

			// Get pointer to thread exit data from read buffer
			pThreadCreateExitData = (THREAD_CREATE_EXIT_DATA*)pBuffer;

			// Print thread exit data to console
			printf("Thread %d Exited from process %d\n", pThreadCreateExitData->ThreadId, pThreadCreateExitData->ProcessId);
			break;
		}
		// Image load event
		case ImageLoad: {
			// Print event time to console
			print_time(&(pEventDataHeader->Time));

			// Get pointer to image load/map data from read buffer
			pImageLoadData = (IMAGE_LOAD_DATA*)pBuffer;

			// Print image load/map data to console
			printf("Image loaded into process %d at address 0x%p (%ws)\n", pImageLoadData->ProcessId, pImageLoadData->LoadAddress, pImageLoadData->ImageFileName);
			break;
		}
		default:
			break;
		}

		// Update read buffer to get next event from it
		pBuffer = pBuffer + pEventDataHeader->Size;

		// Update read events count to decide when to stop processing
		count = count - pEventDataHeader->Size;
	}
}

// Entry point
// ------------------------------------------------------------------------

int main(int argc, const char* argv[]) {
	// Init some important stuff
	HANDLE deviceHandle = NULL;
	BYTE readBuffer[1 << 16] = { 0 }; // 64 kB buffer
	BOOL ret = 0;
	DWORD bytesTransferred = 0;

	// Get handle to device object
	deviceHandle = CreateFileW(DEVICE_SYMBOLIC_LINK, GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (deviceHandle == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW error: %d\n", GetLastError());
		goto cleanup;
	}
	printf("[+] Got handle to device object: %d\n", deviceHandle);

	// Infinite loop to continue polling events from device until termination
	while (true) {
		// Read data from device to read buffer
		ret = ReadFile(deviceHandle, readBuffer, sizeof(readBuffer), &bytesTransferred, NULL);
		if (ret == 0) {
			printf("[-] ReadFile error: %d\n", GetLastError());
			goto cleanup;
		}

		// If we read data from device, pass along read buffer for processing and printing to console
		if (bytesTransferred != 0)
			print_event_info(readBuffer, bytesTransferred);

		// Wait for bit before continuing next iteration - 200 ms
		Sleep(200);
	}

	// Cleanup
cleanup:
	if (deviceHandle)
		CloseHandle(deviceHandle);

	return 0;
}