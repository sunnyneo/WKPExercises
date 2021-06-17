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
	BOOLEAN isBlocked;
} PROCESS_CREATE_DATA, * PPROCESS_CREATE_DATA;

// Hold process termination event data
typedef struct _PROCESS_EXIT_DATA {
	EVENT_DATA_HEADER Header;
	DWORD32 ProcessId;
} PROCESS_EXIT_DATA, * PPROCESS_EXIT_DATA;

// Hold thread creation event data
typedef struct _THREAD_CREATE_DATA {
	EVENT_DATA_HEADER Header;
	DWORD32 ThreadId;
	DWORD32 ProcessId;
	BOOLEAN isCreatedRemote;
	DWORD32 RemoteProcessId;
} THREAD_CREATE_DATA, * PTHREAD_CREATE_DATA;

// Hold thread termination event data
typedef struct _THREAD_EXIT_DATA {
	EVENT_DATA_HEADER Header;
	DWORD32 ThreadId;
	DWORD32 ProcessId;
} THREAD_EXIT_DATA, * PTHREAD_EXIT_DATA;

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
	PTHREAD_CREATE_DATA pThreadCreateData = NULL;
	PTHREAD_EXIT_DATA pThreadExitData = NULL;
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
			if (pProcessCreateData->isBlocked == TRUE)
				printf("Process %d Blocked. Command line: %ws\n", pProcessCreateData->ProcessId, commandLine.c_str());
			else
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
			pThreadCreateData = (THREAD_CREATE_DATA*)pBuffer;

			// Print thread create data to console
			if (pThreadCreateData->isCreatedRemote == TRUE)
				printf("Remote Thread %d Created in process %d by remote process %d\n", pThreadCreateData->ThreadId, pThreadCreateData->ProcessId, pThreadCreateData->RemoteProcessId);
			else
				printf("Thread %d Created in process %d\n", pThreadCreateData->ThreadId, pThreadCreateData->ProcessId);
			break;
		}
		// Thread exit event
		case ThreadExit: {
			// Print event time to console
			print_time(&(pEventDataHeader->Time));

			// Get pointer to thread exit data from read buffer
			pThreadExitData = (THREAD_EXIT_DATA*)pBuffer;

			// Print thread exit data to console
			printf("Thread %d Exited from process %d\n", pThreadExitData->ThreadId, pThreadExitData->ProcessId);
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

int wmain(int argc, const wchar_t* argv[]) {
	// Init some important stuff
	HANDLE deviceHandle = NULL;
	BYTE readBuffer[1 << 16] = { 0 }; // 64 kB buffer
	BOOL ret = 0;
	DWORD bytesTransferred = 0;

	// Check if number of command line args meets minimum requirement
	if (argc < 2) {
		printf("To display all events: chapter8_client.exe -d\n");
		printf("To add PE to blocklist: chapter8_client.exe -p <full NT path of executable to block>\n");
		printf("Example: chapter8_client.exe -p \\??\\C:\\Windows\\System32\\notepad.exe\n");
		return 0;
	}

	// Get handle to device object
	deviceHandle = CreateFileW(DEVICE_SYMBOLIC_LINK, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (deviceHandle == INVALID_HANDLE_VALUE) {
		printf("[-] CreateFileW error: %d\n", GetLastError());
		goto cleanup;
	}
	printf("[+] Got handle to device object: %d\n", deviceHandle);

	// User asked to display all events to console
	if (wcscmp(argv[1], L"-d") == 0) {
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
	}
	// User asked to add an executable to execution blocklist
	else if (wcscmp(argv[1], L"-p") == 0 && argc == 3) {
		// Write data to device from write buffer
		ret = WriteFile(deviceHandle, argv[2], (wcslen(argv[2]) + 1) * sizeof(WCHAR), &bytesTransferred, NULL);
		if (ret == 0) {
			printf("[-] WriteFile error: %d\n", GetLastError());
			goto cleanup;
		}

		// Check if driver's IRP_MJ_WRITE dispatch routine is working as intended
		if (bytesTransferred != (wcslen(argv[2]) + 1) * sizeof(WCHAR)) {
			printf("[-] Wrong number of bytes written to device: %d\n", bytesTransferred);
			goto cleanup;
		}
		printf("[+] Successfully added executable to blocklist!\n");
	}
	// Incorrect command line args
	else
		printf("Incorrect args! Quitting...\n");

	// Cleanup
cleanup:
	if (deviceHandle)
		CloseHandle(deviceHandle);

	return 0;
}