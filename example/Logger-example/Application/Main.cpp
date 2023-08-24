#include "DriverLoader.hpp"

#include <Windows.h>

#include <iostream>
#include <string>

#define IOCTL_REGISTER_EVENT \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_RETURN_IRP_PENDING_PACKETS_AND_DISALLOW_IOCTL \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_BUFFER_CHECK \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS )

#define IOCTL_BUFFER_CHECK_SUCCESS \
   CTL_CODE( FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS )

typedef enum { IRP_BASED, EVENT_BASED } NOTIFY_TYPE;

typedef struct _REGISTER_EVENT { NOTIFY_TYPE Type; HANDLE  hEvent; } REGISTER_EVENT, * PREGISTER_EVENT;

enum Restrictions {
	MaximumPacketsCapacity = 1000,
	PacketChunkSize = 1000,
	UsermodeBufferSize = sizeof(UINT32) + PacketChunkSize + 1,

	SIZEOF_REGISTER_EVENT = sizeof(REGISTER_EVENT),

	DbgPrintLimitation = 512
};

//////////////////////////////////////////////////
//				Operation Codes					//
//////////////////////////////////////////////////

// Message area >= 0x4
enum OperantionCodes {
	OPERATION_LOG_INFO_MESSAGE = 1,
	OPERATION_LOG_WARNING_MESSAGE,
	OPERATION_LOG_ERROR_MESSAGE,
	OPERATION_LOG_NON_IMMEDIATE_MESSAGE,
	OPERATION_LOG_TRACE_MESSAGE
};

BOOLEAN IsSvmOffProcessStart;

void ReadIrpBasedBuffer(HANDLE  Device) {

	BOOL    Status;
	ULONG   ReturnedLength;
	REGISTER_EVENT RegisterEvent;
	UINT32 OperationCode;

	printf(" =============================== Kernel-Mode Logs (Driver) ===============================\n");
	RegisterEvent.hEvent = NULL;
	RegisterEvent.Type = IRP_BASED;
	// allocate buffer for transfering messages
	char* OutputBuffer = (char*)malloc(UsermodeBufferSize);
	bool* OutputBufferBool = (bool*)malloc(sizeof(bool));

	while (TRUE) {
		if (!IsSvmOffProcessStart)
		{
			ZeroMemory(OutputBuffer, UsermodeBufferSize);
			ReturnedLength = 0;

			Status = DeviceIoControl(
				Device,							// Handle to device
				IOCTL_BUFFER_CHECK,			// IO Control code
				NULL,				// Input Buffer to driver.
				NULL,		// Length of input buffer in bytes. (x 2 is bcuz as the driver is x64 and has 64 bit values)
				OutputBufferBool,					// Output Buffer from driver.
				sizeof(bool),				// Length of output buffer in bytes.
				&ReturnedLength,				// Bytes placed in buffer.
				NULL							// synchronous call
			);

			if (*OutputBufferBool == true)
			{
				Status = DeviceIoControl(
					Device,							// Handle to device
					IOCTL_REGISTER_EVENT,			// IO Control code
					&RegisterEvent,					// Input Buffer to driver.
					SIZEOF_REGISTER_EVENT * 2,		// Length of input buffer in bytes. (x 2 is bcuz as the driver is x64 and has 64 bit values)
					OutputBuffer,					// Output Buffer from driver.
					UsermodeBufferSize,				// Length of output buffer in bytes.
					&ReturnedLength,				// Bytes placed in buffer.
					NULL							// synchronous call
				);

				if (!Status) { printf("Ioctl failed with code %d\n", GetLastError()); break; }

				if (ReturnedLength > 1)
				{
					printf("\n========================= Kernel Mode (Buffer) =========================\n");

					OperationCode = 0;
					memcpy(&OperationCode, OutputBuffer, sizeof(UINT32));

					printf("Returned Length : 0x%x \n", ReturnedLength);
					printf("Operation Code : 0x%x \n", OperationCode);

					switch (OperationCode)
					{
					case OPERATION_LOG_NON_IMMEDIATE_MESSAGE:
						printf("A buffer of messages (OPERATION_LOG_NON_IMMEDIATE_MESSAGE) :\n");
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					case OPERATION_LOG_INFO_MESSAGE:
						printf("Information log (OPERATION_LOG_INFO_MESSAGE) :\n");
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					case OPERATION_LOG_ERROR_MESSAGE:
						printf("Error log (OPERATION_LOG_ERROR_MESSAGE) :\n");
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					case OPERATION_LOG_WARNING_MESSAGE:
						printf("Warning log (OPERATION_LOG_WARNING_MESSAGE) :\n");
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					default:
						printf("%s", OutputBuffer + sizeof(UINT32));
						break;
					}

					printf("\n========================================================================\n");

					Status = DeviceIoControl(
						Device,							// Handle to device
						IOCTL_BUFFER_CHECK_SUCCESS,			// IO Control code
						NULL,				// Input Buffer to driver.
						NULL,		// Length of input buffer in bytes. (x 2 is bcuz as the driver is x64 and has 64 bit values)
						NULL,					// Output Buffer from driver.
						NULL,				// Length of output buffer in bytes.
						NULL,				// Bytes placed in buffer.
						NULL							// synchronous call
					);
				}
				else { continue; }
			}
			else
			{
				continue;
			}
		}
		else
		{
			// the thread should not work anymore
			return;
		}
	}
}


DWORD WINAPI ThreadFunc(void* Data) {
	ReadIrpBasedBuffer(Data); return 0;
}

int main()
{
    std::unique_ptr<DRIVER> Driver; Driver = std::make_unique<DRIVER>();
    std::string Wait;

    Driver->LoadDriver((LPTSTR)L"C:\\HyperVsr.sys", (LPTSTR)L"driver", (LPTSTR)L"driver", SERVICE_DEMAND_START);
    std::cout << "Driver Started!" << std::endl;

	HANDLE Handle = CreateFileA("\\\\.\\MyHypervisorDevice",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ |
		FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL |
		FILE_FLAG_OVERLAPPED,
		NULL); 

	if (Handle == INVALID_HANDLE_VALUE) { DWORD ErrorNum = GetLastError(); printf("[*] CreateFile failed : %d\n", ErrorNum); return false; }

	Sleep(1200);

	HANDLE Thread = CreateThread(NULL, 0, ThreadFunc, Handle, 0, NULL);
	if (Thread) { printf("[*] Thread Created successfully !!!\n"); }

	IsSvmOffProcessStart = false;

    std::cout << "Press any key to unload driver...\n";
    getline(std::cin, Wait, '\n');

	IsSvmOffProcessStart = true;

    Driver->UnloadDriver();
    std::cout << "Driver unloaded!" << std::endl;

	return true;
}