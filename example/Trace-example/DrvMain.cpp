#include <ntddk.h>

#include "GuestContext.hpp"
#include "Logger/LogSpin.hpp"
#include "include/HyperVisor/HyperVisor.hpp"

HyperVisorSvm objHyperVisorSvm; 
Log objLog;
UINT64 Counter = 0;

#define LogTraceInfo(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_TRACE_MESSAGE, false, false, "[+] Information (%s:%d) | " format "\n",	\
		 __func__, __LINE__, __VA_ARGS__)

#define LogInfo(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_INFO_MESSAGE, false, false, "[+] Information (%s:%d) | " format "\n",	\
		 __func__, __LINE__, __VA_ARGS__)

#define LogInfoImmediate(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_INFO_MESSAGE, TRUE, false, "[+] Information (%s:%d) | " format "\n",	\
		 __func__, __LINE__, __VA_ARGS__)

#define LogWarning(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_WARNING_MESSAGE, TRUE, false, "[-] Warning (%s:%d) | " format "\n",	\
		__func__, __LINE__, __VA_ARGS__)

#define LogError(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_ERROR_MESSAGE, TRUE, false, "[!] Error (%s:%d) | " format "\n",	\
		 __func__, __LINE__, __VA_ARGS__);	\
		DbgBreakPoint()

// Log without any prefix
#define Log(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_INFO_MESSAGE, false, false, format "\n", __VA_ARGS__)

SVM::PRIVATE_VM_DATA* Interceptions(
	_Inout_ SVM::PRIVATE_VM_DATA* Private)
{
	Private->Guest.ControlArea.InterceptCpuid = TRUE;
	Private->Guest.ControlArea.InterceptVmrun = TRUE;
	Private->Guest.ControlArea.InterceptExceptions.Bitmap.InterceptionVectorDB = TRUE;
	Private->Guest.ControlArea.InterceptMsr = TRUE;
	Private->Guest.ControlArea.MsrpmBasePa = reinterpret_cast<UINT64>(PhysicalMemory::GetPhysicalAddress(&Private->Msrpm));

	return Private;
}

void InjectEvent(__out SVM::VMCB* Guest, unsigned char Vector, unsigned char Type, unsigned int Code)
{
	SVM::EVENTINJ Event = {};
	Event.Bitmap.Vector = Vector;
	Event.Bitmap.Type = Type;
	Event.Bitmap.ErrorCodeValid = TRUE;
	Event.Bitmap.Valid = TRUE;
	Event.Bitmap.ErrorCode = Code;
	Guest->ControlArea.EventInjection = Event.Value;
}

extern "C" SVM::VMM_STATUS SvmVmexitHandler(
	_In_ SVM::PRIVATE_VM_DATA * Private,
	_In_ GuestContext * Context)
{
	// Load the host state:
	__svm_vmload(reinterpret_cast<size_t>(Private->VmmStack.Layout.InitialStack.HostVmcbPa));

	// Restore the guest's RAX that was overwritten by host's RAX on #VMEXIT:
	Context->Rax = Private->Guest.StateSaveArea.Rax;

	SVM::VMM_STATUS Status = SVM::VMM_STATUS::VMM_CONTINUE;	
	//KdPrint(("ExitCode %x\n", Private->Guest.ControlArea.ExitCode));
	//LogInfo("Counter is %p\n", Counter);
	//++Counter;

	switch (Private->Guest.ControlArea.ExitCode)
	{
	case SVM::SVM_EXIT_CODE::VMEXIT_CPUID:
	{
		CPUID_REGS Regs = {};
		int Function = static_cast<int>(Context->Rax);
		int SubLeaf = static_cast<int>(Context->Rcx);
		__cpuidex(Regs.Raw, Function, SubLeaf);

		if (Function == CPUID_VMM_SHUTDOWN) { Status = SVM::VMM_STATUS::VMM_SHUTDOWN; }
		else 
		{
			Context->Rax = Regs.Regs.Eax;
			Context->Rbx = Regs.Regs.Ebx;
			Context->Rcx = Regs.Regs.Ecx;
			Context->Rdx = Regs.Regs.Edx;
		}
		break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_MSR:
	{
		if ((Context->Rcx & MAXUINT32) == static_cast<unsigned int>(AMD::AMD_MSR::MSR_EFER) && Private->Guest.ControlArea.ExitInfo1)
		{
			AMD::EFER Efer = {};
			Efer.Value = ((Context->Rdx & MAXUINT32) << 32) | (Context->Rax & MAXUINT32);
			if (!Efer.Bitmap.SecureVirtualMachineEnable)
			{
				InjectEvent(&Private->Guest, INTERRUPT_VECTOR::GeneralProtection, EXCEPTION_VECTOR::FaultTrapException, 0); // #GP (Vector = 13, Type = Exception)
				break;
			}
			Private->Guest.StateSaveArea.Efer = Efer.Value;
		}
		break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_VMRUN:
	{
		InjectEvent(&Private->Guest, INTERRUPT_VECTOR::GeneralProtection, EXCEPTION_VECTOR::FaultTrapException, 0); // #GP (Vector = 13, Type = Exception)
		break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_EXCP_DB:
	{
		++Counter;
		LogTraceInfo("RIP %p\n", Private->Guest.StateSaveArea.Rip); 
		if (Counter > 100000) { KdPrint(("OVER 100k\n")); Counter = 0; }

		Private->Guest.StateSaveArea.Rax = Context->Rax;
		return Status;
	}
	}
	
	if (Status == SVM::VMM_STATUS::VMM_SHUTDOWN)
	{
		// We should to devirtualize this processor:
		Context->Rax = reinterpret_cast<UINT64>(Private) & MAXUINT32; // Low part
		Context->Rbx = Private->Guest.ControlArea.NextRip;
		Context->Rcx = Private->Guest.StateSaveArea.Rsp;
		Context->Rdx = reinterpret_cast<UINT64>(Private) >> 32; // High part

		// Load the guest's state:
		__svm_vmload(reinterpret_cast<size_t>(Private->VmmStack.Layout.InitialStack.GuestVmcbPa));

		// Store the GIF - Global Interrupt Flag:
		_disable();
		__svm_stgi();

		// Disable the SVM by resetting the EFER.SVME bit:
		AMD::EFER Efer = {};
		Efer.Value = __readmsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_EFER));
		Efer.Bitmap.SecureVirtualMachineEnable = FALSE;
		__writemsr(static_cast<unsigned long>(AMD::AMD_MSR::MSR_EFER), Efer.Value);

		// Restoring the EFlags:
		__writeeflags(Private->Guest.StateSaveArea.Rflags);
	}

	Private->Guest.StateSaveArea.Rax = Context->Rax;

	// Go to the next instruction:
	Private->Guest.StateSaveArea.Rip = Private->Guest.ControlArea.NextRip;

	return Status;
}

//Define in asm file(in my example)
extern "C" void SvmVmmRun(_In_ void* InitialVmmStackPointer);

void DrvUnload(_In_ PDRIVER_OBJECT DriverObj)
{
	UNREFERENCED_PARAMETER(DriverObj);
	KdPrint(("Sample driver Unload called\n"));
}

NTSTATUS DrvUnsupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	objHyperVisorSvm.PInterceptions = &Interceptions;
	objHyperVisorSvm.PSvmVmmRun = &SvmVmmRun;

	if (objHyperVisorSvm.IsSvmSupported()) { LogInfoImmediate("Hypervisor start =)\n"); objHyperVisorSvm.VirtualizeAllProcessors(); }

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvDispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION  IrpStack;
	PREGISTER_EVENT RegisterEvent;
	NTSTATUS    Status;
	UNREFERENCED_PARAMETER(DeviceObject);

	IrpStack = IoGetCurrentIrpStackLocation(Irp);

	switch (IrpStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_REGISTER_EVENT:
	{
		if (IrpStack->Parameters.DeviceIoControl.InputBufferLength < SIZEOF_REGISTER_EVENT || Irp->AssociatedIrp.SystemBuffer == NULL) {
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		RegisterEvent = (PREGISTER_EVENT)Irp->AssociatedIrp.SystemBuffer;

		switch (RegisterEvent->Type)
		{
		case IRP_BASED:
			Status = objLog.LogRegisterIrpBasedNotification(DeviceObject, Irp);
			break;
		case EVENT_BASED:
			Status = objLog.LogRegisterEventBasedNotification(DeviceObject, Irp);
			break;
		default:
			Status = STATUS_INVALID_PARAMETER;
			break;
		}
		break;
	}
	case IOCTL_BUFFER_CHECK:
	{
		RtlCopyBytes(Irp->AssociatedIrp.SystemBuffer, &objLog.BufferIsReady, sizeof(bool));
		Irp->IoStatus.Information = sizeof(bool);
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	case IOCTL_BUFFER_CHECK_SUCCESS:
	{
		objLog.BufferIsReady = FALSE;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	}
	return STATUS_SUCCESS;
}

NTSTATUS DrvClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegisterPath)
{
	UNREFERENCED_PARAMETER(RegisterPath); NTSTATUS Ntstatus = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = NULL; UNICODE_STRING DriverName, DosDeviceName;

	if (!objLog.LogInitialize()) { DbgPrint("[*] Log buffer is not initialized !\n"); DbgBreakPoint(); }

	RtlInitUnicodeString(&DriverName, L"\\Device\\MyHypervisorDevice");

	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisorDevice");
	Ntstatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);

	if (Ntstatus == STATUS_SUCCESS)
	{
		for (UINT64 Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++) { DriverObject->MajorFunction[Index] = DrvUnsupported; }

		DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvDispatchIoControl;
		DriverObject->DriverUnload = DrvUnload;
		IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	}

	return STATUS_SUCCESS;
}