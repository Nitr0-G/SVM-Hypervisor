#include <ntddk.h>

#include "GuestContext.hpp"
//#include "Logger/LogSpin.hpp"
#include "include/HyperVisor/HyperVisor.hpp"
#include "include/HyperVisor/Logger/Logger.hpp"
#include "include/HyperVisor/TraceWriter/File.hpp"
#include "include/HyperVisor/TraceWriter/Trace.hpp"
#include "include/HyperVisor/CommonApi/SystemMemory.hpp"

#include <cstdarg>
#include <stdio.h>
#include <CppSupport/CppSupport.hpp>

HyperVisorSvm objHyperVisorSvm;
Log objLog;
File objFile;
Trace objTrace;

uint64_t CounterOfInstrs = 0;
uint64_t FirstSize = 0;
uint64_t SizeOfAll = 0;
std::vector<ULONG_PTR> AddrsFuncs;
std::vector<std::pair<ULONG_PTR, const std::string>>* Funcs;
ULONG_PTR ExitProcesAddr; 
ULONGLONG freeMemory = 0;

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

#define LogBreakpointImmediate(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_BREAKPOINT_MESSAGE, TRUE, false, "[+] BreakPoint(%s:%d) | " format "\n",	\
		 __func__, __LINE__, __VA_ARGS__);	\

// Log without any prefix
#define Log(format, ...)  \
    objLog.LogSendMessageToQueue(OPERATION_LOG_INFO_MESSAGE, false, false, format "\n", __VA_ARGS__)

SVM::PRIVATE_VM_DATA* Interceptions(
	_Inout_ SVM::PRIVATE_VM_DATA* Private)
{
	Private->Guest.ControlArea.InterceptCpuid = TRUE;
	Private->Guest.ControlArea.InterceptVmrun = TRUE;
	Private->Guest.ControlArea.InterceptPushf = TRUE;
	//Private->Guest.ControlArea.InterceptPopf = TRUE;
	Private->Guest.ControlArea.InterceptExceptions.Bitmap.InterceptionVectorDB = TRUE;
	Private->Guest.ControlArea.InterceptExceptions.Bitmap.InterceptionVectorBP = TRUE;
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

void HvSetRflagTrapFlag(_In_ BOOLEAN Set, _In_ SVM::PRIVATE_VM_DATA* Private)
{
	RFLAGS Rflags = { 0 }; 

	//
	// Unset the trap-flag, as we set it before we have to mask it now
	//
	Rflags.Value = Private->Guest.StateSaveArea.Rflags;

	Rflags.Bitmap.Eflags.Bitmap.TF = Set;

	Private->Guest.StateSaveArea.Rflags = Rflags.Value;
}

void VmFuncSetRflagTrapFlag(_In_ BOOLEAN Set, _In_ SVM::PRIVATE_VM_DATA* Private)
{
	HvSetRflagTrapFlag(Set, Private);
}

void KdOnRegularStepInInstruction(_In_ SVM::PRIVATE_VM_DATA* Private)
{
	//RFLAGS Rflags = { 0 };

	//Private->Guest.StateSaveArea.Rflags;

	//Rflags.Value = Private->Guest.StateSaveArea.Rflags;

	//
	// Adjust RFLAG's trap-flag
	//
	VmFuncSetRflagTrapFlag(TRUE, Private);
	//if (Rflags.Bitmap.Eflags.Bitmap.TF)
	//{
	//	VmFuncSetRflagTrapFlag(TRUE, Private);//FALSE
	//}
	//else
	//{
	//	VmFuncSetRflagTrapFlag(TRUE, Private);
	//}
}

void KdOffRegularStepInInstruction(_In_ SVM::PRIVATE_VM_DATA* Private)
{
	//RFLAGS Rflags = { 0 };

	//Private->Guest.StateSaveArea.Rflags;

	//Rflags.Value = Private->Guest.StateSaveArea.Rflags;

	VmFuncSetRflagTrapFlag(FALSE, Private);
}

unsigned char EPBreakpoint; bool BpPass = false;
//bool Entry = false;
//extern unsigned char StolenByte;

extern "C" SVM::VMM_STATUS SvmVmexitHandler(
	_In_ SVM::PRIVATE_VM_DATA* Private,
	_In_ GuestContext* Context)
{
	// Load the host state:
	__svm_vmload(reinterpret_cast<size_t>(Private->VmmStack.Layout.InitialStack.HostVmcbPa));
	// Restore the guest's RAX that was overwritten by host's RAX on #VMEXIT:
	Context->Rax = Private->Guest.StateSaveArea.Rax;

	SVM::VMM_STATUS Status = SVM::VMM_STATUS::VMM_CONTINUE;	

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
	case SVM::SVM_EXIT_CODE::VMEXIT_PUSHF:
	{
		if (((RFLAGS)Private->Guest.StateSaveArea.Rflags).Bitmap.Eflags.Bitmap.VM)
		{
			KeBugCheck(MANUALLY_INITIATED_CRASH);
		}

		if (*(uint8_t*)Private->Guest.StateSaveArea.Rip == 0x66)
		{
			Private->Guest.StateSaveArea.Rsp -= sizeof(uint16_t);

			*(uint16_t*)Private->Guest.StateSaveArea.Rsp = (uint16_t)(((RFLAGS)Private->Guest.StateSaveArea.Rflags).Value & UINT16_MAX);
		}
		else if (Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode)
		{
			Private->Guest.StateSaveArea.Rsp -= sizeof(uintptr_t);
			*(uint64_t*)Private->Guest.StateSaveArea.Rsp = ((RFLAGS)Private->Guest.StateSaveArea.Rflags).Value;
		}
		else if (!Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode)
		{
			Private->Guest.StateSaveArea.Rsp -= sizeof(uint32_t);
			uint32_t value = (uint32_t)(((RFLAGS)Private->Guest.StateSaveArea.Rflags).Value & UINT32_MAX);
			*(uint32_t*)Private->Guest.StateSaveArea.Rsp = value;
		}
		//Private->Guest.StateSaveArea.Rsp -= sizeof(uintptr_t);
		//*(uint64_t*)Private->Guest.StateSaveArea.Rsp = Private->Guest.StateSaveArea.Rflags;

		/*
		KdPrint(("PUSHf\n"));
		if (Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode == 1)
		{
			Private->Guest.StateSaveArea.Rsp -= sizeof(uint64_t);
			*(uint64_t*)Private->Guest.StateSaveArea.Rsp = Private->Guest.StateSaveArea.Rflags;
			//((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.TF = 0;
			//((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.IF = 1;
			//((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.RF = 0;
			//((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.VM = 0;
		}
		else
		{
			Private->Guest.StateSaveArea.Rsp -= sizeof(uint32_t);
			*(uint32_t*)Private->Guest.StateSaveArea.Rsp = ((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Value;
			//((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.TF = 0;
			//((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.IF = 1;
			//((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.RF = 0;
			//((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.VM = 0;
		}
		*/
		break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_POPF:
	{
		//Private->Guest.StateSaveArea.Rflags = *(uint64_t*)Private->Guest.StateSaveArea.Rsp;
		//Private->Guest.StateSaveArea.Rsp += sizeof(uint64_t);

		RFLAGS StackRFlag{0};
		uint32_t OperandSize = 0;

		if (Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode)
		{
			OperandSize = sizeof(uintptr_t);
			StackRFlag.Value = *(uint64_t*)Private->Guest.StateSaveArea.Rsp;
		}
		else if (!Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode)
		{
			OperandSize = sizeof(uint32_t);
			StackRFlag.Value = *(uint32_t*)Private->Guest.StateSaveArea.Rsp;
		}

		if (*(uint8_t*)Private->Guest.StateSaveArea.Rip == 0x66)
		{
			OperandSize = sizeof(uint16_t);
			StackRFlag.Value = *(uint16_t*)Private->Guest.StateSaveArea.Rsp;
			StackRFlag.Value = (uint16_t)StackRFlag.Value | (StackRFlag.Value & 0xffff0000u);
		}
		StackRFlag.Value &= 0x257fd5;
		((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Value |= (uint32_t)(StackRFlag.Value) | 0x02;
		Private->Guest.StateSaveArea.Rsp += OperandSize;

		/*
		KdPrint(("POPf\n"));
		if (Private->Guest.StateSaveArea.Cs.Attrib.Bitmap.LongMode == 1)
		{
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.ZF =
				((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.ZF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.OF = 
				((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.OF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.CF =
				((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.CF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.PF =
				((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.PF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.SF =
				((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.SF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.AF =
				((RFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.Eflags.Bitmap.DF;
			Private->Guest.StateSaveArea.Rsp += sizeof(uint64_t);
		}
		else
		{
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.ZF =
				((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.ZF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.OF =
				((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.OF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.CF =
				((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.CF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.PF =
				((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.PF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.SF =
				((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.SF;
			((RFLAGS*)Private->Guest.StateSaveArea.Rflags)->Bitmap.Eflags.Bitmap.AF =
				((EFLAGS*)Private->Guest.StateSaveArea.Rsp)->Bitmap.DF;
			Private->Guest.StateSaveArea.Rsp += sizeof(uint32_t);
		}
		*/
		break;
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_EXCP_DB:
	{
		++CounterOfInstrs;
		if (Private->Guest.StateSaveArea.Rip != ExitProcesAddr)
		{
			VmFuncSetRflagTrapFlag(TRUE, Private);

			//objTrace.TraceRip(Private);
			objTrace.TraceMnemonic(Private);
		}
		else 
		{
			KdPrint(("ExitProcesAddr!\n"));
			VmFuncSetRflagTrapFlag(FALSE, Private);

			//objTrace.TraceRipFinalization();
			KdPrint(("COUNT OF INSTRS: %p\n", CounterOfInstrs));
			objTrace.TraceMnemonicFinalization();
		}

		if (!Private->Guest.ControlArea.NextRip)
		{
			Private->Guest.StateSaveArea.Rax = Context->Rax;
			return Status;
		} else { break; }
	}
	case SVM::SVM_EXIT_CODE::VMEXIT_EXCP_BP:
	{
		VmFuncSetRflagTrapFlag(TRUE, Private); BpPass = true;
		Private->Guest.StateSaveArea.Rax = Context->Rax;
		return Status;
		//if (!Entry)
		//{
		//	KdOnRegularStepInInstruction(Private); BpPass = true; Entry = true;
		//	Private->Guest.StateSaveArea.Rax = Context->Rax;
		//	return Status;
		//}
		//else
		//{
		//	VmFuncSetRflagTrapFlag(TRUE, Private);
		//	memcpy((void*)Private->Guest.StateSaveArea.Rip, (const void*)&StolenByte, 1);
		//	Private->Guest.StateSaveArea.Rax = Context->Rax;
		//	return Status;
		//}
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

	if (objHyperVisorSvm.IsSvmSupported()) 
	{ 
		objFile.CreateFile(
			L"\\??\\C:\\Trace.out",
			FILE_GENERIC_WRITE,
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
			FILE_OVERWRITE_IF,
			FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
		objHyperVisorSvm.VirtualizeAllProcessors(); 
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

NTSTATUS DrvDispatchIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION IrpStack;
	PREGISTER_EVENT RegisterEvent;
	NTSTATUS Status = STATUS_SUCCESS;
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
	case IOCTL_WRITE:
	{
		//objTrace.AcceptRipMessage(objFile);
		//objTrace.AcceptMnemonicMessage(objFile);
		objTrace.AcceptGraphMessage(objFile);
		//while (TRUE)
		//{
		//	objTrace.AcceptCombineBufferRipMessage(objFile, objTrace.MainBuffer);
		//
		////	if(objTrace.Exit) { objTrace.AcceptCombineBufferRipMessage(objFile, objTrace.MainBuffer); }
		//}
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	case IOCTL_CLOSE_FILE:
	{
		objFile.CloseFile();

		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	case IOCTL_BREAKPOINT_PASS:
	{
		RtlCopyBytes(Irp->AssociatedIrp.SystemBuffer, &BpPass, sizeof(bool));
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
	case IOCTL_EP_BREAKPOINT:
	{
		if (IrpStack->Parameters.DeviceIoControl.InputBufferLength < sizeof(unsigned char) || Irp->AssociatedIrp.SystemBuffer == NULL) {
			Status = STATUS_INVALID_PARAMETER;
			break;
		}

		RtlCopyBytes(&EPBreakpoint, Irp->AssociatedIrp.SystemBuffer, sizeof(unsigned char));

		Irp->IoStatus.Information = sizeof(unsigned char);
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_PE_ANALYZE:
	{
		Funcs = (std::vector<std::pair<ULONG_PTR, const std::string>>*)Irp->AssociatedIrp.SystemBuffer;
		if (Funcs && Funcs->size() > 0)
		{
			for (const auto& pair : *Funcs)
			{
				if (pair.second == "ExitProcess")
				{
					ExitProcesAddr = pair.first;
					KdPrint(("%p\n", ExitProcesAddr)); break;
				}
				AddrsFuncs.push_back(pair.first);
			}
		}
		else { KdPrint(("Funcs is empty or nullptr\n")); }
		Irp->IoStatus.Status = STATUS_SUCCESS;
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		Status = STATUS_SUCCESS;

		break;
	}
	}
	return Status;
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
	if (!objTrace.TraceInitializeMnemonic()) { DbgPrint("[*] Trace buffer is not initialized !\n"); DbgBreakPoint(); }

	RtlInitUnicodeString(&DriverName, L"\\Device\\MyHypervisorDevice");
	RtlInitUnicodeString(&DosDeviceName, L"\\DosDevices\\MyHypervisorDevice");
	
	Ntstatus = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	__crt_init();
	if (Ntstatus == STATUS_SUCCESS)
	{
		for (UINT64 Index = 0; Index < IRP_MJ_MAXIMUM_FUNCTION; Index++) 
		{ DriverObject->MajorFunction[Index] = DrvUnsupported; }

		DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
		DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
		DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DrvDispatchIoControl;
		DriverObject->DriverUnload = DrvUnload;
		IoCreateSymbolicLink(&DosDeviceName, &DriverName);
	}

	return STATUS_SUCCESS;
}