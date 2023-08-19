#include <ntddk.h>

#include "GuestContext.hpp"
#include "include/HyperVisor/HyperVisor.hpp"

HyperVisorSvm objHyperVisorSvm;

void DriverUnload(_In_ PDRIVER_OBJECT DriverObj)
{
	UNREFERENCED_PARAMETER(DriverObj);
	KdPrint(("Sample driver Unload called\n"));
}

SVM::PRIVATE_VM_DATA* Interceptions(
	_Inout_ SVM::PRIVATE_VM_DATA* Private)
{
	Private->Guest.ControlArea.InterceptVmrun = TRUE;
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
	
	switch (Private->Guest.ControlArea.ExitCode)
	{
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
	}
	
	KdPrint(("Exit code %p\n", Private->Guest.ControlArea.ExitCode));

	Private->Guest.StateSaveArea.Rax = Context->Rax;

	// Go to the next instruction:
	Private->Guest.StateSaveArea.Rip = Private->Guest.ControlArea.NextRip;

	return Status;
}

//Define in asm file(in my example)
extern "C" void SvmVmmRun(_In_ void* InitialVmmStackPointer);

extern "C" NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObj, PUNICODE_STRING RegisterPath)
{
	UNREFERENCED_PARAMETER(RegisterPath);

	objHyperVisorSvm.PInterceptions = &Interceptions;
	objHyperVisorSvm.PSvmVmmRun = &SvmVmmRun;

	if (objHyperVisorSvm.IsSvmSupported()) { objHyperVisorSvm.VirtualizeAllProcessors(); }
	DriverObj->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}
