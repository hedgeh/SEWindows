#include "main.h"
#include "filemon.h"
#include "processmon.h"
#include "regmon.h"
#include <Strsafe.h>


PDEVICE_OBJECT              g_DevObj = NULL;
BOOLEAN						g_bHipsInit = FALSE;
HANDLE						g_currentPid = NULL;
BOOLEAN						g_is_reg_run = FALSE;
BOOLEAN						g_is_proc_run = FALSE;
BOOLEAN						g_is_file_run = FALSE;
PDRIVER_OBJECT				g_DriverObject = NULL;
WCHAR						g_device_name[MAXNAMELEN];
WCHAR						g_symbol_name[MAXNAMELEN];
WCHAR						g_port_name[MAXNAMELEN];
WCHAR						g_service_name[MAXNAMELEN];
BOOLEAN						g_is_unload_allowed = FALSE;
BOOLEAN						g_is_notify_mode = TRUE;
PBOOLEAN					p = &g_is_proc_run;


DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD   PtDeviceUnload;
NTSTATUS
DriverEntry (
     PDRIVER_OBJECT DriverObject,
     PUNICODE_STRING RegistryPath
    );

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#endif


NTSTATUS dispatch_create(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	static BOOLEAN bFirst = TRUE;
	PAGED_CODE();
	if (!g_bHipsInit)
	{
		status = STATUS_UNSUCCESSFUL;
	}

	if (bFirst)
	{
		g_currentPid = PsGetCurrentProcessId();
		bFirst = FALSE;
	}
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS dispatch_close(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	NTSTATUS status = STATUS_SUCCESS;
	PAGED_CODE();

	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS dispatch_ictl(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{

	NTSTATUS			status = STATUS_SUCCESS;
	PIO_STACK_LOCATION	irpStack;
	PVOID				ioBuf;
	ULONG				inBufLength, outBufLength;
	ULONG				ioControlCode;

	PAGED_CODE();

	if (g_currentPid != PsGetCurrentProcessId())
	{
		goto retLable;
	}
	irpStack = IoGetCurrentIrpStackLocation(pIrp);
	pIrp->IoStatus.Information = 0;
	ioBuf = pIrp->AssociatedIrp.SystemBuffer;
	inBufLength = irpStack->Parameters.DeviceIoControl.InputBufferLength;
	outBufLength = irpStack->Parameters.DeviceIoControl.OutputBufferLength;
	ioControlCode = irpStack->Parameters.DeviceIoControl.IoControlCode;
	
	switch (ioControlCode)
	{
	case IOCTL_START_PROCMONITOR:
		g_is_proc_run = TRUE;
		break;
	case IOCTL_PAUSE_PROCMONITOR:
		g_is_proc_run = FALSE;
		break;
	case IOCTL_START_FILEMONITOR:
		g_is_file_run = TRUE;
		break;
	case IOCTL_PAUSE_FILEMONITOR:
		g_is_file_run = FALSE;
		break;
	case IOCTL_STOP_ALL:
		g_is_reg_run = FALSE;
		g_is_proc_run = FALSE;
		g_is_file_run = FALSE;
		break;
	case IOCTL_START_ALL:
		g_is_reg_run = TRUE;
		g_is_proc_run = TRUE;
		g_is_file_run = TRUE;
		break;
	case IOCTL_PAUSE_REGMONITOR:
		g_is_reg_run = FALSE;
		break;
	case IOCTL_START_REGMONITOR:
		g_is_reg_run = TRUE;
		break;
	case IOCTL_STOP_UNLOAD:
		g_is_unload_allowed = FALSE;
		break;
	case IOCTL_PERMIT_UNLOAD:
		g_is_unload_allowed = TRUE;
		break;
	case IOCTL_SET_INTERCEPT_MODE:
		g_is_notify_mode = FALSE;
		break;
	case IOCTL_SET_NOTIFY_MODE:
		g_is_notify_mode = TRUE;
		break;
	default:
		break;
	}
retLable:
	pIrp->IoStatus.Status = status;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return status;
}

NTSTATUS irp_shutdown(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNICODE_STRING deviceDosName;

	g_is_file_run = FALSE;
	g_is_proc_run = FALSE;
	g_is_reg_run = FALSE;

	sw_register_uninit(g_DriverObject);
#if (NTDDI_VERSION >= NTDDI_VISTA)
	sw_uninit_procss(g_DriverObject);
#endif
	sw_uninit_minifliter(g_DriverObject);

	if (g_DevObj)
	{
		IoUnregisterShutdownNotification(g_DevObj);
		IoDeleteDevice(g_DevObj);
		g_DevObj = NULL;
	}
	RtlInitUnicodeString(&deviceDosName, g_symbol_name);
	IoDeleteSymbolicLink(&deviceDosName);
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING deviceDosName;

	g_is_file_run = FALSE;
	g_is_proc_run = FALSE;
	g_is_reg_run = FALSE;

	sw_register_uninit(g_DriverObject);
#if (NTDDI_VERSION >= NTDDI_VISTA)
	sw_uninit_procss(g_DriverObject);
#endif
	sw_uninit_minifliter(g_DriverObject);

	if (g_DevObj)
	{
		IoUnregisterShutdownNotification(g_DevObj);
		IoDeleteDevice(g_DevObj);
		g_DevObj = NULL;
	}
	RtlInitUnicodeString(&deviceDosName, g_symbol_name);
	IoDeleteSymbolicLink(&deviceDosName);
}

NTSTATUS irp_pass(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(Irp, IO_NETWORK_INCREMENT);
	return STATUS_SUCCESS;
}

BOOLEAN load_global_config(PUNICODE_STRING registryPath)
{
	NTSTATUS			status;
	OBJECT_ATTRIBUTES	objectAttributes;
	UNICODE_STRING		valueName;
	ULONG				resultLength;
	HANDLE				hKey = NULL;
	KEY_VALUE_PARTIAL_INFORMATION* regValue = NULL;
	UCHAR				buffer[512];
	regValue = (KEY_VALUE_PARTIAL_INFORMATION*)buffer;

	InitializeObjectAttributes(&objectAttributes,registryPath,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,NULL);

	status = ZwOpenKey(&hKey,KEY_READ,&objectAttributes);
	if (!NT_SUCCESS(status))
	{
		return FALSE;
	}
	RtlInitUnicodeString(&valueName,L"service_name");
	RtlZeroMemory(buffer, 512);
	status = ZwQueryValueKey(hKey, &valueName, KeyValuePartialInformation, buffer, 512, &resultLength);
	if (!NT_SUCCESS(status) || regValue->Type != REG_SZ || resultLength >= MAXNAMELEN)
	{
		ZwClose(hKey);
		return FALSE;
	}

	StringCbCopyNW(g_service_name, MAXNAMELEN*sizeof(WCHAR), (WCHAR*)regValue->Data, regValue->DataLength);

	StringCbCopyW(g_device_name, MAXNAMELEN*sizeof(WCHAR), _DEVICE_NAME);
	StringCbCatNW(g_device_name, MAXNAMELEN*sizeof(WCHAR), (WCHAR*)regValue->Data, regValue->DataLength);
	
	StringCbCopyW(g_symbol_name, MAXNAMELEN*sizeof(WCHAR), _DEVICE_DOSNAME);
	StringCbCatNW(g_symbol_name, MAXNAMELEN*sizeof(WCHAR), (WCHAR*)regValue->Data, regValue->DataLength);

	StringCbCopyW(g_port_name, MAXNAMELEN*sizeof(WCHAR), L"\\");
	StringCbCatNW(g_port_name, MAXNAMELEN*sizeof(WCHAR), (WCHAR*)regValue->Data, regValue->DataLength);
	

	ZwClose(hKey);
	return TRUE;
}


NTSTATUS
DriverEntry (
     PDRIVER_OBJECT DriverObject,
     PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    
	BOOLEAN bNeedToDelDevice = FALSE;
	BOOLEAN bNeedToDelSym = FALSE;
	BOOLEAN bNeedToUninitMinifilter = FALSE;
	BOOLEAN bNeedToUninitProcmon = FALSE;
	BOOLEAN bNeedToUninitRegmon = FALSE;
	BOOLEAN bNeedToUnregShutdown = FALSE;
	UNICODE_STRING  deviceName = {0};
	UNICODE_STRING  deviceDosName = {0};
	int nIndex = 0;

	UNREFERENCED_PARAMETER( RegistryPath );

#ifdef DBG
	__debugbreak();
#endif
	
	g_DriverObject = DriverObject;
	if (!load_global_config(RegistryPath))
	{
		return status;
	}

	for (; nIndex < IRP_MJ_MAXIMUM_FUNCTION; ++nIndex)
	{
		DriverObject->MajorFunction[nIndex] = irp_pass;
	}
	DriverObject->DriverUnload = DriverUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = dispatch_create;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = dispatch_close;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatch_ictl;
	DriverObject->MajorFunction[IRP_MJ_SHUTDOWN] = irp_shutdown;


	RtlInitUnicodeString(&deviceName, g_device_name);
	status = IoCreateDevice(DriverObject,
		0,
		&deviceName,
		FILE_DEVICE_NETWORK,
		0,
		FALSE,
		&g_DevObj);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToDelDevice = TRUE;

	status = IoRegisterShutdownNotification(g_DevObj);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUnregShutdown = TRUE;


	RtlInitUnicodeString(&deviceDosName, g_symbol_name);
	status = IoCreateSymbolicLink(&deviceDosName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Create Symbolink name failed!\n"));
		goto err_ret;
	}

	bNeedToDelSym = TRUE;
	status = sw_init_minifliter(DriverObject);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUninitMinifilter = TRUE;
#if (NTDDI_VERSION >= NTDDI_VISTA)
	status = sw_init_procss(DriverObject);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUninitProcmon = TRUE;
#endif
	status = sw_register_init(DriverObject);
	if (!NT_SUCCESS(status))
	{
		goto err_ret;
	}
	bNeedToUninitRegmon = TRUE;
	g_bHipsInit = TRUE;
    return status;
err_ret:
	g_is_reg_run = FALSE;
	g_is_file_run = FALSE;
	g_is_proc_run = FALSE;

	if (bNeedToUnregShutdown)
	{
		IoUnregisterShutdownNotification(g_DevObj);
	}

	if (bNeedToDelSym)
	{
		RtlInitUnicodeString(&deviceDosName, g_symbol_name);
		IoDeleteSymbolicLink(&deviceDosName);
	}

	if (bNeedToDelDevice)
	{
		IoDeleteDevice(g_DevObj);
		g_DevObj = NULL;
	}

	if (bNeedToUninitRegmon)
	{
		sw_register_uninit(DriverObject);
	}
#if (NTDDI_VERSION >= NTDDI_VISTA)
	if (bNeedToUninitProcmon)
	{
		sw_uninit_procss(DriverObject);
	}
#endif
	if (bNeedToUninitMinifilter)
	{
		sw_uninit_minifliter(DriverObject);
	}
	return status;
}
