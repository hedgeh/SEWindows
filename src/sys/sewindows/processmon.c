#include "main.h"
#include "processmon.h"
#include "lpc.h"
#include "regmon.h"
#include "filemon.h"
#include <strsafe.h>


#if (NTDDI_VERSION >= NTDDI_VISTA)

PVOID						g_proc_callback_handle = NULL;
OB_CALLBACK_REGISTRATION	g_proc_callback = { 0 };
OB_OPERATION_REGISTRATION	g_operation_registration[2] = { { 0 }, { 0 } };
static BOOLEAN				g_bSetCreateProcessNotify = FALSE;

OB_PREOP_CALLBACK_STATUS pre_procopration_callback( PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	HIPS_RULE_NODE	Pi;
	HANDLE			target_pid = NULL;
	ACCESS_MASK		OriginalDesiredAccess = 0;
	PACCESS_MASK	DesiredAccess = NULL;

	if (pOperationInformation->KernelHandle == TRUE || g_is_proc_run == FALSE)
	{
		return OB_PREOP_SUCCESS;
	}

	if (pOperationInformation->ObjectType == *PsThreadType)
	{
		target_pid = PsGetThreadProcessId ((PETHREAD)pOperationInformation->Object);
	}
	else if (pOperationInformation->ObjectType == *PsProcessType)
	{
		target_pid = PsGetProcessId((PEPROCESS)pOperationInformation->Object);
	}
	else
	{
		return OB_PREOP_SUCCESS;
	}

	if ((PsGetCurrentProcessId() == target_pid))
	{
		return OB_PREOP_SUCCESS;
	}

	switch (pOperationInformation->Operation) 
	{
	case OB_OPERATION_HANDLE_CREATE:
		DesiredAccess = &pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess;
		OriginalDesiredAccess = pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		break;
	case OB_OPERATION_HANDLE_DUPLICATE:
		DesiredAccess = &pOperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess;
		OriginalDesiredAccess = pOperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
		break;
	default:
		return OB_PREOP_SUCCESS;
	}

	RtlZeroMemory(&Pi, sizeof(HIPS_RULE_NODE));
	Pi.major_type = PROC_OP;
	Pi.sub_pid = PsGetCurrentProcessId();		

	Pi.obj_pid = target_pid;		

	if (pOperationInformation->ObjectType == *PsProcessType)
	{
		if ((OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
		{
			//	杀死进程
			Pi.minor_type = OP_PROC_KILL;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_TERMINATE;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_CREATE_THREAD) == PROCESS_CREATE_THREAD)
		{	//	远程线程创建
			Pi.minor_type = OP_PROC_CREATE_REMOTE_THREAD;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_CREATE_THREAD;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
		{	//	修改内存属性
			Pi.minor_type = OP_PROC_CHANGE_VM;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_VM_OPERATION;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
		{	//	读内存
			Pi.minor_type = OP_PROC_READ_PROCESS;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_VM_READ;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
		{	//	写内存
			Pi.minor_type = OP_PROC_WRITE_PROCESS;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
		if ((OriginalDesiredAccess & PROCESS_SUSPEND_RESUME) == PROCESS_SUSPEND_RESUME)
		{	
			Pi.minor_type = OP_PROC_SUSPEND_RESUME;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
			}
		}

		if ((OriginalDesiredAccess & PROCESS_DUP_HANDLE) == PROCESS_DUP_HANDLE)
		{	
			Pi.minor_type = OP_PROC_DUPHANDLE;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~PROCESS_DUP_HANDLE;
			}
		}
	}
	else
	{
		if ((OriginalDesiredAccess & THREAD_SUSPEND_RESUME) == THREAD_SUSPEND_RESUME)
		{	
			Pi.minor_type = OP_THREAD_SUSPEND_RESUME;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~THREAD_SUSPEND_RESUME;
			}
		}

		if ((OriginalDesiredAccess & THREAD_GET_CONTEXT) == THREAD_GET_CONTEXT)
		{	
			Pi.minor_type = OP_THREAD_GET_CONTEXT;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~THREAD_GET_CONTEXT;
			}
		}

		if ((OriginalDesiredAccess & THREAD_SET_CONTEXT) == THREAD_SET_CONTEXT)
		{	
			Pi.minor_type = OP_THREAD_SET_CONTEXT;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~THREAD_SET_CONTEXT;
			}
		}

		if ((OriginalDesiredAccess & THREAD_TERMINATE) == THREAD_TERMINATE)
		{	
			Pi.minor_type = OP_THREAD_KILL;
			if (rule_match(&Pi) == FALSE)
			{
				*DesiredAccess &= ~THREAD_TERMINATE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

VOID create_process_notity_routine( PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	HIPS_RULE_NODE Pi;
	RtlZeroMemory(&Pi, sizeof(HIPS_RULE_NODE));
	Pi.major_type = PROC_OP;

	if (g_is_proc_run == FALSE)
	{
		return;
	}

	if (CreateInfo != NULL)
	{
		Pi.sub_pid = CreateInfo->ParentProcessId;
		Pi.obj_pid = ProcessId;
		Pi.minor_type = OP_PROC_CREATE_PROCESS;
		StringCbCopyNW(Pi.des_path, sizeof(Pi.des_path), CreateInfo->ImageFileName->Buffer, CreateInfo->ImageFileName->Length);
		if (rule_match(&Pi) == FALSE)
		{
			CreateInfo->CreationStatus = STATUS_UNSUCCESSFUL;
		}
	}
	else
	{
		if (g_current_pid == ProcessId)
		{
			g_is_file_run = FALSE;
			g_is_proc_run = FALSE;
			g_is_reg_run = FALSE;

		}
	}
}

NTSTATUS sw_init_procss(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS					Status = STATUS_SUCCESS;
	UNICODE_STRING				altitude = { 0 };
	WCHAR						szBuffer[20];
	ULONGLONG					ul_altitude = 1000;
	Status = PsSetCreateProcessNotifyRoutineEx(create_process_notity_routine,FALSE);
	if (NT_SUCCESS(Status))
	{
		g_bSetCreateProcessNotify = TRUE;

		g_operation_registration[0].ObjectType = PsProcessType;
		g_operation_registration[0].Operations |= OB_OPERATION_HANDLE_CREATE;
		g_operation_registration[0].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
		g_operation_registration[0].PreOperation = pre_procopration_callback;

		g_operation_registration[1].ObjectType = PsThreadType;
		g_operation_registration[1].Operations |= OB_OPERATION_HANDLE_CREATE;
		g_operation_registration[1].Operations |= OB_OPERATION_HANDLE_DUPLICATE;
		g_operation_registration[1].PreOperation = pre_procopration_callback;
		g_proc_callback.Version = OB_FLT_REGISTRATION_VERSION;
		g_proc_callback.OperationRegistrationCount = 2;
		g_proc_callback.RegistrationContext = NULL;
		g_proc_callback.OperationRegistration = g_operation_registration;

try_again:
		RtlZeroMemory(szBuffer, sizeof(szBuffer));
		RtlInitEmptyUnicodeString(&altitude, szBuffer, 20 * sizeof(WCHAR));
		RtlInt64ToUnicodeString(ul_altitude, 10, &altitude);
		g_proc_callback.Altitude = altitude;
		Status = ObRegisterCallbacks(
			&g_proc_callback,
			&g_proc_callback_handle       
			);
		if (NT_SUCCESS(Status))
		{
			return Status;
		}

		if (STATUS_FLT_INSTANCE_ALTITUDE_COLLISION == Status)
		{
			ul_altitude++;
			if (ul_altitude<100000)
			{
				goto try_again;
			}
		}
		PsSetCreateProcessNotifyRoutineEx(create_process_notity_routine, TRUE);
		g_bSetCreateProcessNotify = FALSE;
	}
	return Status;
}

NTSTATUS sw_uninit_procss(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS Status = STATUS_SUCCESS;
	if (g_bSetCreateProcessNotify)
	{
		Status = PsSetCreateProcessNotifyRoutineEx(create_process_notity_routine, TRUE);
		g_bSetCreateProcessNotify = FALSE;
	}

	if (g_proc_callback_handle)
	{
		ObUnRegisterCallbacks(g_proc_callback_handle);
		g_proc_callback_handle = NULL;
	}
	return Status;
}

#else

#ifndef _WIN64

#include <ntimage.h>

#pragma pack(1)
typedef struct ServiceDescriptorEntry {
	unsigned int *ServiceTableBase;
	unsigned int *ServiceCounterTableBase; //Used only in checked build
	unsigned int NumberOfServices;
	unsigned char *ParamTableBase;
} ServiceDescriptorTableEntry_t, *PServiceDescriptorTableEntry_t;
#pragma pack()

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG		Reserved[2];
	PVOID		Base;
	ULONG		Size;
	ULONG		Flags;
	USHORT		Index;
	USHORT		Unknown;
	USHORT		LoadCount;
	USHORT		ModNameOffset;
	CHAR		ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYS_MOD_INFO {
	ULONG	NumberOfModules;
	SYSTEM_MODULE_INFORMATION Module[1];
} SYS_MOD_INFO, *PSYS_MOD_INFO;


typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation, // 0 Y N
	SystemProcessorInformation, // 1 Y N
	SystemPerformanceInformation, // 2 Y N
	SystemTimeOfDayInformation, // 3 Y N
	SystemNotImplemented1, // 4 Y N
	SystemProcessesAndThreadsInformation, // 5 Y N
	SystemCallCounts, // 6 Y N
	SystemConfigurationInformation, // 7 Y N
	SystemProcessorTimes, // 8 Y N
	SystemGlobalFlag, // 9 Y Y
	SystemNotImplemented2, // 10 Y N
	SystemModuleInformation, // 11 Y N
	SystemLockInformation, // 12 Y N
	SystemNotImplemented3, // 13 Y N
	SystemNotImplemented4, // 14 Y N
	SystemNotImplemented5, // 15 Y N
	SystemHandleInformation, // 16 Y N
	SystemObjectInformation, // 17 Y N
	SystemPagefileInformation, // 18 Y N
	SystemInstructionEmulationCounts, // 19 Y N
	SystemInvalidInfoClass1, // 20
	SystemCacheInformation, // 21 Y Y
	SystemPoolTagInformation, // 22 Y N
	SystemProcessorStatistics, // 23 Y N
	SystemDpcInformation, // 24 Y Y
	SystemNotImplemented6, // 25 Y N
	SystemLoadImage, // 26 N Y
	SystemUnloadImage, // 27 N Y
	SystemTimeAdjustment, // 28 Y Y
	SystemNotImplemented7, // 29 Y N
	SystemNotImplemented8, // 30 Y N
	SystemNotImplemented9, // 31 Y N
	SystemCrashDumpInformation, // 32 Y N
	SystemExceptionInformation, // 33 Y N
	SystemCrashDumpStateInformation, // 34 Y Y/N
	SystemKernelDebuggerInformation, // 35 Y N
	SystemContextSwitchInformation, // 36 Y N
	SystemRegistryQuotaInformation, // 37 Y Y
	SystemLoadAndCallImage, // 38 N Y
	SystemPrioritySeparation, // 39 N Y
	SystemNotImplemented10, // 40 Y N
	SystemNotImplemented11, // 41 Y N
	SystemInvalidInfoClass2, // 42
	SystemInvalidInfoClass3, // 43
	SystemTimeZoneInformation, // 44 Y N
	SystemLookasideInformation, // 45 Y N
	SystemSetTimeSlipEvent, // 46 N Y
	SystemCreateSession, // 47 N Y
	SystemDeleteSession, // 48 N Y
	SystemInvalidInfoClass4, // 49
	SystemRangeStartInformation, // 50 Y N
	SystemVerifierInformation, // 51 Y Y
	SystemAddVerifier, // 52 N Y
	SystemSessionProcessesInformation // 53 Y N
} SYSTEM_INFORMATION_CLASS;

typedef struct _PORT_MESSAGE
{
     ULONG u1;
     ULONG u2;
     union
     {
          CLIENT_ID ClientId;
		  float DoNotUseThisField;
     };
     ULONG MessageId;
     union
     {
          ULONG ClientViewSize;
          ULONG CallbackId;
     };
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct _LPCP_NONPAGED_PORT_QUEUE {
    KSEMAPHORE Semaphore;       // Counting semaphore that is incremented
                                // whenever a message is put in receive queue
    struct _LPCP_PORT_OBJECT *BackPointer;
} LPCP_NONPAGED_PORT_QUEUE, *PLPCP_NONPAGED_PORT_QUEUE;

typedef struct _LPCP_PORT_QUEUE {
    PLPCP_NONPAGED_PORT_QUEUE NonPagedPortQueue;
    PKSEMAPHORE Semaphore;      // Counting semaphore that is incremented
                                // whenever a message is put in receive queue
    LIST_ENTRY ReceiveHead;     // list of messages to receive
} LPCP_PORT_QUEUE, *PLPCP_PORT_QUEUE;

typedef struct _LPCP_PORT_OBJECT {
    struct _LPCP_PORT_OBJECT *ConnectionPort;
    struct _LPCP_PORT_OBJECT *ConnectedPort;
    LPCP_PORT_QUEUE MsgQueue;
    CLIENT_ID Creator;
    PVOID ClientSectionBase;
    PVOID ServerSectionBase;
    PVOID PortContext;
    PETHREAD ClientThread;                  // only SERVER_COMMUNICATION_PORT
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SECURITY_CLIENT_CONTEXT StaticSecurity;
    LIST_ENTRY LpcReplyChainHead;           // Only in _COMMUNICATION ports
    LIST_ENTRY LpcDataInfoChainHead;        // Only in _COMMUNICATION ports
    union {
        PEPROCESS ServerProcess;                // Only in SERVER_CONNECTION ports
        PEPROCESS MappingProcess;               // Only in _COMMUNICATION    ports
    };
    USHORT MaxMessageLength;
    USHORT MaxConnectionInfoLength;
    ULONG Flags;
    KEVENT WaitEvent;                          // Object is truncated for non-waitable ports
} LPCP_PORT_OBJECT, *PLPCP_PORT_OBJECT;

__declspec(dllimport)  ServiceDescriptorTableEntry_t KeServiceDescriptorTable;

#define SYSTEMSERVICE_BY_FUNC_ID(_func_id)				KeServiceDescriptorTable.ServiceTableBase[_func_id]
#define VALID_RVA(__rva1__, __hdr1__)					(GetEnclosingSectionHeader(__rva1__, __hdr1__)?TRUE:FALSE)
#define PTR_FROM_RVA(__img_base__, __hdr__, __rva__)	(VALID_RVA(__rva__, __hdr__)?(PCHAR)__img_base__+(ULONG_PTR)__rva__:NULL)
#define RVA_FROM_PTR(__img_base__, __ptr__)				((ULONG)((ULONG_PTR)__ptr__-(ULONG_PTR)__img_base__))
#define IMG_DIR_ENTRY_RVA(__hdr__, __i__)				(__hdr__->OptionalHeader.DataDirectory[__i__].VirtualAddress)
#define IMG_DIR_ENTRY_SIZE(__hdr__, __i__)				(__hdr__->OptionalHeader.DataDirectory[__i__].Size)
#define PAGE_BASE(__ptr__)								((ULONG_PTR)__ptr__ & ~((ULONG_PTR)PAGE_SIZE-1LL))
#define PAGE_OFFSET(__ptr__)							((ULONG_PTR)__ptr__ & ((ULONG_PTR)PAGE_SIZE-1LL))

NTSYSAPI
NTSTATUS
NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTSTATUS (__stdcall *real_NtTerminateProcess)( 
	__in HANDLE ProcessHandle,
	__in ULONG ProcessExitCode
	);

NTSTATUS (__stdcall *real_NtCreateThread) (
	__out PHANDLE ThreadHandle,
	__in ACCESS_MASK DesiredAccess, 
	__in_opt POBJECT_ATTRIBUTES ObjectAttributes,
	__in HANDLE ProcessHandle,
	__out PCLIENT_ID ClientID, 
	__in PCONTEXT Context,
	__in /*PUSER_STACK*/PVOID StackInfo,
	__in BOOLEAN CreateSuspended
	);


NTSTATUS ( NTAPI *real_NtRequestWaitReplyPort)(
	__in HANDLE PortHandle,
	__in PPORT_MESSAGE RequestMessage,
	__out PPORT_MESSAGE ReplyMessage
	) = NULL;

static PVOID	g_BaseOfNtDllDll = 0;
static ULONG	g_NtTerminateProcess_index = MAXULONG;
static ULONG	g_NtCreateThread_index = MAXULONG;
static ULONG	g_NtRequestWaitReplyPort_index = MAXULONG;

ULONG CheckException ()
{
	return EXCEPTION_EXECUTE_HANDLER;
}


NTSTATUS Sys_GetProcessIdByHandle (HANDLE ProcessHandle, PHANDLE pProcessId)
{
	NTSTATUS status;
	PROCESS_BASIC_INFORMATION ProcInfo;

	if (!ProcessHandle || UlongToHandle( -1 ) == ProcessHandle)
	{
		return STATUS_UNSUCCESSFUL;
	}

	status = g_ZwQueryInformationProcess (ProcessHandle,ProcessBasicInformation,&ProcInfo,sizeof(ProcInfo),NULL);

	if (NT_SUCCESS( status ))
	{
#ifdef _WIN64
		*pProcessId = (HANDLE) ProcInfo.UniqueProcessId;
#else
		*pProcessId = ULongToHandle( ProcInfo.UniqueProcessId );
#endif
	}
	return status;
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(ULONG RVA, PIMAGE_NT_HEADERS pNtHeader)
{
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeader);
    ULONG i;
    
    for (i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++, pSection++)
    {
		ULONG SectionSize = pSection->Misc.VirtualSize;
		if (0 == SectionSize)
		{
			SectionSize = pSection->SizeOfRawData;
		}
			
        if ( RVA >= pSection->VirtualAddress && RVA <  pSection->VirtualAddress+SectionSize)
		{
			return pSection;
		}
    }
    return NULL;
}


PVOID GetExport(IN PVOID ImageBase, IN PCHAR NativeName, OUT PVOID *p_ExportAddr OPTIONAL, OUT PULONG pNativeSize OPTIONAL) 
{
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	ULONG					i;
	PULONG					pFunctionRVAs;
	PUSHORT					pOrdinals;
	PULONG					pFuncNameRVAs;
	ULONG					exportsStartRVA;
	PIMAGE_DOS_HEADER		pDosHeader;
	PIMAGE_NT_HEADERS		pNTHeader;

	__try
	{
		pDosHeader= (PIMAGE_DOS_HEADER)ImageBase;
		if(pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			return NULL;
		}

		pNTHeader = (PIMAGE_NT_HEADERS)((PCHAR)ImageBase+pDosHeader->e_lfanew);
		if(pNTHeader->Signature != IMAGE_NT_SIGNATURE)
		{
			return NULL;
		}
			
		exportsStartRVA = IMG_DIR_ENTRY_RVA(pNTHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);
		pExportDir = (PIMAGE_EXPORT_DIRECTORY)PTR_FROM_RVA(ImageBase, pNTHeader, exportsStartRVA);
		if (!pExportDir)
		{
			return NULL;
		}
	
		pFunctionRVAs = (PULONG)PTR_FROM_RVA(ImageBase, pNTHeader, pExportDir->AddressOfFunctions);
		if (!pFunctionRVAs)
		{
			return NULL;
		}
			
		pOrdinals = (PUSHORT)PTR_FROM_RVA(ImageBase, pNTHeader, pExportDir->AddressOfNameOrdinals);
		if (!pOrdinals)
		{
			return NULL;
		}
			
		pFuncNameRVAs = (PULONG)PTR_FROM_RVA(ImageBase, pNTHeader, pExportDir->AddressOfNames);
		if (!pFuncNameRVAs)
		{
			return NULL;
		}
			

		for (i = 0; i < pExportDir->NumberOfNames; i++)
		{
			PCHAR FuncName;
			ULONG FuncNameRVA = pFuncNameRVAs[i];

			FuncName = PTR_FROM_RVA(ImageBase, pNTHeader, FuncNameRVA);
			if (!FuncName)
			{
				continue;
			}
				
			if(0 == strcmp(FuncName, NativeName))
			{
				USHORT Ordinal = pOrdinals[i];
				ULONG FuncRVA  = pFunctionRVAs[Ordinal];
				
				if(p_ExportAddr)
				{
					*p_ExportAddr = &pFunctionRVAs[Ordinal];
				}
					
				if (pNativeSize)
				{
					ULONG j;
					ULONG MinRVA = MAXULONG;

					for (j = 0; j < pExportDir->NumberOfFunctions; j++)
					{
						ULONG CurrRVA = pFunctionRVAs[j];

						if (CurrRVA > FuncRVA && CurrRVA < MinRVA)
						{
							MinRVA = CurrRVA;
						}
					}

					*pNativeSize = MinRVA-FuncRVA;
				}

				return PTR_FROM_RVA(ImageBase, pNTHeader, FuncRVA);
			}
		}
	}
	__except(CheckException())
	{
		return NULL;
	}
	return NULL;
}


PVOID GetNativeBase (PCHAR DllName)
{
	ULONG		BufLen;
	ULONG		i;
	PVOID		ret = NULL;
	PULONG		qBuff;
	PSYSTEM_MODULE_INFORMATION Mod;

	NTSTATUS status = ZwQuerySystemInformation( 11, &BufLen, 0, &BufLen );
	if (STATUS_INFO_LENGTH_MISMATCH != status || !BufLen)
	{
		return NULL;
	}
		
	qBuff = ExAllocatePoolWithTag( PagedPool, BufLen, 'HOOK' );
	if(!qBuff)
	{
		return NULL;
	}
		
	status = ZwQuerySystemInformation( 11, qBuff, BufLen, NULL );
	if(NT_SUCCESS( status ))
	{
		Mod = (PSYSTEM_MODULE_INFORMATION)( qBuff + 1 );
		for(i = 0; i < *qBuff; i++)
		{
			if(!_stricmp( Mod[i].ImageName + Mod[i].ModNameOffset, DllName ))
			{
				ret = Mod[i].Base;
				break;
			}
		}
	}
	ExFreePool( qBuff );
	return ret;
}

ULONG GetNativeID (__in PVOID NativeBase,__in PSTR NativeName)
{
	PVOID NativeEP;
	PVOID paddr = 0;
	
	if (!NativeBase)
	{
		return 0;
	}

	NativeEP = GetExport(NativeBase, NativeName, &paddr, NULL);
	if(NativeEP)
	{
		if(((UCHAR*)NativeEP)[0] == 0xB8) // MOV EAX,XXXXXXXX?
		{
			return ((ULONG*)((PCHAR)NativeEP+1))[0];
		}
	}
	return 0;
}

NTSTATUS
__stdcall
fake_NtTerminateProcess ( __in HANDLE ProcessHandle, __in ULONG ProcessExitCode )
{
	NTSTATUS		status;
	HIPS_RULE_NODE	Pi;
	HANDLE			hDestProcessId;

	if (ExGetPreviousMode() == KernelMode || 
		KeGetCurrentIrql() >= DISPATCH_LEVEL || 
		g_is_proc_run == FALSE ||
		PsGetCurrentProcessId() == (HANDLE)4 || 
		PsGetCurrentProcessId() == (HANDLE)0 ||
		ProcessHandle == UlongToHandle(-1)
		)
	{
		return real_NtTerminateProcess( ProcessHandle, ProcessExitCode );
	}

	if (is_process_in_white_list(PsGetCurrentProcessId()))
	{
		return real_NtTerminateProcess( ProcessHandle, ProcessExitCode );
	}

	if (!NT_SUCCESS( Sys_GetProcessIdByHandle( ProcessHandle, &hDestProcessId ) ))
	{
		return real_NtTerminateProcess( ProcessHandle, ProcessExitCode );
	}

	RtlZeroMemory(&Pi, sizeof(HIPS_RULE_NODE));
	Pi.major_type = PROC_OP;
	Pi.sub_pid = PsGetCurrentProcessId();		
	Pi.obj_pid = hDestProcessId;		
	Pi.minor_type = OP_PROC_KILL;

	if (rule_match(&Pi) == FALSE)
	{
		return STATUS_ACCESS_DENIED;
	}
	else
	{
		return real_NtTerminateProcess( ProcessHandle, ProcessExitCode );
	}
}

NTSTATUS
__stdcall
fake_NtCreateThread (
				 __out PHANDLE ThreadHandle,
				 __in ACCESS_MASK DesiredAccess, 
				 __in_opt POBJECT_ATTRIBUTES ObjectAttributes,
				 __in HANDLE ProcessHandle,
				 __out PCLIENT_ID ClientID, 
				 __in PCONTEXT Context,
				 __in /*PUSER_STACK*/PVOID StackInfo,
				 __in BOOLEAN CreateSuspended
				 )
{

	NTSTATUS		status;
	HIPS_RULE_NODE	Pi;
	HANDLE			hDestProcessId;

	if (ExGetPreviousMode() == KernelMode || 
		KeGetCurrentIrql() >= DISPATCH_LEVEL || 
		g_is_proc_run == FALSE ||
		PsGetCurrentProcessId() == (HANDLE)4 || 
		PsGetCurrentProcessId() == (HANDLE)0 ||
		ProcessHandle == UlongToHandle(-1) ||
		ProcessHandle == 0
		)
	{
		return real_NtCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, Context, StackInfo, CreateSuspended );
	}

	if (is_process_in_white_list(PsGetCurrentProcessId()))
	{
		return real_NtCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, Context, StackInfo, CreateSuspended );
	}

	if (!NT_SUCCESS( Sys_GetProcessIdByHandle( ProcessHandle, &hDestProcessId ) ))
	{
		hDestProcessId = PsGetCurrentProcessId(); // skip
	}

	if (PsGetCurrentProcessId() == hDestProcessId)
	{
		return real_NtCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, Context, StackInfo, CreateSuspended );
	}

	RtlZeroMemory(&Pi, sizeof(HIPS_RULE_NODE));
	Pi.major_type = PROC_OP;
	Pi.sub_pid = PsGetCurrentProcessId();		
	Pi.obj_pid = hDestProcessId;		
	Pi.minor_type = OP_PROC_CREATE_REMOTE_THREAD;

	if (rule_match(&Pi) == FALSE)
	{
		return STATUS_ACCESS_DENIED;
	}
	else
	{
		return real_NtCreateThread( ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle, ClientID, Context, StackInfo, CreateSuspended );
	}
}

NTSTATUS
NTAPI fake_NtRequestWaitReplyPort (
	__in HANDLE PortHandle,
	__in PPORT_MESSAGE RequestMessage,
	__out PPORT_MESSAGE ReplyMessage
	)
{
	NTSTATUS					status = STATUS_SUCCESS ; 
	PVOID						Object = NULL;
	UNICODE_STRING				ServPortName;
	WCHAR						ObjName[100] = {0};
	POBJECT_NAME_INFORMATION	ObjectNameInfo = (POBJECT_NAME_INFORMATION)ObjName;
	ULONG						uactLength = 0;

	if ( KernelMode == ExGetPreviousMode() ||
		KeGetCurrentIrql() >= DISPATCH_LEVEL||
		PortHandle == NULL ||
		RequestMessage == NULL ||
		PsGetCurrentProcessId() == (HANDLE)0)
	{
		return real_NtRequestWaitReplyPort(PortHandle,RequestMessage,ReplyMessage);
	}

	RtlInitUnicodeString(&ServPortName,L"\\RPC Control\\ntsvcs");

	status = ObReferenceObjectByHandle( PortHandle, 0, NULL, KernelMode, &Object, NULL );
	if ( ! NT_SUCCESS(status) )
	{
		return real_NtRequestWaitReplyPort(PortHandle,RequestMessage,ReplyMessage);
	}

	status = ObQueryNameString(((PLPCP_PORT_OBJECT)Object)->ConnectionPort,ObjectNameInfo,100*2,&uactLength);
	if ( ! NT_SUCCESS(status) )
	{
		ObDereferenceObject(Object);
		return real_NtRequestWaitReplyPort(PortHandle,RequestMessage,ReplyMessage);
	}

	if(RtlEqualUnicodeString(&ServPortName,&ObjectNameInfo->Name,TRUE))
	{
		ObDereferenceObject(Object);
		return real_NtRequestWaitReplyPort(PortHandle,RequestMessage,ReplyMessage);
	}

	ObDereferenceObject(Object);
	return real_NtRequestWaitReplyPort(PortHandle,RequestMessage,ReplyMessage);
}


BOOLEAN
HookNtFunc (
	__out PULONG pInterceptedFuncAddress,
	__out PULONG pFuncIndex,
	__in ULONG   NewFuncAddress,
	__in PCHAR   FuncName
	)
{
	BOOLEAN bPatched = FALSE;
	ULONG NativeID = 0;
	if (!pInterceptedFuncAddress || !pFuncIndex)
	{
		return FALSE;
	}

	NativeID = GetNativeID( g_BaseOfNtDllDll, FuncName );

	if (NativeID)
	{
		*pInterceptedFuncAddress = SYSTEMSERVICE_BY_FUNC_ID( NativeID );
		*pFuncIndex = NativeID;
		__asm
	{
		cli
		push eax
		mov eax,cr0
		and eax,not 0x10000
		mov cr0,eax
		pop eax
	}

		SYSTEMSERVICE_BY_FUNC_ID( NativeID ) = NewFuncAddress;

		__asm
	{
		push eax
		mov eax,cr0
		or eax,0x10000
		mov cr0,eax
		pop eax
		sti
	}

		bPatched = TRUE;
	}
	return bPatched;
}


VOID
UnHookNtFunc (
	__in ULONG	 FuncIndex,
	__in ULONG   RealFuncAddress
	)
{
	if (MAXULONG == FuncIndex || !RealFuncAddress)
	{
		return ;
	}

	__asm
	{
		cli
		push eax
		mov eax,cr0
		and eax,not 0x10000
		mov cr0,eax
		pop eax
	}

	SYSTEMSERVICE_BY_FUNC_ID( FuncIndex ) = RealFuncAddress;

	__asm
	{
		push eax
		mov eax,cr0
		or eax,0x10000
		mov cr0,eax
		pop eax
		sti
	}
}

NTSTATUS sw_init_procss(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS					Status = STATUS_SUCCESS;
	g_BaseOfNtDllDll = GetNativeBase( "NTDLL.DLL" );
	if (!g_BaseOfNtDllDll)
	{
		return STATUS_UNSUCCESSFUL;
	}
	HookNtFunc( (ULONG*) &real_NtRequestWaitReplyPort,&g_NtRequestWaitReplyPort_index, (ULONG) fake_NtRequestWaitReplyPort, "NtRequestWaitReplyPort");
	HookNtFunc( (ULONG*) &real_NtTerminateProcess,&g_NtTerminateProcess_index, (ULONG) fake_NtTerminateProcess, "NtTerminateProcess");
	HookNtFunc( (ULONG*) &real_NtCreateThread,&g_NtCreateThread_index, (ULONG) fake_NtCreateThread, "NtCreateThread");
	
	return Status;
}

VOID
SleepImp (
	__int64 ReqInterval
	)
{
	LARGE_INTEGER	Interval;
	*(__int64*)&Interval=-(ReqInterval*10000000L);
	KeDelayExecutionThread( KernelMode, FALSE, &Interval );
}


NTSTATUS sw_uninit_procss(PDRIVER_OBJECT pDriverObj)
{
	NTSTATUS Status = STATUS_SUCCESS;

	

	UnHookNtFunc(g_NtTerminateProcess_index,(ULONG)real_NtTerminateProcess);
	g_NtTerminateProcess_index = MAXULONG;

	UnHookNtFunc(g_NtCreateThread_index,(ULONG)real_NtCreateThread);
	g_NtCreateThread_index = MAXULONG;

	UnHookNtFunc(g_NtRequestWaitReplyPort_index,(ULONG)real_NtRequestWaitReplyPort);
	g_NtRequestWaitReplyPort_index = MAXULONG;

	return Status;
}

#endif 

#endif