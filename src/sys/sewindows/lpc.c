#include "main.h"
#include "lpc.h"

static PFLT_PORT g_ServerPort = NULL; 
static PFLT_PORT g_ClientPort = NULL;
static PFLT_FILTER g_Filter = NULL;

#define DELAY_ONE_MICROSECOND ( -10 )
#define DELAY_ONE_MILLISECOND	( DELAY_ONE_MICROSECOND * 1000 )

BOOLEAN rule_match(PHIPS_RULE_NODE hrn)
{
	USER_DATA		ud;
	PVOID			pBuf = &ud;
	ULONG			replyLength = sizeof(SCANNER_REPLY);
	NTSTATUS		status;
	SCANNER_REPLY	reply;
	LARGE_INTEGER	my_interval;

	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= 15000;

	RtlMoveMemory(&ud.rule_node, hrn, sizeof(HIPS_RULE_NODE));
	if (!g_is_notify_mode)
	{
		ud.option = OPTION_TO_JUGE;
		status = FltSendMessage(g_Filter,
			&g_ClientPort,
			pBuf,
			sizeof(USER_DATA),
			pBuf,
			&replyLength,
			&my_interval);
		if (STATUS_SUCCESS == status)
		{
			RtlCopyMemory(&reply, pBuf, sizeof(SCANNER_REPLY));
			return reply.bPermit;
		}
		else
		{
			if (STATUS_TIMEOUT == status)
			{
				g_is_file_run = FALSE;
				g_is_proc_run = FALSE;
				g_is_reg_run = FALSE;
				g_is_unload_allowed = TRUE;
			}
			return TRUE;
		}
	}
	else
	{
		ud.option = OPTION_TO_NOTIFY;
		status = FltSendMessage(g_Filter,
			&g_ClientPort,
			pBuf,
			sizeof(USER_DATA),
			NULL,
			&replyLength,
			&my_interval);
		if (STATUS_TIMEOUT == status)
		{
			g_is_file_run = FALSE;
			g_is_proc_run = FALSE;
			g_is_reg_run = FALSE;
			g_is_unload_allowed = TRUE;
		}
		return TRUE;
	}
}


BOOLEAN notify_process_exit(HANDLE pid)
{
	USER_DATA		ud;
	PVOID			pBuf = &ud;
	ULONG			replyLength = sizeof(SCANNER_REPLY);
	NTSTATUS		status;
	LARGE_INTEGER	my_interval;

	my_interval.QuadPart = DELAY_ONE_MILLISECOND;
	my_interval.QuadPart *= 15000;
	RtlZeroMemory(&ud, sizeof(USER_DATA));
	
	ud.option = OPTION_PROC_EXIT;
	ud.rule_node.sub_pid = pid;
	status = FltSendMessage(g_Filter,
		&g_ClientPort,
		pBuf,
		sizeof(USER_DATA),
		NULL,
		&replyLength,
		&my_interval);
	if (STATUS_TIMEOUT == status)
	{
		g_is_file_run = FALSE;
		g_is_proc_run = FALSE;
		g_is_reg_run = FALSE;
		g_is_unload_allowed = TRUE;
	}
	return TRUE;
	
}


NTSTATUS
port_connect(PFLT_PORT ClientPort,PVOID ServerPortCookie, PVOID ConnectionContext, ULONG SizeOfContext,PVOID *ConnectionCookie)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionCookie);

	g_ClientPort = ClientPort;

	return STATUS_SUCCESS;
}


VOID port_disconnect( PVOID ConnectionCookie)
{
	UNREFERENCED_PARAMETER(ConnectionCookie);
	PAGED_CODE();
	if (g_ClientPort)
	{
		FltCloseClientPort(g_Filter, &g_ClientPort);
		g_ClientPort = NULL;
	}
}

void uninit_lpc()
{
	if (g_ServerPort)
	{
		FltCloseCommunicationPort(g_ServerPort);
		g_ServerPort = NULL;
	}
}


NTSTATUS init_lpc(PWCHAR port_name, PFLT_FILTER filter)
{
	OBJECT_ATTRIBUTES		oa;
	UNICODE_STRING			uniString;
	PSECURITY_DESCRIPTOR	sd;
	NTSTATUS				status;

	g_Filter = filter;
	RtlInitUnicodeString(&uniString, port_name);
	status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
	if (NT_SUCCESS(status)) 
	{

		InitializeObjectAttributes(&oa,&uniString,OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,NULL,sd);
		status = FltCreateCommunicationPort(filter,
			&g_ServerPort,
			&oa,
			NULL,
			port_connect,
			port_disconnect,
			NULL,
			1);
		FltFreeSecurityDescriptor(sd);
	}
	return status;
}