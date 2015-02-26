#pragma once
typedef struct _SCANNER_REPLY
{
	BOOLEAN bPermit;
} SCANNER_REPLY, *PSCANNER_REPLY;

BOOLEAN	get_user_judge(PVOID psendBuf, ULONG send_size, PSCANNER_REPLY pBret, PLARGE_INTEGER time_out);
NTSTATUS init_lpc(PWCHAR port_name, PFLT_FILTER filter);
void uninit_lpc();
BOOLEAN rule_match(PHIPS_RULE_NODE hrn);
BOOLEAN notify_process_exit(HANDLE pid);
//BOOLEAN notify_process_create(HANDLE pid);