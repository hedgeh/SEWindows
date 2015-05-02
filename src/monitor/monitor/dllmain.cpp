// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"
#include "mhook-lib/mhook.h"
#include "monitor.h"


fn_CreateServiceW	real_CreateServiceW = NULL;
fn_CreateServiceA	real_CreateServiceA = NULL;
fn_OpenServiceW		real_OpenServiceW = NULL;
fn_OpenServiceA		real_OpenServiceA = NULL;
fn_EndTask			real_EndTask = NULL;


void GetProcessAddr()
{
	
	real_CreateServiceW = (fn_CreateServiceW)GetProcAddress(GetModuleHandle(L"Advapi32"), "CreateServiceW");
	real_CreateServiceA = (fn_CreateServiceA)GetProcAddress(GetModuleHandle(L"Advapi32"), "CreateServiceA");
	real_OpenServiceW = (fn_OpenServiceW)GetProcAddress(GetModuleHandle(L"Advapi32"), "OpenServiceW");
	real_OpenServiceA = (fn_OpenServiceA)GetProcAddress(GetModuleHandle(L"Advapi32"), "OpenServiceA");
	real_EndTask = (fn_EndTask)GetProcAddress(GetModuleHandle(L"user32"), "EndTask");
}


void StartHook()
{
	Mhook_SetHook((PVOID*)&real_CreateServiceW, fake_CreateServiceW);
	Mhook_SetHook((PVOID*)&real_CreateServiceA, fake_CreateServiceA);
	Mhook_SetHook((PVOID*)&real_OpenServiceW, fake_OpenServiceW);
	Mhook_SetHook((PVOID*)&real_OpenServiceA, fake_OpenServiceA);
	Mhook_SetHook((PVOID*)&real_EndTask, fake_EndTask);
}

void RemoveHook()
{
	Mhook_Unhook((PVOID*)&real_CreateServiceW);
	Mhook_Unhook((PVOID*)&real_CreateServiceA);
	Mhook_Unhook((PVOID*)&real_OpenServiceW);
	Mhook_Unhook((PVOID*)&real_OpenServiceA);
	Mhook_Unhook((PVOID*)&real_EndTask);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		GetProcessAddr();
		StartHook();
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		RemoveHook();
		break;
	}
	return TRUE;
}

