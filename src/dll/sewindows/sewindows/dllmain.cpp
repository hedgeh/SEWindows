// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include "sewindows.h"
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	UNREFERENCED_PARAMETER(lpReserved);
	UNREFERENCED_PARAMETER(hModule);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
		sewin_setoption(SEWIN_MODE_INTERCEPT, 0);
		sewin_uninit();
		break;
	}
	return TRUE;
}

