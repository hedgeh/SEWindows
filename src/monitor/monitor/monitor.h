#pragma once

#include <Windows.h>

typedef SC_HANDLE (WINAPI *fn_CreateServiceW)(
			_In_        SC_HANDLE    hSCManager,
			_In_        LPCWSTR     lpServiceName,
			_In_opt_    LPCWSTR     lpDisplayName,
			_In_        DWORD        dwDesiredAccess,
			_In_        DWORD        dwServiceType,
			_In_        DWORD        dwStartType,
			_In_        DWORD        dwErrorControl,
			_In_opt_    LPCWSTR     lpBinaryPathName,
			_In_opt_    LPCWSTR     lpLoadOrderGroup,
			_Out_opt_   LPDWORD      lpdwTagId,
			_In_opt_    LPCWSTR     lpDependencies,
			_In_opt_    LPCWSTR     lpServiceStartName,
			_In_opt_    LPCWSTR     lpPassword
			);

SC_HANDLE (WINAPI *fn_CreateServiceA)(
			_In_        SC_HANDLE    hSCManager,
			_In_        LPCSTR     lpServiceName,
			_In_opt_    LPCSTR     lpDisplayName,
			_In_        DWORD        dwDesiredAccess,
			_In_        DWORD        dwServiceType,
			_In_        DWORD        dwStartType,
			_In_        DWORD        dwErrorControl,
			_In_opt_    LPCSTR     lpBinaryPathName,
			_In_opt_    LPCSTR     lpLoadOrderGroup,
			_Out_opt_   LPDWORD      lpdwTagId,
			_In_opt_    LPCSTR     lpDependencies,
			_In_opt_    LPCSTR     lpServiceStartName,
			_In_opt_    LPCSTR     lpPassword
			);