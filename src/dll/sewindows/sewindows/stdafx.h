// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently, but
// are changed infrequently
//

#pragma once

#include "targetver.h"

#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
// Windows Header Files:
#include <windows.h>
#include <stdlib.h>  
#include <malloc.h>
#include <tchar.h>
#include <Fltuser.h>
#include <strsafe.h>
#include <atlstr.h>
#pragma comment(lib,"fltLib.lib")

#define SERVICENAME		_T("sewindows")
#define DRIVERNAME		_T("sewindows.sys")
#define LINKNAME		_T("\\\\.\\sewindows") 
#define HIPSPORTNAME	_T("\\sewindows")
#define THREAD_COUNT	4 
#define REQUEST_COUNT	4

#include "rule_struct.h"

// TODO: reference additional headers your program requires here
