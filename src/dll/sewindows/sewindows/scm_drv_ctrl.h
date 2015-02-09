#pragma once

#include <Winsvc.h>

class ScmDrvCtrl
{
public:
	ScmDrvCtrl(void);
	~ScmDrvCtrl(void);
public:
	BOOLEAN Install(const TCHAR* lpszServiceName, const TCHAR* lpszDriverPath, const TCHAR* lpszAltitude, const TCHAR* lpszLink_name);
	BOOLEAN UnInstall(const TCHAR* lpszServiceName);
	BOOLEAN Start(const TCHAR* lpszDriverName);
	BOOLEAN Stop(const TCHAR* lpszDriverName);
	BOOLEAN IoControl(DWORD dwIoCode, PVOID InBuff, DWORD InBuffLen, PVOID OutBuff, DWORD OutBuffLen, DWORD *RealRetBytes);
private:
	TCHAR	m_link_name[MAX_PATH];
};

