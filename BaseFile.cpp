#include <tchar.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <Iphlpapi.h>
#include <tcpmib.h>

#pragma comment(lib, "Iphlpapi.lib")

//�Ƚ��ļ��汾�� �汾����Ҫ��ѭ��׼1.0.0.0
//-1 �°汾�Žϵ� 1 �°�Žϸ� 0 ���
int CompareVersionA(char* pszVersionOld, char* pszVersionNew)
{
	if ((NULL == pszVersionOld) || (NULL == pszVersionNew))
	{
		return 0;
	}
	int nVersionOld = 1;
	int nVersionNew = 1;
	char* pVersionOld = pszVersionOld;
	char* pVersionNew = pszVersionNew;
	//�Ƚ�λ��
	//�ж�10.0 > 9.0�������
	pVersionOld++;
	while ((*pVersionOld != '.') && (*pVersionOld != 0))
	{
		pVersionOld++;
		nVersionOld++;
	}
	pVersionNew++;
	while ((*pVersionNew != '.') && (*pVersionNew != 0))
	{
		pVersionNew++;
		nVersionNew++;
	}
	if (nVersionOld > nVersionNew)
	{
		return -1;
	}
	else if (nVersionNew > nVersionOld)
	{
		return 1;
	}
	//λ����ͬ�������Ƚϣ��ָ���ʼ״̬
	pVersionOld = pszVersionOld;
	pVersionNew = pszVersionNew;
	//��һλ
	if (*pVersionOld > *pVersionNew)
	{
		return -1;
	}
	else if (*pszVersionOld < *pszVersionNew)
	{
		return 1;
	}
	else
	{
		//��һλ��ͬ��ѭ���Ƚ�֮��
		while(nVersionOld != 0)
		{
			pVersionOld++;
			pVersionNew++;
			if (*pVersionOld > *pVersionNew)
			{
				return -1;
			}
			else if (*pVersionOld < *pVersionNew)
			{
				return 1;
			}
			nVersionOld -= 1;
		}
		//����ͬ���Ƚ���һλ
		pVersionOld++;
		pVersionNew++;
		if ((*pVersionOld == 0) && (*pVersionNew == 0))
		{
			return 0;
		}
		return CompareVersionA(pVersionOld, pVersionNew);
	}
}

//�Ƚ��ļ��汾�� �汾����Ҫ��ѭ��׼1.0.0.0
//-1 �°汾�Žϵ� 1 �°�Žϸ� 0 ���
int CompareVersionW(WCHAR* pszVersionOld, WCHAR* pszVersionNew)
{
	if ((NULL == pszVersionOld) || (NULL == pszVersionNew))
	{
		return 0;
	}
	int nVersionOld = 1;
	int nVersionNew = 1;
	WCHAR* pVersionOld = pszVersionOld;
	WCHAR* pVersionNew = pszVersionNew;
	//�Ƚ�λ��
	//�ж�10.0 > 9.0�������
	pVersionOld++;
	while ((*pVersionOld != _T('.')) && (*pVersionOld != 0))
	{
		pVersionOld++;
		nVersionOld++;
	}
	pVersionNew++;
	while ((*pVersionNew != _T('.')) && (*pVersionNew != 0))
	{
		pVersionNew++;
		nVersionNew++;
	}
	if (nVersionOld > nVersionNew)
	{
		return -1;
	}
	else if (nVersionNew > nVersionOld)
	{
		return 1;
	}
	//λ����ͬ�������Ƚϣ��ָ���ʼ״̬
	pVersionOld = pszVersionOld;
	pVersionNew = pszVersionNew;
	//��һλ
	if (*pVersionOld > *pVersionNew)
	{
		return -1;
	}
	else if (*pszVersionOld < *pszVersionNew)
	{
		return 1;
	}
	else
	{
		//��һλ��ͬ��ѭ���Ƚ�֮��
		while(nVersionOld != 0)
		{
			pVersionOld++;
			pVersionNew++;
			if (*pVersionOld > *pVersionNew)
			{
				return -1;
			}
			else if (*pVersionOld < *pVersionNew)
			{
				return 1;
			}
			nVersionOld -= 1;
		}
		//����ͬ���Ƚ���һλ
		pVersionOld++;
		pVersionNew++;
		if ((*pVersionOld == 0) && (*pVersionNew == 0))
		{
			return 0;
		}
		return CompareVersionW(pVersionOld, pVersionNew);
	}
}

// �ж�ָ���ļ��Ƿ���ڣ�����·����
BOOL	FileIsExist(LPCTSTR szFileName)
{
	DWORD dwRes = GetFileAttributes(szFileName);
	if (dwRes == INVALID_FILE_ATTRIBUTES)
	{
		return FALSE;
	}
	return TRUE;
}

// �ж�ָ���ļ��Ƿ���ڣ�����·����
BOOL	FileIsExistA(const char* pszFileName)
{
	DWORD dwRes = GetFileAttributesA(pszFileName);
	if (dwRes == INVALID_FILE_ATTRIBUTES)
	{
		return FALSE;
	}
	return TRUE;
}

//ȥ������·���е��ļ�������չ����szPath��Ҫ����ռ�
BOOL	GetFilePath(TCHAR* szFullPath, TCHAR* szPath)
{
	TCHAR szDrive[_MAX_DRIVE];
	TCHAR szDir[_MAX_DIR];
	_tsplitpath_s(szFullPath, szDrive, _MAX_DRIVE, szDir, _MAX_DIR, NULL, NULL, NULL, NULL);
	_tmakepath_s(szPath, MAX_PATH, szDrive, szDir, NULL, NULL);
	return TRUE;
}

//ȥ������·���е��ļ�������չ����szPath��Ҫ����ռ�
BOOL	GetFilePathA(const char* szFullPath, char* szPath)
{
	char szDrive[_MAX_DRIVE];
	char szDir[_MAX_DIR];
	_splitpath_s(szFullPath, szDrive, _MAX_DRIVE, szDir, _MAX_DIR, NULL, NULL, NULL, NULL);
	_makepath_s(szPath, MAX_PATH, szDrive, szDir, NULL, NULL);
	return TRUE;
}

// �õ�ָ���ļ��Ĵ�С
ULONGLONG	GetFileSize(LPCTSTR szFileName)
{
	if (NULL == szFileName)
	{
		return 0;
	}
	WIN32_FILE_ATTRIBUTE_DATA data;
	if (GetFileAttributesEx(szFileName, GetFileExInfoStandard, &data))
	{
		ULONGLONG llFileSize = data.nFileSizeHigh;

		llFileSize <<= sizeof(DWORD)*8; //���� 32 λ
		llFileSize += data.nFileSizeLow;
		return llFileSize;
	}
	return 0;
}

// �õ�ָ���ļ��Ĵ�С
ULONGLONG	GetFileSizeA(const char* pszFileName)
{
	if (NULL == pszFileName)
	{
		return 0;
	}
	WIN32_FILE_ATTRIBUTE_DATA data;
	if (GetFileAttributesExA(pszFileName, GetFileExInfoStandard, &data))
	{
		ULONGLONG llFileSize = data.nFileSizeHigh;

		llFileSize <<= sizeof(DWORD)*8; //���� 32 λ
		llFileSize += data.nFileSizeLow;
		return llFileSize;
	}
	return 0;
}

#define TOHEX( x ) ( ( x ) > 9 ? ( x ) + 55 : ( x ) + 48 )
#define FROMHEX( x ) ( isdigit(x) ? x - '0' : x - 'A' + 10 )

//URL����pOutʹ�������Ҫfree
void URLDecode(const char* szIn, char** pOut)
{
	int nInLenth = (int) strlen( szIn );
	int nFlag = 0;
	*pOut = (char*)malloc(nInLenth+1);
	char* szOut = *pOut;
	for (int i = 0; i < nInLenth; i++)
	{
		if (szIn[i] == '%')
		{
			szOut[nFlag] = (FROMHEX(szIn[i+1])<<4);
			szOut[nFlag] |= FROMHEX(szIn[i+2]);
			i += 2;
		}
		else
		{
			szOut[nFlag] = szIn[i];
		}
		nFlag++;
	}
	szOut[nFlag] = '\0';
}

//URL����
void URLEncode(const char* szIn, char** pOut)
{
	int nInLenth = (int) strlen( szIn );
	int nFlag = 0;
	BYTE byte;
	*pOut = (char*)malloc(nInLenth*3);
	char *szOut = *pOut;
	for ( int i = 0; i < nInLenth; i++ )
	{
		byte = szIn[i];
		if ( isalnum( byte ) )
		{
			szOut[nFlag++] = byte;
		}
		else
		{
			szOut[nFlag++] = '%';
			szOut[nFlag++] = TOHEX( byte >> 4 );
			szOut[nFlag++] = TOHEX( byte % 16 );
		}
	}
	szOut[nFlag] = '\0';
}

wchar_t* ANSIToUnicode(const char* str) 
{ 
	if (NULL == str)
	{
		return NULL;
	}
	int textlen ; 
	wchar_t * result = NULL; 
	textlen = MultiByteToWideChar( CP_ACP, 0, str,-1, NULL,0 ); 
	result = (wchar_t *)malloc((textlen+1)*sizeof(wchar_t)); 
	memset(result,0,(textlen+1)*sizeof(wchar_t)); 
	MultiByteToWideChar(CP_ACP, 0,str,-1,(LPWSTR)result,textlen ); 
	return result; 
} 

char * UnicodeToANSI(const wchar_t* str) 
{
	if (NULL == str)
	{
		return NULL;
	}
	char* result = NULL; 
	int textlen; 
	textlen = WideCharToMultiByte( CP_ACP, 0, str, -1, NULL, 0, NULL, NULL ); 
	result =(char *)malloc((textlen+1)*sizeof(char)); 
	memset( result, 0, sizeof(char) * ( textlen + 1 ) ); 
	WideCharToMultiByte( CP_ACP, 0, str, -1, result, textlen, NULL, NULL ); 
	return result; 
} 

wchar_t * UTF8ToUnicode(const char* str) 
{
	if (NULL == str)
	{
		return NULL;
	}
	int textlen ; 
	wchar_t * result = NULL; 
	textlen = MultiByteToWideChar( CP_UTF8, 0, str,-1, NULL,0 ); 
	result = (wchar_t *)malloc((textlen+1)*sizeof(wchar_t)); 
	memset(result,0,(textlen+1)*sizeof(wchar_t)); 
	MultiByteToWideChar(CP_UTF8, 0,str,-1,(LPWSTR)result,textlen ); 
	return result; 
} 

char * UnicodeToUTF8(const wchar_t* str) 
{
	if (NULL == str)
	{
		return NULL;
	}
	char* result = NULL; 
	int textlen; 
	textlen = WideCharToMultiByte( CP_UTF8, 0, str, -1, NULL, 0, NULL, NULL ); 
	result =(char *)malloc((textlen+1)*sizeof(char)); 
	memset(result, 0, sizeof(char) * ( textlen + 1 ) ); 
	WideCharToMultiByte( CP_UTF8, 0, str, -1, result, textlen, NULL, NULL ); 
	return result; 
}

//ANSIת��UTF8
char* ANSIToUTF8(const char* str)
{
	if (NULL == str)
	{
		return NULL;
	}
	char* result = NULL;
	wchar_t* pUTF16 = ANSIToUnicode(str);
	if (pUTF16)
	{
		result = UnicodeToUTF8(pUTF16);
		free(pUTF16);
		pUTF16 = NULL;
	}
	return result;
}

//UTF8ת��ANSI
char* UTF8ToANSI(const char* str)
{
	if (NULL == str)
	{
		return NULL;
	}
	char* result = NULL;
	wchar_t* pUTF16 = UTF8ToUnicode(str);
	if (pUTF16)
	{
		result = UnicodeToANSI(pUTF16);
		free(pUTF16);
		pUTF16 = NULL;
	}
	return result;
}


// ��URL�����ļ���
BOOL GetFileNameFromUrlA(char* szUrl, char* szFileName)
{
	if ((NULL == szUrl) || (NULL == szFileName))
	{
		return FALSE;
	}
	char* pTmp = szUrl;
	pTmp += strlen(szUrl) - 1;
	while((*pTmp != '\\') && (*pTmp != '/') && (pTmp != szUrl))
	{
		pTmp--;
	}
	if (pTmp == szUrl)
	{
		strcpy(szFileName, szUrl);
		return TRUE;
	}
	pTmp++;
	strcpy(szFileName, pTmp);
	return TRUE;
}

// ��URL�����ļ���
BOOL GetFileNameFromUrlW(WCHAR* szUrl, WCHAR* szFileName)
{
	if ((NULL == szUrl) || (NULL == szFileName))
	{
		return FALSE;
	}
	WCHAR* pTmp = szUrl;
	pTmp += wcslen(szUrl) - 1;
	while((*pTmp != '\\') && (*pTmp != '/') && (pTmp != szUrl))
	{
		pTmp--;
	}
	if (pTmp == szUrl)
	{
		wcscpy(szFileName, szUrl);
		return TRUE;
	}
	pTmp++;
	wcscpy(szFileName, pTmp);
	return TRUE;
}

// �õ��ļ��ĺ�׺��
char*	GetFileExtA(char* pszFile)
{
	if (NULL == pszFile) return NULL;
	char* pTmp = pszFile;
	pTmp += strlen(pszFile);
	for (;pTmp != pszFile;pTmp--)
	{
		if (*pTmp == '.')
		{
			return pTmp;
		}
	}
	return NULL;
}

// �õ��ļ��ĺ�׺��
WCHAR*	GetFileExtW(WCHAR* pszFile)
{
	if (NULL == pszFile) return NULL;
	WCHAR* pTmp = pszFile;
	pTmp += wcslen(pszFile);
	for (;pTmp != pszFile;pTmp--)
	{
		if (*pTmp == L'.')
		{
			return pTmp;
		}
	}
	return NULL;
}

// ��·���а����ļ���
BOOL GetFileNameA(char* szFullPath, char* szFileName)
{
	if ((NULL == szFullPath) || (NULL == szFileName))
	{
		return FALSE;
	}
	char* pTmp = szFullPath;
	pTmp += strlen(szFullPath) - 1;
	while((*pTmp != '\\') && (pTmp != szFullPath))
	{
		pTmp--;
	}
	if (pTmp == szFullPath)
	{
		strcpy(szFileName, szFullPath);
		return TRUE;
	}
	pTmp++;
	strcpy(szFileName, pTmp);
	return TRUE;
}

// ��·���а����ļ���
BOOL GetFileNameW(WCHAR* szFullPath, WCHAR* szFileName)
{
	if ((NULL == szFullPath) || (NULL == szFileName))
	{
		return FALSE;
	}
	WCHAR* pTmp = szFullPath;
	pTmp += wcslen(szFullPath) - 1;
	while((*pTmp != '\\') && (*pTmp != '/') && (pTmp != szFullPath))
	{
		pTmp--;
	}
	if (pTmp == szFullPath)
	{
		wcscpy(szFileName, szFullPath);
		return TRUE;
	}
	pTmp++;
	wcscpy(szFileName, pTmp);
	return TRUE;
}

// ͨ��PID��ȡ��������
BOOL GetProcessNameFromId(DWORD dwPid, TCHAR* pszProcessName)
{
	BOOL bRet = FALSE;
	if (pszProcessName == NULL)
	{
		return bRet;
	}
	PROCESSENTRY32 pe32;  
	// ��ʹ������ṹ֮ǰ�����������Ĵ�С  
	pe32.dwSize = sizeof(pe32);   

	// ��ϵͳ�ڵ����н�����һ������  
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);  
	if(hProcessSnap == INVALID_HANDLE_VALUE)  
	{  
		OutputDebugString(_T(" CreateToolhelp32Snapshot����ʧ�ܣ� \n"));  
		return -1;  
	}  

	// �������̿��գ�������ʾÿ�����̵���Ϣ  
	BOOL bMore = ::Process32First(hProcessSnap, &pe32);  
	while(bMore)  
	{  
		if (pe32.th32ProcessID == dwPid)
		{
			_tcscpy(pszProcessName, pe32.szExeFile);
			bRet = TRUE;
			break;
		}
		bMore = ::Process32Next(hProcessSnap, &pe32);  
	}  

	// ��Ҫ���������snapshot����  
	::CloseHandle(hProcessSnap);  
	return bRet;
}

typedef DWORD (WINAPI * PFN_GET_EXTENDED_TCP_TABLE)    
	(    
	PVOID           pTcpTable,     
	PDWORD          pdwSize,     
	BOOL            bOrder,     
	ULONG           ulAf,     
	TCP_TABLE_CLASS TableClass,     
	ULONG           Reserved     
	);

// ����ռ��ĳ���˿ڵĽ���ID
// XP SP2����ϵͳ
BOOL GetProcessIdFromPort(DWORD dwPort, DWORD& dwPid)
{
	BOOL bRet = FALSE;
	HMODULE hModule = LoadLibrary(_T("iphlpapi.dll"));
	if (NULL == hModule)
	{
		return bRet;
	}
	PFN_GET_EXTENDED_TCP_TABLE pGetExtendTcpTable = (PFN_GET_EXTENDED_TCP_TABLE)GetProcAddress(hModule, "GetExtendedTcpTable");
	if (NULL == pGetExtendTcpTable)
	{
		FreeLibrary(hModule);
		return bRet;
	}
	PMIB_TCPTABLE_OWNER_PID pTcpTable = NULL;
	DWORD dwSize = 0;
	DWORD dwRes = pGetExtendTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
	if (dwRes == ERROR_INSUFFICIENT_BUFFER)
	{
		pTcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
	}
	else
	{
		FreeLibrary(hModule);
		return bRet;
	}
	if (NULL == pTcpTable)
	{
		FreeLibrary(hModule);
		return bRet;
	}
	dwRes = pGetExtendTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_LISTENER, 0);
	if (dwRes == NO_ERROR)
	{
		for (int i = 0; i < pTcpTable->dwNumEntries; i++)
		{
			int nPort = ntohs((USHORT)pTcpTable->table[i].dwLocalPort);
			if (nPort == dwPort)
			{
				dwPid = pTcpTable->table[i].dwOwningPid;
				bRet = TRUE;
				break;
			}
		}
	}
	free(pTcpTable);
	pTcpTable = NULL;
	FreeLibrary(hModule);
	return bRet;
}

// ����ָ�����ƵĽ���
BOOL GetProcessByName(TCHAR* pszProcessName)
{
	//���������Ƿ��Ѵ���
	DWORD aProcesses[1024], cbNeeded, cProcesses;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
		return FALSE;

	cProcesses = cbNeeded / sizeof(DWORD);

	TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");
	HANDLE hProcess;
	for (unsigned int i = 0; i < cProcesses; i++)
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);

		if (NULL != hProcess)
		{
			HMODULE hMod;
			DWORD cbNeeded;

			if (::EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded))
			{
				::GetModuleBaseName(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
				if (_tcscmp(szProcessName, pszProcessName) == 0)
				{
					CloseHandle(hProcess);
					return TRUE;
				}
			}
			CloseHandle(hProcess);
		}
	}
	return FALSE;
}