// dllmain.cpp : Defines the entry point for the DLL application.

#include "stdafx.h"

#include "CPUInfo.h"

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemAllowedCpuSetsInformation = 168,
	SystemCpuSetInformation = 175,
	SystemCpuSetTagInformation = 176,
} SYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
	ProcessDefaultCpuSetsInformation = 66,
	ProcessAllowedCpuSetsInformation = 67,
} PROCESSINFOCLASS;

#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022L)
#define STATUS_SUCCESS		 ((NTSTATUS)0)

extern "C"
NTSTATUS
NTAPI
NtSetInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_In_reads_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength
);

extern "C"
NTSTATUS
NTAPI
NtQuerySystemInformationEx(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_In_reads_bytes_(InputBufferLength) PVOID InputBuffer,
	_In_ ULONG InputBufferLength,
	_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

extern "C"
NTSTATUS
NTAPI
NtSetSystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_In_reads_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength
);

extern "C"
NTSTATUS
NTAPI
NtQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Out_writes_bytes_to_opt_(SystemInformationLength, *ReturnLength) PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_ PULONG ReturnLength
);

extern "C"
NTSTATUS
NTAPI
NtQueryInformationProcess(
	_In_ HANDLE ProcessHandle,
	_In_ PROCESSINFOCLASS ProcessInformationClass,
	_Out_writes_bytes_opt_(ProcessInformationLength) PVOID ProcessInformation,
	_In_ ULONG ProcessInformationLength,
	_Out_opt_ PULONG ReturnLength
);

#pragma comment(lib, "ntdll")

const unsigned int HALF_ARRAY = 0x1FFFFFF + 1;
const unsigned int ARRAY_SIZE = HALF_ARRAY * 2;

unsigned int* mem;

typedef BOOL(WINAPI* LPFN_GLPI)(
	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION,
	PDWORD);


// TIME DIFF FUNC
ULONGLONG SubtractTimes(const FILETIME one, const FILETIME two)
{
	LARGE_INTEGER a, b;
	a.LowPart = one.dwLowDateTime;
	a.HighPart = one.dwHighDateTime;

	b.LowPart = two.dwLowDateTime;
	b.HighPart = two.dwHighDateTime;

	return a.QuadPart - b.QuadPart;
}

extern "C"
{
	__declspec(dllexport) double __stdcall CPUUsage(void)
	{
		//https://stackoverflow.com/questions/23143693/retrieving-cpu-load-percent-total-in-windows-with-c

		FILETIME prevSysIdle, prevSysKernel, prevSysUser;
		FILETIME sysIdle, sysKernel, sysUser;
		// sysKernel include IdleTime

		if (GetSystemTimes(&sysIdle, &sysKernel, &sysUser) == 0) // GetSystemTimes func FAILED return value is zero;
			return 0;

		prevSysIdle = sysIdle;
		prevSysKernel = sysKernel;
		prevSysUser = sysUser;


		Sleep(100);

		if (GetSystemTimes(&sysIdle, &sysKernel, &sysUser) == 0) // GetSystemTimes func FAILED return value is zero;
			return 0;


		if (prevSysIdle.dwLowDateTime != 0 && prevSysIdle.dwHighDateTime != 0)
		{
			ULONGLONG sysIdleDiff, sysKernelDiff, sysUserDiff;
			sysIdleDiff = SubtractTimes(sysIdle, prevSysIdle);
			sysKernelDiff = SubtractTimes(sysKernel, prevSysKernel);
			sysUserDiff = SubtractTimes(sysUser, prevSysUser);

			ULONGLONG sysTotal = sysKernelDiff + sysUserDiff;
			ULONGLONG kernelTotal = sysKernelDiff - sysIdleDiff; // kernelTime - IdleTime = kernelTime, because sysKernel include IdleTime

			if (sysTotal > 0) // sometimes kernelTime > idleTime
				return (double)(((kernelTotal + sysUserDiff) * 100.0) / sysTotal);
		}
		return 0;

	}
}

DWORD CountSetBits(ULONG_PTR bitMask)
{
	DWORD LSHIFT = sizeof(ULONG_PTR) * 8 - 1;
	DWORD bitSetCount = 0;
	ULONG_PTR bitTest = (ULONG_PTR)1 << LSHIFT;
	DWORD i;

	for (i = 0; i <= LSHIFT; ++i)
	{
		bitSetCount += ((bitMask & bitTest) ? 1 : 0);
		bitTest /= 2;
	}

	return bitSetCount;
}

char* getCpuidVendor(char* vendor) {
	int data[4];
	__cpuid(data, 0);
	*reinterpret_cast<int*>(vendor) = data[1];
	*reinterpret_cast<int*>(vendor + 4) = data[3];
	*reinterpret_cast<int*>(vendor + 8) = data[2];
	vendor[12] = 0;
	return vendor;
}

int getCpuidFamily() {
	int data[4];
	__cpuid(data, 1);
	int family = ((data[0] >> 8) & 0x0F);
	int extendedFamily = (data[0] >> 20) & 0xFF;
	int displayFamily = (family != 0x0F) ? family : (extendedFamily + family);
	return displayFamily;
}

CPUInfo getCPUInfo()
{
	LPFN_GLPI glpi;
	BOOL done = FALSE;
	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION buffer = NULL;
	PSYSTEM_LOGICAL_PROCESSOR_INFORMATION ptr = NULL;
	DWORD returnLength = 0;
	DWORD byteOffset = 0;
	PCACHE_DESCRIPTOR Cache;
	CPUInfo info;

	info.cpuidFamily = getCpuidFamily();
	getCpuidVendor(info.vendor);

	glpi = (LPFN_GLPI)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "GetLogicalProcessorInformation");
	if (NULL == glpi)
	{
		//cout << "GetLogicalProcessorInformation is not supported";
		return info;
	}

	while (!done)
	{
		DWORD rc = glpi(buffer, &returnLength);
		if (FALSE == rc)
		{
			if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
			{
				if (buffer)
				{
					free(buffer);
				}

				buffer = (PSYSTEM_LOGICAL_PROCESSOR_INFORMATION)malloc(returnLength);

				if (NULL == buffer)
				{
					//cout << "Error: Allocation failure";
					return info;
				}
			}
			else
			{
				//cout << "Error: " << GetLastError();
				return info;
			}
		}
		else
		{
			done = TRUE;
		}
	}

	ptr = buffer;

	while (byteOffset + sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION) <= returnLength)
	{
		switch (ptr->Relationship)
		{
		case RelationNumaNode:
			// Non-NUMA systems report a single record of this type.
			info.numaNodeCount++;
			break;

		case RelationProcessorCore:
			info.physicalCoreCount++;
			info.logicalCoreCount += CountSetBits(ptr->ProcessorMask);
			break;

		case RelationCache:
			Cache = &ptr->Cache;
			if (Cache->Level == 1)
			{
				if (Cache->Type == CacheData) {
					info.L1CacheCount++;
				}
			}
			else if (Cache->Level == 2)
			{
				info.L2CacheCount++;
			}
			else if (Cache->Level == 3)
			{
				info.L3CacheCount++;
			}
			break;

		case RelationProcessorPackage:
			info.packageCount++;
			break;

		default:
			break;
		}
		byteOffset += sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION);
		ptr++;
	}
	free(buffer);
	return info;
}

int runTestLegacy(int core, int quick) {
	//Setup
	SetThreadAffinityMask(GetCurrentThread(), static_cast<DWORD_PTR>(1) << core);

	//Randomly jump through the array
	//This will alternate between the high and low half
	//This is certain to run to completion because no element can contain the index for itself.
	//This process should defeat branch predictors and prefetches 
	//and result in needing data from RAM on every loop iteration.
	unsigned int value = mem[0];
	unsigned int qvalue = mem[0];

	
	if (quick == 1) {
		for (int n = 0; n < 100; n++)
		{
			for (int i = 0; i < ARRAY_SIZE / 8192; i++)
			{
				//Set value equal to the value stored at an array index
				value = mem[value];
			}
			Sleep(50);
		}
	}
	else
	{
		for (int i = 0; i < ARRAY_SIZE; i++)
		{
			//Set value equal to the value stored at an array index
			value = mem[value];
		}
	}

	//Return final value to prevent loop from being optimized out
	return value;
}

extern "C"
{
	__declspec(dllexport) int __stdcall _RunBoostTest(int thread, int mode)
	{
		int _ret = -1;
		if (mode == 0)
		{
			// Quick Mode Legacy
			_ret = _RunBoostTest(thread, 0);
		}
		else if (mode == 1)
		{
			// Sustained Mode Legacy
			_ret = _RunBoostTest(thread, 1);
		}
		return _ret;
	}
}

int _RunBoostTestLegacy(int thread, int quick)
{
	//Memory required
	unsigned int memsize = ARRAY_SIZE / 256 / 1024;

	//One time setup
	mem = new unsigned int[ARRAY_SIZE];

	//Populate memory array
	for (unsigned int i = 0; i < HALF_ARRAY; i++)
	{
		//Fill low half of the array with values from the high half
		mem[i] = i + HALF_ARRAY;

		//Fill high half of the array with values for the low half
		mem[i + HALF_ARRAY] = i;
	}

	//Now we shuffle the high and low part of the array.
	//Doing it this way ensures that no element contains the index for itself
	//Performing array shuffle (low)
	for (unsigned int i = 0; i < HALF_ARRAY; i++) {
		int r = rand() % HALF_ARRAY;
		unsigned int temp = mem[i];
		mem[i] = mem[r];
		mem[r] = temp;
	}

	//Performing array shuffle (high)
	for (unsigned int i = HALF_ARRAY; i < ARRAY_SIZE; i++) {
		int r = (rand() % HALF_ARRAY) + HALF_ARRAY;
		unsigned int temp = mem[i];
		mem[i] = mem[r];
		mem[r] = temp;
	}

	//CPUInfo info = getCPUInfo();
	//int threadsPerCore = info.getThreadsPerCore();

	//This value has no actual meaning, but is required to avoid runTest() being optimized out by the compiler
	unsigned long counter = 0;
	//This condition will never be false. Tricking the compiler....
	while (counter < 0xFFFFFFFFF) {
		//for (int i = 0; i < info.logicalCoreCount; i += threadsPerCore) {
		counter = runTestLegacy(thread, quick);
		//Sleep(3000);
		//}
	}

	//Have to use the return from runTest() somewhere or it gets optimized out.
	return counter;
}

BOOLEAN WINAPI CpuToolsDllMain(IN HINSTANCE hDllHandle,
	IN DWORD nReason,
	IN LPVOID Reserved)
{
	switch (nReason)
	{
	case DLL_PROCESS_ATTACH:
		{
			break;
		}
	case DLL_PROCESS_DETACH:
		{
			break;
		}
	}

	return TRUE;
}

extern "C" BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	BOOLEAN bSuccess = TRUE;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hModule);
		break;
	case DLL_PROCESS_DETACH:
		break;
	}


	if (CpuToolsDllMain(hModule, ul_reason_for_call, lpReserved))
	{
		bSuccess = TRUE;
	}
	else
	{
		bSuccess = FALSE;
	}

	return bSuccess;
}

BOOL SetPrivilege(HANDLE hToken, PCTSTR lpszPrivilege, bool bEnablePrivilege) {
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!::LookupPrivilegeValue(nullptr, lpszPrivilege, &luid))
		return FALSE;

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!::AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), nullptr, nullptr)) {
		return FALSE;
	}

	if (::GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}

template<typename T>
//bool ParseCPUSet(T* pSet, const char* text, int& count) {
bool ParseCPUSet(T* pSet, const UINT bitMask, int& count) {
	/*
	if (*text == '\0')
		return true;
	bool hex = false;
	if (strlen(text) > 2 && (::strncmp(text, "0x", 2) == 0 || ::strncmp(text, "0X", 2) == 0))
		hex = true;

	int value = std::stoi(std::string(text + (hex ? 2 : 0)), nullptr, hex ? 16 : 10);
	*/
	pSet[0] = bitMask;
	count = 1;
	return true;
}

extern "C"
{
	__declspec(dllexport) int __stdcall SetSystemCpuSet(UINT bitMask)
	{
		ULONG64 systemCpuSet[20];
		int count = 0;
		int _ret = 0;
		HANDLE hToken = nullptr;
		NTSTATUS status;

		::OpenProcessToken(::GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);

		if (!SetPrivilege(hToken, SE_INC_BASE_PRIORITY_NAME, TRUE))
			_ret = -1;
		::CloseHandle(hToken);

		if (_ret == 0)
			if (!ParseCPUSet(systemCpuSet, bitMask, count))
				_ret = -2;

		if (_ret == 0) {
			auto pSet = systemCpuSet;

			if (bitMask == 0) {
				pSet = nullptr;
				count = 0;
			}

			status = ::NtSetSystemInformation(SystemAllowedCpuSetsInformation, pSet, count * sizeof(ULONG64));

			if (status == STATUS_SUCCESS)
				_ret = 0;
			else
				_ret = (int)status;

		}

		return _ret;
	}
}

extern "C"
{
	__declspec(dllexport) double __stdcall GetCpuTotalLoad()
	{
		static PDH_HQUERY cpuQuery;
		static PDH_HCOUNTER cpuTotal;
		PdhOpenQuery(NULL, NULL, &cpuQuery);
		// You can also use L"\\Processor(*)\\% Processor Time" and get individual CPU values with PdhGetFormattedCounterArray()
		PdhAddEnglishCounter(cpuQuery, L"\\Processor(_Total)\\% Processor Time", NULL, &cpuTotal);
		PdhCollectQueryData(cpuQuery);
		PDH_FMT_COUNTERVALUE counterVal;
		
		for (int count = 0; count <= 3; count++) {
			PdhCollectQueryData(cpuQuery);
		}
		
		PdhGetFormattedCounterValue(cpuTotal, PDH_FMT_DOUBLE, NULL, &counterVal);
		return counterVal.doubleValue;	
	}
}
