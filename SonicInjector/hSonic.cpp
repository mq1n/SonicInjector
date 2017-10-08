#include "main.h"
 
std::vector <DWORD> GetProcessIdsFromProcessName(const char* c_szProcessName)
{
	std::vector <DWORD> vPIDs;

	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!hSnapshot || hSnapshot == INVALID_HANDLE_VALUE)
		return vPIDs;

	PROCESSENTRY32 pt;
	pt.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pt)) {
		do {
			std::string szProcessName = pt.szExeFile;
			std::transform(szProcessName.begin(), szProcessName.end(), szProcessName.begin(), tolower);

			if (strstr(szProcessName.c_str(), c_szProcessName))
				vPIDs.emplace_back(pt.th32ProcessID);

		} while (Process32Next(hSnapshot, &pt));
	}

	CloseHandle(hSnapshot);
	return vPIDs;
}

HANDLE GetHandleForIOProcesses(HANDLE hIOPort, const std::string & szTargetProcessName, DWORD dwDesiredAccess, BOOL bInheritHandle)
{
	HANDLE hTarget = INVALID_HANDLE_VALUE;
	char buffer[MAX_PATH];
	DWORD numberOfBytesTransferred;
	ULONG_PTR completionKey;
	LPOVERLAPPED overlapped;

	while (GetQueuedCompletionStatus(hIOPort, &numberOfBytesTransferred, &completionKey, &overlapped, INFINITE))
	{
		HANDLE hSonicProcess = OpenProcess(dwDesiredAccess, bInheritHandle, reinterpret_cast<DWORD>(overlapped));
		if (hSonicProcess && hSonicProcess != INVALID_HANDLE_VALUE)
		{
			GetModuleFileNameExA(hSonicProcess, 0, buffer, MAX_PATH);
			printf("Sonic process handled %u(%p) %s\n", GetProcessId(hSonicProcess), hSonicProcess, buffer);

			std::string szProcessImageFileName = buffer;
			std::transform(szProcessImageFileName.begin(), szProcessImageFileName.end(), szProcessImageFileName.begin(), tolower);

			auto posLastSlash = szProcessImageFileName.find_last_of("\\/");
			szProcessImageFileName = szProcessImageFileName.substr(posLastSlash + 1, szProcessImageFileName.length() - posLastSlash);

			printf("Parsed name: %s\n", szProcessImageFileName.c_str());

			if (szProcessImageFileName == szTargetProcessName)
			{
				hTarget = hSonicProcess;
				PostQueuedCompletionStatus(hIOPort, NULL, NULL, NULL);
				break;
			}
			CloseHandle(hSonicProcess);
		}
		Sleep(1);
	}

	return hTarget;
}

HANDLE GetSonicHandle(const std::string & szWatchedProcessName, const std::string & szTargetProcessName, DWORD dwDesiredAccess, BOOL bInheritHandle)
{
	// Predefined veriables
	std::vector <HANDLE> vWatchedProcessHandles;
	std::vector <DWORD>  vWatchedProcessList;
	bool bAssignedToAnyProcess = false;
	JOBOBJECT_ASSOCIATE_COMPLETION_PORT jobIOport;

	// Common arg checks
	if (szWatchedProcessName.empty() || szTargetProcessName.empty())
		goto clean;

	// Process infos
	printf("Watched process name: %s\n", szWatchedProcessName.c_str());

	vWatchedProcessList = GetProcessIdsFromProcessName(szWatchedProcessName.c_str());
	if (vWatchedProcessList.empty())
		goto clean;

	printf("Watched process list size: %u\n", vWatchedProcessList.size());

	/* Creating job to get instant notification of new child processes */
	auto hIOPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, NULL, NULL);
	if (!hIOPort)
		goto clean;

	auto hJobObject = CreateJobObjectA(NULL, NULL);
	if (!hJobObject)
		goto clean;
	
	jobIOport.CompletionKey = NULL;
	jobIOport.CompletionPort = hIOPort;
	auto bSetInfoJobObjStatus = SetInformationJobObject(hJobObject, JobObjectAssociateCompletionPortInformation, &jobIOport, sizeof(jobIOport));
	if (!bSetInfoJobObjStatus)
		goto clean;
	
	for (auto & dwCurrentWatchedProcessId : vWatchedProcessList)
	{
		printf("Watched process id: %u\n", dwCurrentWatchedProcessId);

		auto hWatchedProcess = OpenProcess(PROCESS_SET_QUOTA | PROCESS_TERMINATE, TRUE, dwCurrentWatchedProcessId);
		if (hWatchedProcess && hWatchedProcess != INVALID_HANDLE_VALUE)
		{
			printf("Watched process handle: %p\n", hWatchedProcess);

			if (AssignProcessToJobObject(hJobObject, hWatchedProcess))
				bAssignedToAnyProcess = true;
			else
				printf("Error! Can not assigned to: %u\n", dwCurrentWatchedProcessId);

			vWatchedProcessHandles.emplace_back(hWatchedProcess);
		}
	}

	if (!bAssignedToAnyProcess)
		goto clean;

	// Create IO watcher
	auto hTarget = GetHandleForIOProcesses(hIOPort, szTargetProcessName, dwDesiredAccess, bInheritHandle);
	if (!hTarget || hTarget == INVALID_HANDLE_VALUE)
		goto clean;
 
	/* Cleanup before returning handle */
clean:
	for (auto & hCurrentWatchedProcess : vWatchedProcessHandles)
	{
		if (hCurrentWatchedProcess && hCurrentWatchedProcess != INVALID_HANDLE_VALUE)
			CloseHandle(hCurrentWatchedProcess);
	}

	if (hIOPort && hIOPort != INVALID_HANDLE_VALUE)
		CloseHandle(hIOPort);

	if (hJobObject && hJobObject != INVALID_HANDLE_VALUE)
		CloseHandle(hJobObject);

	return hTarget;
}

