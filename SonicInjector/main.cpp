#include "main.h"
#pragma comment(lib, "psapi.lib")

typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
	PHANDLE hThread, 
	ACCESS_MASK DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	HANDLE ProcessHandle, 
	LPTHREAD_START_ROUTINE lpStartAddress, 
	LPVOID lpParameter, 
	ULONG CreateFlags, 
	ULONG_PTR StackZeroBits,
	SIZE_T SizeOfStackCommit, 
	SIZE_T SizeOfStackReserve, 
	LPVOID AttributeList
);
typedef HMODULE(WINAPI* _LoadLibraryA)(
	_In_ LPCTSTR lpFileName
);
typedef FARPROC(WINAPI* _GetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR  lpProcName
);
typedef BOOL(WINAPI* _DllMain)(
	HINSTANCE	hinstDLL,
	DWORD		fdwReason,
	LPVOID		lpReserved
);

typedef struct _PREMOTE_THREAD_PARAM
{
	PVOID			ImageBase;
	PIMAGE_NT_HEADERS			NtHeaders;
	PIMAGE_BASE_RELOCATION		BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR	ImportDirectory;
	_LoadLibraryA	LoadLibraryA;
	_GetProcAddress GetProcAddress;
}REMOTE_THREAD_PARAM, *PREMOTE_THREAD_PARAM;

DWORD WINAPI RemoteThreadRoutine(LPVOID lpParam)
{
	auto param = (PREMOTE_THREAD_PARAM)lpParam;

	HMODULE hModule;
	DWORD Function, count;

	PDWORD ptr;
	PWORD list;

	PIMAGE_IMPORT_BY_NAME pIBN;
	PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

	auto delta = (DWORD)((LPBYTE)param->ImageBase - param->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	// Relocate the image
	auto pIBR = param->BaseRelocation;
	while (pIBR->VirtualAddress)
	{
		if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list = (PWORD)(pIBR + 1);

			for (DWORD i = 0; i < count; i++)
			{
				if (list[i])
				{
					ptr = (PDWORD)((LPBYTE)param->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
	}

	// Resolve DLL imports
	auto pIID = param->ImportDirectory;
	while (pIID->Characteristics)
	{
		OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)param->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)param->ImageBase + pIID->FirstThunk);

		hModule = param->LoadLibraryA((LPCSTR)param->ImageBase + pIID->Name);
		if (!hModule)
			return 0;

		while (OrigFirstThunk->u1.AddressOfData)
		{
			if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal
				Function = (DWORD)param->GetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));
				if (!Function)
					return 0;

				FirstThunk->u1.Function = Function;
			}

			else
			{
				// Import by name
				pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)param->ImageBase + OrigFirstThunk->u1.AddressOfData);

				Function = (DWORD)param->GetProcAddress(hModule, (LPCSTR)pIBN->Name);
				if (!Function)
					return 0;

				FirstThunk->u1.Function = Function;
			}

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	if (param->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		auto EntryPoint = (_DllMain)((LPBYTE)param->ImageBase + param->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)param->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}

	return 0;
}

static int UselessFunction()
{
	return 0;
}

bool LoadDLL(HANDLE hProcess, const wchar_t* c_wszModule)
{
	bool bResult = false;

	// Ntdll & apis
	auto hNtdll = LoadLibraryA("ntdll");
	if (!hNtdll) {
		printf("LoadLibraryA fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	auto NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
	if (!NtCreateThreadEx) {
		printf("NtCreateThreadEx not found!\n");
		goto skip;
	}

	// Store file bytes to memory
	auto hFile = CreateFileW(c_wszModule, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (!hFile || hFile == INVALID_HANDLE_VALUE) {
		printf("CreateFileW fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	auto dwFileSize = GetFileSize(hFile, NULL);
	if (!dwFileSize || dwFileSize == INVALID_FILE_SIZE) {
		printf("GetFileSize fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	auto pFileBuffer = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pFileBuffer) {
		printf("VirtualAlloc fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	DWORD dwReadedByteCount;
	if (!ReadFile(hFile, pFileBuffer, dwFileSize, &dwReadedByteCount, NULL)) {
		printf("ReadFile fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	CloseHandle(hFile);

	/// Header & Characteristic check
	auto pIDH = (PIMAGE_DOS_HEADER)pFileBuffer;
	if (pIDH->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Dos header check fail! File can not executable!\n");
		goto skip;
	}

	auto pINH = (PIMAGE_NT_HEADERS)((LPBYTE)pFileBuffer + pIDH->e_lfanew);
	if (pINH->Signature != IMAGE_NT_SIGNATURE) {
		printf("Nt header check fail! Invalid PE Header!\n");
		goto skip;
	}

	if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		printf("Characteristic check fail! File is not a dll!\n");
		goto skip;
	}

	auto pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);

	// Create memory for store file on target process
	auto pRemoteFileBuffer = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!pRemoteFileBuffer) {
		printf("VirtualAllocEx fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	// Copy PE headers
	if (!WriteProcessMemory(hProcess, pRemoteFileBuffer, pFileBuffer, pINH->OptionalHeader.SizeOfHeaders, NULL)) {
		printf("WriteProcessMemory fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	// Copy sections
	for (WORD i = 0; i<pINH->FileHeader.NumberOfSections; i++)
	{
		if (!pISH[i].PointerToRawData && !pISH[i].VirtualAddress) {
			printf("Null raw data pointer or virtual address!\n");
			goto skip;
		}

		WriteProcessMemory(hProcess, (PVOID)((LPBYTE)pRemoteFileBuffer + pISH[i].VirtualAddress), (PVOID)((LPBYTE)pFileBuffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
	}

	// Loader
	auto pRemoteLoader = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE); // Allocate memory for the loader code
	if (!pRemoteLoader) {
		VirtualFreeEx(hProcess, pRemoteFileBuffer, 0, MEM_RELEASE);
		printf("VirtualAllocEx(2) fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	// Create remote param
	REMOTE_THREAD_PARAM RemoteThreadParam;
	memset(&RemoteThreadParam, 0, sizeof(REMOTE_THREAD_PARAM));

	RemoteThreadParam.ImageBase = pRemoteFileBuffer;
	RemoteThreadParam.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)pRemoteFileBuffer + pIDH->e_lfanew);
	RemoteThreadParam.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRemoteFileBuffer + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	RemoteThreadParam.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pRemoteFileBuffer + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	RemoteThreadParam.LoadLibraryA = (_LoadLibraryA)LoadLibraryA;
	RemoteThreadParam.GetProcAddress = (_GetProcAddress)GetProcAddress;

	// Write to target process
	auto bWriteRemoteParam = WriteProcessMemory(hProcess, pRemoteLoader, &RemoteThreadParam, sizeof(REMOTE_THREAD_PARAM), NULL); // Write the loader information to target process
	if (!bWriteRemoteParam) {
		VirtualFreeEx(hProcess, pRemoteFileBuffer, 0, MEM_RELEASE);
		printf("WriteProcessMemory fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	auto bWriteRemoteCode = WriteProcessMemory(hProcess, (PVOID)((PREMOTE_THREAD_PARAM)pRemoteLoader + 1), RemoteThreadRoutine, (DWORD)UselessFunction - (DWORD)RemoteThreadRoutine, NULL); // Write the loader code to target process
	if (!bWriteRemoteCode) {
		VirtualFreeEx(hProcess, pRemoteFileBuffer, 0, MEM_RELEASE);
		printf("WriteProcessMemory(2) fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	// Create thread
	HANDLE hThread = INVALID_HANDLE_VALUE;
	auto ntStatus = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, 0, hProcess, (LPTHREAD_START_ROUTINE)((PREMOTE_THREAD_PARAM)pRemoteLoader + 1), pRemoteLoader, 0, 0, 0, 0, 0);
	if (ntStatus != (NTSTATUS)0x00000000L || !hThread || hThread == INVALID_HANDLE_VALUE) {
		VirtualFreeEx(hProcess, pRemoteFileBuffer, 0, MEM_RELEASE);
		printf("NtCreateThreadEx fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	// Wait
	WaitForSingleObject(hThread, INFINITE);

	// Finalize
	DWORD dwThreadExitCode;
	if (!GetExitCodeThread(hThread, &dwThreadExitCode)) {
		VirtualFreeEx(hProcess, pRemoteFileBuffer, 0, MEM_RELEASE);
		printf("GetExitCodeThread fail! Error code: %u\n", GetLastError());
		goto skip;
	}

	printf("DLL injected at %p\n", pRemoteFileBuffer);

	if (pINH->OptionalHeader.AddressOfEntryPoint)
		printf("DLL entry point: %p\n", (PVOID)((LPBYTE)pRemoteFileBuffer + pINH->OptionalHeader.AddressOfEntryPoint));

	bResult = true;

skip:
	if (pFileBuffer)
		VirtualFree(pFileBuffer, 0, MEM_RELEASE);

	if (pRemoteLoader)
		VirtualFreeEx(hProcess, pRemoteLoader, 0, MEM_RELEASE);

	if (hFile && hFile != INVALID_HANDLE_VALUE)
		CloseHandle(hFile);

	if (hThread && hThread != INVALID_HANDLE_VALUE)
		CloseHandle(hThread);

	if (hProcess && hProcess != INVALID_HANDLE_VALUE)
		CloseHandle(hProcess);

	return bResult;
}

int main()
{
#if 0
	auto hGame = GetSonicHandle("steam.exe", "blacksquadgame.exe", PROCESS_ALL_ACCESS, FALSE);
	if (hGame && hGame != INVALID_HANDLE_VALUE)
	{
		std::wstring wszModuleName = L"C:\\Users\\Koray\\Desktop\\SonicInjector\\Release\\TestModule.dll";

		auto bLoadRet = LoadDLL(hGame, wszModuleName.c_str());
		if (bLoadRet)
			printf("Injection successfully completed!\n");
	}
#endif

	// Process inputs
	std::string szProcessName = "";
	printf("Process name: ");
	std::getline(std::cin, szProcessName);
	std::transform(szProcessName.begin(), szProcessName.end(), szProcessName.begin(), tolower);

	std::string szParentName = "";
	printf("Parent name: ");
	std::getline(std::cin, szParentName);
	std::transform(szParentName.begin(), szParentName.end(), szParentName.begin(), tolower);

	printf("Ready to get handle, please start target program.\n");

	// Game
	auto hGame = GetSonicHandle(szParentName, szProcessName, PROCESS_ALL_ACCESS, FALSE);
	if (!hGame || hGame == INVALID_HANDLE_VALUE) {
		printf("Handle can not created!\n");
		std::cin.get();
		return EXIT_SUCCESS;
	}

	printf("hGame: %p\n", hGame);

	// DLL input
	std::wstring wszModuleName = L"";
	printf("Module name(w/path):");
	std::getline(std::wcin, wszModuleName);
	std::transform(wszModuleName.begin(), wszModuleName.end(), wszModuleName.begin(), towlower);

	// Injection
	auto bLoadRet = LoadDLL(hGame, wszModuleName.c_str());
	if (!bLoadRet) {
		printf("DLL can not injected!\n");
		std::cin.get();
		return EXIT_SUCCESS;
	}

	printf("Process Completed!\n");
	std::cin.get();
	return EXIT_SUCCESS;
}

