#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <thread>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

extern bool g_bHandleTraceStopped;
typedef void(__cdecl* _OnHandleCreated)(
	_In_ HANDLE hProcess
);
extern void OnHandleCreated(HANDLE hProcess);
extern void GetSonicHandle(const std::string & szWatchedProcessName, const std::string & szTargetProcessName, DWORD dwDesiredAccess, BOOL bInheritHandle, _OnHandleCreated callback);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;


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

