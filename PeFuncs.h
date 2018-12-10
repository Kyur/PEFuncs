#pragma once
#include <Windows.h>

typedef struct _PEHANDLE
{
	DWORD fileFullSize;
	PBYTE pFile;

	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

}PEHANDLE, *PPEHANDLE;


// Create/Close PE Handle
EXTERN_C __declspec(dllexport) PPEHANDLE CreatePeHandle(HANDLE hFile);
EXTERN_C __declspec(dllexport) BOOL ClosePeHandle(PPEHANDLE);

// Inner Functions
EXTERN_C __declspec(dllexport) BOOL ParsePE(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetDosHeaderStructure(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetNtHeaderStructure(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetSectionHeaderStructure(PPEHANDLE);

// Service Functions
EXTERN_C __declspec(dllexport) BOOL IsPeFile(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL HasExtraSection(PPEHANDLE);

EXTERN_C __declspec(dllexport) DWORD GetNumberOfSections(PPEHANDLE);
EXTERN_C __declspec(dllexport) DWORD GetEntryPointRVA(PPEHANDLE);
EXTERN_C __declspec(dllexport) DWORD GetEntryPointRAW(PPEHANDLE);
EXTERN_C __declspec(dllexport) DWORD RVAtoRAW(PPEHANDLE, DWORD);
EXTERN_C __declspec(dllexport) DWORD RVAtoVA(PPEHANDLE, DWORD);