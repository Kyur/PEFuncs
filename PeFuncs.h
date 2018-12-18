#pragma once
#include <Windows.h>

// Do not use this structure direct
typedef struct _PEHANDLE
{
	DWORD fileFullSize;
	PBYTE pFile;

	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

}PEHANDLE, *PPEHANDLE;


// Inner Functions
// Do not use this fucntions.
EXTERN_C __declspec(dllexport) BOOL ParsePE(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetDosHeaderStructure(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetNtHeaderStructure(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetSectionHeaderStructure(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL CheckSectionNumberRange(PPEHANDLE, DWORD);


// ---------------------------------------- Service Functions ----------------------------------------

// Create/Close PE Handle
// ClosePeHandle must be used after you work
EXTERN_C __declspec(dllexport) PPEHANDLE CreatePeHandle(HANDLE hFile);
EXTERN_C __declspec(dllexport) BOOL ClosePeHandle(PPEHANDLE);

// Normal functions
EXTERN_C __declspec(dllexport) BOOL IsPeFile(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL HasExtraSection(PPEHANDLE);
EXTERN_C __declspec(dllexport) DWORD RVAtoRAW(PPEHANDLE, DWORD);
EXTERN_C __declspec(dllexport) DWORD RVAtoVA(PPEHANDLE, DWORD);

// With IMAGE_FILE_HADER fucnctions
EXTERN_C __declspec(dllexport) DWORD GetNumberOfSections(PPEHANDLE);

// With IMAGE_OPTIONAL_HEADER fuctions
EXTERN_C __declspec(dllexport) DWORD GetEntryPointRVA(PPEHANDLE);
EXTERN_C __declspec(dllexport) DWORD GetEntryPointRAW(PPEHANDLE);
EXTERN_C __declspec(dllexport) DWORD GetImageBase(PPEHANDLE);
EXTERN_C __declspec(dllexport) DWORD GetSizeOfImage(PPEHANDLE);

// With IMAGE_SECTION_HEADER functions
EXTERN_C __declspec(dllexport) DWORD GetSectionVirtualAddress(PPEHANDLE, DWORD);
EXTERN_C __declspec(dllexport) DWORD GetSectionVirtualSize(PPEHANDLE, DWORD);
EXTERN_C __declspec(dllexport) DWORD GetSectionSizeOfRawData(PPEHANDLE, DWORD);
EXTERN_C __declspec(dllexport) DWORD GetSectionPointerToRawData(PPEHANDLE, DWORD);