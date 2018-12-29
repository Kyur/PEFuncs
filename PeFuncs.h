#pragma once
#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>

#define PE_INVAILD_VALUE 0xFFFFFFFF


// Do not use this structure direct
typedef struct _PEHANDLE
{
	DWORD fileFullSize;

	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	PBYTE pFile;

}PEHANDLE, *PPEHANDLE;


// Inner Functions
// Do not use this fucntions.
EXTERN_C __declspec(dllexport) BOOL ParsePE(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetDosHeaderStructure(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetNtHeaderStructure(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetSectionHeaderStructure(PPEHANDLE);
EXTERN_C __declspec(dllexport) BOOL CheckSectionNumberRange(PPEHANDLE, DWORD);

EXTERN_C __declspec(dllexport) VOID OutputDebugStringFormat(const char*, ...);


// ---------------------------------------- Service Functions ----------------------------------------

// Create/Close PE Handle
// ClosePeHandle must be used after you work
EXTERN_C __declspec(dllexport) PPEHANDLE CreatePeHandle(HANDLE hFile);
EXTERN_C __declspec(dllexport) BOOL ClosePeHandle(PPEHANDLE hPe);

// Normal functions
EXTERN_C __declspec(dllexport) BOOL IsPeFile(PPEHANDLE hPe);
EXTERN_C __declspec(dllexport) BOOL HasExtraSection(PPEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD RVAtoRAW(PPEHANDLE hPe, DWORD dwRva);
EXTERN_C __declspec(dllexport) DWORD RVAtoVA(PPEHANDLE hPe, DWORD dwRva);

// IMAGE_DOS_HEADER functions
EXTERN_C __declspec(dllexport) DWORD GetElfanewValue(PPEHANDLE hPe);

// IMAGE_FILE_HADER funcctions
EXTERN_C __declspec(dllexport) DWORD GetNumberOfSections(PPEHANDLE hPe);

// IMAGE_OPTIONAL_HEADER functions
EXTERN_C __declspec(dllexport) DWORD GetEntryPointRVA(PPEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD GetEntryPointRAW(PPEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD GetImageBase(PPEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD GetSizeOfImage(PPEHANDLE hPe);

// IMAGE_SECTION_HEADER functions
EXTERN_C __declspec(dllexport) DWORD GetSectionHeaderOffset(PPEHANDLE hPe, DWORD nSection);
EXTERN_C __declspec(dllexport) DWORD GetVirtualAddress(PPEHANDLE hPe, DWORD nSection);
EXTERN_C __declspec(dllexport) DWORD GetVirtualSize(PPEHANDLE hPe, DWORD nSection);
EXTERN_C __declspec(dllexport) DWORD GetSizeOfRawData(PPEHANDLE hPe, DWORD nSection);
EXTERN_C __declspec(dllexport) DWORD GetPointerToRawData(PPEHANDLE hPe, DWORD nSection);


