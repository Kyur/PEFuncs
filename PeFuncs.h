#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>

#define PE_INVAILD_VALUE 0xFFFFFFFF

typedef struct _PEHANDLE* PEHANDLE;


// Inner Functions
// Do not use this fucntions.
EXTERN_C __declspec(dllexport) BOOL ParsePE(PEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetDosHeaderStructure(PEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetNtHeaderStructure(PEHANDLE);
EXTERN_C __declspec(dllexport) BOOL SetSectionHeaderStructure(PEHANDLE);
EXTERN_C __declspec(dllexport) BOOL CheckSectionNumberRange(PEHANDLE, DWORD);

EXTERN_C __declspec(dllexport) VOID OutputDebugStringFormat(const char*, ...);


// ---------------------------------------- Service Functions ----------------------------------------

// Create/Close PE Handle
// ClosePeHandle must be used after you work
EXTERN_C __declspec(dllexport) PEHANDLE CreatePeHandle(HANDLE hFile);
EXTERN_C __declspec(dllexport) BOOL ClosePeHandle(PEHANDLE hPe);

// Normal functions
EXTERN_C __declspec(dllexport) BOOL IsPeFile(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) BOOL HasExtraSection(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD RVAtoRAW(PEHANDLE hPe, DWORD dwRva);
EXTERN_C __declspec(dllexport) DWORD RVAtoVA(PEHANDLE hPe, DWORD dwRva);

// IMAGE_DOS_HEADER functions
EXTERN_C __declspec(dllexport) DWORD GetElfanewValue(PEHANDLE hPe);

// IMAGE_FILE_HADER funcctions
EXTERN_C __declspec(dllexport) DWORD GetNumberOfSections(PEHANDLE hPe);

// IMAGE_OPTIONAL_HEADER functions
EXTERN_C __declspec(dllexport) DWORD GetEntryPointRVA(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD GetEntryPointRAW(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD GetImageBase(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD GetSizeOfImage(PEHANDLE hPe);

// IMAGE_SECTION_HEADER functions
EXTERN_C __declspec(dllexport) DWORD GetSectionHeaderOffset(PEHANDLE hPe, DWORD nSection);
EXTERN_C __declspec(dllexport) DWORD GetVirtualAddress(PEHANDLE hPe, DWORD nSection);
EXTERN_C __declspec(dllexport) DWORD GetVirtualSize(PEHANDLE hPe, DWORD nSection);
EXTERN_C __declspec(dllexport) DWORD GetSizeOfRawData(PEHANDLE hPe, DWORD nSection);
EXTERN_C __declspec(dllexport) DWORD GetPointerToRawData(PEHANDLE hPe, DWORD nSection);


