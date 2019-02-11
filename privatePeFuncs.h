#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>


#define PE_INVAILD_VALUE 0xFFFFFFFF
#define MAX_TYPE_NAME_LIST 0x20

#define UNSTABLE_PE_HEADER_SIGNATURE_MZ 0x00000001
#define UNSTABLE_PE_HEADER_SIGNATURE_PE 0x00000002

// ----- PE Headers size
#define SIZE_OF_IMAGE_SECTION_HEADER sizeof(IMAGE_SECTION_HEADER)
#define SIZE_OF_IMAGE_NT_HEAEDER sizeof(IMAGE_NT_HEADERS)
#define SIZE_OF_IMAGE_FILE_HEADER sizeof(IMAGE_FILE_HEADER)
#define SIZE_OF_IMAGE_OPTIONAL_HEADER sizeof(IMAGE_OPTIONAL_HEADER)

typedef struct _PEHANDLE* PEHANDLE;

// Inner Functions
// Do not use this fucntions.
BOOL ParsePE(PEHANDLE);
BOOL SetDosHeaderStructure(PEHANDLE);
BOOL SetNtHeaderStructure(PEHANDLE);
BOOL SetSectionHeaderStructure(PEHANDLE);
BOOL CheckSectionNumberRange(PEHANDLE, DWORD);
BOOL WritePEValueToFile(PEHANDLE hPe, DWORD dwFileOffset, DWORD dwValue, DWORD cSize);
BOOL IsValidFileHandle(PEHANDLE hPe);
DWORD GetFileOffset(PEHANDLE hPe, PVOID pMemOffset);

VOID OutputDebugStringFormat(const char*, ...);


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
EXTERN_C __declspec(dllexport) BOOL CheckElfanewValueRange(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD GetElfanewValue(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) BOOL SetElfanewValue(PEHANDLE hPe, DWORD dwNewElfanew);

// IMAGE_FILE_HADER functions
EXTERN_C __declspec(dllexport) WORD GetMachineCode(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) BOOL GetMachineCodeName(PEHANDLE hPe, char* szMachineCodeName);
EXTERN_C __declspec(dllexport) WORD GetNumberOfSections(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD GetTimeDataStamp(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) char* GetTimeDataStampToTime(PEHANDLE hPe);

EXTERN_C __declspec(dllexport) DWORD GetPointerToSymbolTable(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) DWORD GetNumberOfSymbls(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) WORD GetSizeOfOptionalHeader(PEHANDLE hPe);
EXTERN_C __declspec(dllexport) WORD GetFileHeaderCharacteristics(PEHANDLE hPe);
//EXTERN_C __declspec(dllexport) VOID GetFileHeaderCharacteristicsElement(PEHANDLE hPe, _PTYPE_NAME_LIST &fileHeaderCharacteristicsElement);

EXTERN_C __declspec(dllexport) BOOL SetNumberOfSections(PEHANDLE hPe, WORD wNewNumberOfSections);


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


