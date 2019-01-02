#include "PeFuncs.h"


// PEHANDLE Structure
struct _PEHANDLE
{
	DWORD fileFullSize;

	IMAGE_DOS_HEADER dosHeader;
	IMAGE_NT_HEADERS ntHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	PBYTE pFile;
};


// ----- PE Headers size
#define SIZE_IMAGE_SECTION_HEADER sizeof(IMAGE_SECTION_HEADER)
#define SIZE_IMAGE_NT_HEAEDER sizeof(IMAGE_NT_HEADERS)
#define SIZE_IMAGE_FILE_HEADER sizeof(IMAGE_FILE_HEADER)
#define SIZE_IMAGE_OPTIONAL_HEADER sizeof(IMAGE_OPTIONAL_HEADER)

// ----- Value for inner function
#define FIRST_SECTION 0x01
#define SIZE_IMAGE_NT_HEADER_SIGNATURE 0x04

// ----- Macro
#define ConvertUserIndex(REAL_INDEX) --REAL_INDEX



// ==================== Inner Functions

BOOL ParsePE(PEHANDLE hPe)
{

	if (!SetDosHeaderStructure(hPe))
		return FALSE;

	if (!SetNtHeaderStructure(hPe))
		return FALSE;

	if (!SetSectionHeaderStructure(hPe))
		return FALSE;
}


BOOL SetDosHeaderStructure(PEHANDLE hPe)
{
	memcpy(&hPe->dosHeader, hPe->pFile, sizeof(IMAGE_DOS_HEADER));

	return TRUE;
}


BOOL SetNtHeaderStructure(PEHANDLE hPe)
{
	PBYTE pNtHeader = NULL;

	pNtHeader = (PBYTE)(hPe->pFile + hPe->dosHeader.e_lfanew);
	memcpy(&hPe->ntHeader, pNtHeader, sizeof(IMAGE_NT_HEADERS));

	return TRUE;
}


BOOL SetSectionHeaderStructure(PEHANDLE hPe)
{
	DWORD dwSectionHeaderStartOffset = 0;
	DWORD dwNumberOfSections = 0;

	dwNumberOfSections = GetNumberOfSections(hPe);

	hPe->pSectionHeader = (PIMAGE_SECTION_HEADER)VirtualAlloc(NULL, (SIZE_IMAGE_SECTION_HEADER * dwNumberOfSections), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	dwSectionHeaderStartOffset = GetSectionHeaderOffset(hPe, FIRST_SECTION);
	if (dwSectionHeaderStartOffset != PE_INVAILD_VALUE)
	{
		memcpy(hPe->pSectionHeader, (hPe->pFile + dwSectionHeaderStartOffset), (SIZE_IMAGE_SECTION_HEADER * dwNumberOfSections));
		return TRUE;
	}

	OutputDebugStringFormat("ERROR: SetSectionHeaderStructure(), Invaild Section header start offset");
	return FALSE;
}


BOOL CheckSectionNumberRange(PEHANDLE hPe, DWORD nSectionCnt)
{
	if ((0 < nSectionCnt) && (nSectionCnt <= hPe->ntHeader.FileHeader.NumberOfSections))
		return TRUE;

	return FALSE;
}


VOID OutputDebugStringFormat(const char* str, ...)
{
	va_list vaList_dbgStr;
	char errorStr[MAX_PATH] = { 0, };

	va_start(vaList_dbgStr, str);
	vsprintf(errorStr, str, vaList_dbgStr);
	va_end(vaList_dbgStr);

	OutputDebugString(errorStr);
}


// ---------------------------------------- Service Functions ----------------------------------------

// ==================== Create/Close PE Handle

PEHANDLE CreatePeHandle(HANDLE hFile)
{
	DWORD lpNumberOfBytesRead = 0;
	DWORD dwNumberOfSectionsTemp = 0;
	PEHANDLE hPe = NULL;


	// Create PEHANDLE structure
	hPe = (PEHANDLE)VirtualAlloc(NULL, sizeof(_PEHANDLE), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (hPe == NULL)
		return NULL;


	// Load target data (full size)
	hPe->fileFullSize = GetFileSize(hFile, NULL);
	hPe->pFile = (PBYTE)VirtualAlloc(NULL, hPe->fileFullSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	ReadFile(hFile, hPe->pFile, hPe->fileFullSize, &lpNumberOfBytesRead, NULL);
	if (lpNumberOfBytesRead == 0)
		return NULL;


	// Set basic PE infomation
	if (!ParsePE(hPe))
		return NULL;

	return hPe;
}


BOOL ClosePeHandle(PEHANDLE hPe)
{
	// Release target file data
	if (VirtualFree(hPe->pFile, 0x00, MEM_RELEASE) == 0)
	{
		OutputDebugStringFormat("ERROR: VirtualFree(hPe->pFile) %08X", GetLastError());
		return FALSE;
	}

	// Relase IMAGE_SECTION_HEADER
	if (VirtualFree(hPe->pSectionHeader, 0x00, MEM_RELEASE) == 0)
	{
		OutputDebugStringFormat("ERROR: VirtualFree(hPe->pSectionHeader) %08X", GetLastError());
		return FALSE;
	}

	// Release PEHANDLE structure
	if (VirtualFree(hPe, 0x00, MEM_RELEASE) == 0)
	{
		OutputDebugStringFormat("ERROR: VirtualFree(hPe) %08X", GetLastError());
		return FALSE;
	}

	return TRUE;
}



// ==================== Normal functions

BOOL IsPeFile(PEHANDLE hPe)
{
	if (hPe->dosHeader.e_magic == IMAGE_DOS_SIGNATURE)
	{
		if (hPe->ntHeader.Signature == IMAGE_NT_SIGNATURE)
		{
			return TRUE;
		}
	}

	return FALSE;
}


BOOL HasExtraSection(PEHANDLE hPe)
{
	DWORD dwTotalSectionSize = 0;
	DWORD sectionCnt = 0;
	PIMAGE_SECTION_HEADER _pSectionHeader = NULL;

	_pSectionHeader = hPe->pSectionHeader;

	for (sectionCnt = 1; sectionCnt <= (hPe->ntHeader.FileHeader.NumberOfSections); sectionCnt++)
	{
		if (sectionCnt == (hPe->ntHeader.FileHeader.NumberOfSections))
		{
			dwTotalSectionSize = _pSectionHeader->PointerToRawData;
			dwTotalSectionSize += _pSectionHeader->SizeOfRawData;

			break;
		}

		_pSectionHeader++;
	}

	if (dwTotalSectionSize < hPe->fileFullSize)
	{
		return TRUE;
	}

	return FALSE;
}


DWORD RVAtoRAW(PEHANDLE hPe, DWORD dwRva)
{
	DWORD returnVal = 0;
	DWORD sectionCnt = 0;
	DWORD dwSectionHeaderIndex = 0;
	PIMAGE_SECTION_HEADER _pSectionHeader = NULL;

	_pSectionHeader = hPe->pSectionHeader;

	for (sectionCnt = 0; sectionCnt < (hPe->ntHeader.FileHeader.NumberOfSections); sectionCnt++)
	{
		if ((_pSectionHeader->VirtualAddress <= dwRva) &&
			dwRva <= (_pSectionHeader->VirtualAddress) + (_pSectionHeader->Misc.VirtualSize))
		{
			returnVal = (dwRva - _pSectionHeader->VirtualAddress) + _pSectionHeader->PointerToRawData;

			return returnVal;
		}

		_pSectionHeader++;
	}

	//printf("Cannot Search RVA Range.\n");
	return 0;
}


DWORD RVAtoVA(PEHANDLE hPe, DWORD dwRva)
{
	return hPe->ntHeader.OptionalHeader.ImageBase + dwRva;
}



// ==================== IMAGE_DOS_HEADER functions

DWORD GetElfanewValue(PEHANDLE hPe)
{
	return hPe->dosHeader.e_lfanew;
}



// ==================== IMAGE_FILE_HADER funcctions

DWORD GetNumberOfSections(PEHANDLE hPe)
{
	DWORD dwNumberOfSections = 0;

	if ((dwNumberOfSections = hPe->ntHeader.FileHeader.NumberOfSections) <= 0x00)
	{
		OutputDebugStringFormat("ERROR: GetNumberOfSections(), Invaild NumberOfSections");
		return PE_INVAILD_VALUE;
	}
		
	return dwNumberOfSections;
}



// ==================== IMAGE_OPTIONAL_HEADER functions

DWORD GetEntryPointRVA(PEHANDLE hPe)
{
	DWORD dwEntryPointRva = 0;

	if (!(dwEntryPointRva = hPe->ntHeader.OptionalHeader.AddressOfEntryPoint))
		return 0;

	return dwEntryPointRva;
}


DWORD GetEntryPointRAW(PEHANDLE hPe)
{
	DWORD dwEntryPointRva = 0;
	DWORD dwEntryPointRaw = 0;

	dwEntryPointRva = GetEntryPointRVA(hPe);
	dwEntryPointRaw = RVAtoRAW(hPe, dwEntryPointRva);

	if (dwEntryPointRaw == 0)
		return 0;

	return dwEntryPointRaw;
}


DWORD GetImageBase(PEHANDLE hPe)
{
	return hPe->ntHeader.OptionalHeader.ImageBase;
}


DWORD GetSizeOfImage(PEHANDLE hPe)
{
	return hPe->ntHeader.OptionalHeader.SizeOfImage;
}


// ==================== IMAGE_SECTION_HEADER functions

DWORD GetSectionHeaderOffset(PEHANDLE hPe, DWORD nSection)
{
	DWORD dwOffsetFirstSectionHeader = 0;

	if ( !CheckSectionNumberRange(hPe, nSection) )
	{
		OutputDebugStringFormat("ERROR: GetSectionHeaderOffset(), Invaild section number.");
		return PE_INVAILD_VALUE;
	}

	ConvertUserIndex(nSection);

	dwOffsetFirstSectionHeader = GetElfanewValue(hPe) + SIZE_IMAGE_NT_HEAEDER;
	return dwOffsetFirstSectionHeader + (SIZE_IMAGE_SECTION_HEADER * nSection);
}


DWORD GetVirtualAddress(PEHANDLE hPe, DWORD nSection)
{
	DWORD sectionVirtualAddress = 0;
	
	if ( !CheckSectionNumberRange(hPe, nSection) )
	{
		OutputDebugStringFormat("ERROR: GetVirtualAddress(), Invaild section number.");
		return PE_INVAILD_VALUE;
	}
	
	ConvertUserIndex(nSection);

	sectionVirtualAddress = (hPe->pSectionHeader + nSection)->VirtualAddress;
	return sectionVirtualAddress;
}


DWORD GetVirtualSize(PEHANDLE hPe, DWORD nSection)
{
	DWORD sectionVirtualSize = 0;

	if ( !CheckSectionNumberRange(hPe, nSection) )
	{
		OutputDebugStringFormat("ERROR: GetVirtualSize(), Invaild section number.");
		return PE_INVAILD_VALUE;
	}

	ConvertUserIndex(nSection);

	sectionVirtualSize = ((hPe->pSectionHeader) + nSection)->Misc.VirtualSize;
	return sectionVirtualSize;
}


DWORD GetSizeOfRawData(PEHANDLE hPe, DWORD nSection)
{
	DWORD sectionSizeOfRawData = 0;

	if ( !CheckSectionNumberRange(hPe, nSection) )
	{
		OutputDebugStringFormat("ERROR: GetSizeOfRawData(), Invaild section number.");
		return PE_INVAILD_VALUE;
	}

	ConvertUserIndex(nSection);

	sectionSizeOfRawData = (hPe->pSectionHeader + nSection)->SizeOfRawData;
	return sectionSizeOfRawData;
}


DWORD GetPointerToRawData(PEHANDLE hPe, DWORD nSection)
{
	DWORD sectionPointerToRawdata = 0;

	if ( !CheckSectionNumberRange(hPe, nSection) )
	{
		OutputDebugStringFormat("ERROR: GetPointerToRawData(), Invaild section number.");
		return PE_INVAILD_VALUE;
	}

	ConvertUserIndex(nSection);

	sectionPointerToRawdata = (hPe->pSectionHeader + nSection)->PointerToRawData;
	return sectionPointerToRawdata;
}


