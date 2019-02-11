#include "dataCalculator.h"
#include "privatePeFuncs.h"


// PEHANDLE Structure
struct _PEHANDLE
{
	HANDLE hFile;
	DWORD dwFileFullSize;

	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	PIMAGE_SECTION_HEADER pSectionHeader;

	PBYTE pFile;
};


// ----- Value for inner function
#define FIRST_SECTION 0x01
#define SIZE_OF_IMAGE_NT_HEADER_SIGNATURE 0x04

// ----- Macro
// Man index(1) -> Computer index(0)
#define ConvertUserIndex(REAL_INDEX) (--REAL_INDEX)




// ==================== Inner Functions

BOOL ParsePE(PEHANDLE hPe)
{
	if ( !SetDosHeaderStructure(hPe) )
	{
		OutputDebugStringFormat("ERROR: ParsePE(), fail to SetDosHeaderStructure() function.");
		return FALSE;
	}

	if ( !SetNtHeaderStructure(hPe) )
	{
		OutputDebugStringFormat("ERROR: ParsePE(), fail to SetNtHeaderStructure() function.");
		return FALSE;
	}

	if ( !SetSectionHeaderStructure(hPe) )
	{
		OutputDebugStringFormat("ERROR: ParsePE(), fail to SetSectionHeaderStructure() function.");
		return FALSE;
	}

	return TRUE;
}


BOOL SetDosHeaderStructure(PEHANDLE hPe)
{
	hPe->pDosHeader = (PIMAGE_DOS_HEADER)hPe->pFile;

	return TRUE;
}


BOOL SetNtHeaderStructure(PEHANDLE hPe)
{
	if ( !CheckElfanewValueRange(hPe) )
	{
		OutputDebugStringFormat("ERROR: SetNtHeaderStructure(), Invaild e_lfanew value.");
		return FALSE;
	}

	hPe->pNtHeader = (PIMAGE_NT_HEADERS)(hPe->pFile + GetElfanewValue(hPe));

	return TRUE;
}


BOOL SetSectionHeaderStructure(PEHANDLE hPe)
{
	DWORD dwSectionHeaderStartOffset = 0;

	dwSectionHeaderStartOffset = GetSectionHeaderOffset(hPe, FIRST_SECTION);
	
	if (dwSectionHeaderStartOffset == PE_INVAILD_VALUE)
	{
		OutputDebugStringFormat("ERROR: SetSectionHeaderStructure(), Invaild Section header start offset");
		return FALSE;
	}

	hPe->pSectionHeader = (PIMAGE_SECTION_HEADER)(hPe->pFile + dwSectionHeaderStartOffset);
	return TRUE;
}


BOOL CheckSectionNumberRange(PEHANDLE hPe, DWORD nSectionCnt)
{
	if ( (0 < nSectionCnt) && (nSectionCnt <= hPe->pNtHeader->FileHeader.NumberOfSections) )
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


BOOL WritePEValueToFile(PEHANDLE hPe, DWORD dwFileOffset, DWORD dwValue, DWORD cSize)
{
	DWORD lpNumberOfBytesWritten = 0;
	LARGE_INTEGER llFileOffset = { 0, };
	llFileOffset.QuadPart = dwFileOffset;

	
	if ( !IsValidFileHandle(hPe) )
	{
		OutputDebugStringFormat("ERROR: WritePEValueToFile().IsValidFileHandle()");
		return FALSE;
	}

	if ( cSize == 0 )
	{
		OutputDebugStringFormat("ERROR: WritePEValueToFile(), cSize cannot have 0");
		return FALSE;
	}
	

	if (!SetFilePointerEx(hPe->hFile, llFileOffset, NULL, FILE_BEGIN))
	{
		OutputDebugStringFormat("ERROR: WritePEValueToFile().SetFilePointerEx(), %08X", GetLastError());
		return FALSE;
	}

	if ( !WriteFile(hPe->hFile, &dwValue, cSize, &lpNumberOfBytesWritten, NULL) )
	{
		OutputDebugStringFormat("ERROR: WritePEValueToFile().WriteFile(), %08X", GetLastError());
		return FALSE;
	}

	if ( lpNumberOfBytesWritten == 0 )
	{
		OutputDebugStringFormat("ERROR: WritePEValueToFile(), lpNumberOfBytesWritten is 0");
		return FALSE;
	}

	return TRUE;
}


BOOL IsValidFileHandle(PEHANDLE hPe)
{
	BOOL bFileInfo = FALSE;
	BY_HANDLE_FILE_INFORMATION lpFileInformation = { 0x00, };


	bFileInfo = GetFileInformationByHandle(hPe->hFile, &lpFileInformation);

	if ( bFileInfo == FALSE )
	{
		OutputDebugStringFormat("ERROR: IsValidFileHandle() bFileInfo is FALSE, %08X", GetLastError());
		return FALSE;
	}
	
	if ( lpFileInformation.dwFileAttributes == 0x00 )
	{
		OutputDebugStringFormat("ERROR: WritePEValueToFile(), lpFileInformation.dwFileAttributes is 0");
		return FALSE;
	}

	return TRUE;
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


	// DuplicateHandle
	if ( !DuplicateHandle(GetCurrentProcess(), hFile, GetCurrentProcess(), &hPe->hFile, NULL, FALSE, DUPLICATE_SAME_ACCESS) )
	{
		OutputDebugStringFormat("ERROR: CreatePeHandle.DuplicateHandle(), %08X", GetLastError());
		return NULL;
	}


	// Load target data (full size)
	hPe->dwFileFullSize = GetFileSize(hPe->hFile, NULL);
	hPe->pFile = (PBYTE)VirtualAlloc(NULL, hPe->dwFileFullSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	ReadFile(hPe->hFile, hPe->pFile, hPe->dwFileFullSize, &lpNumberOfBytesRead, NULL);
	if (lpNumberOfBytesRead == 0)
	{
		OutputDebugStringFormat("ERROR: CreatePeHandle.ReadFile(), %08X", GetLastError());
		return NULL;
	}


	// Set basic PE infomation
	if (!ParsePE(hPe))
		return NULL;

	return hPe;
}


BOOL ClosePeHandle(PEHANDLE hPe)
{
	// Close duplicated file handle
	if ( !CloseHandle(hPe->hFile) )
	{
		OutputDebugStringFormat("ERROR: CloseHandle(hPe->hFile) %08X", GetLastError());
		return FALSE;
	}

	// Release target file data
	if ( !VirtualFree(hPe->pFile, 0x00, MEM_RELEASE) )
	{
		OutputDebugStringFormat("ERROR: VirtualFree(hPe->pFile) %08X", GetLastError());
		return FALSE;
	}
	

	// Remove pointer
	hPe->hFile = NULL;
	hPe->pDosHeader = NULL;
	hPe->pNtHeader = NULL;
	hPe->pSectionHeader = NULL;
	hPe->pFile = NULL;


	// Release PEHANDLE structure
	if (!VirtualFree(hPe, 0x00, MEM_RELEASE))
	{
		OutputDebugStringFormat("ERROR: VirtualFree(hPe) %08X", GetLastError());
		return FALSE;
	}

	hPe = NULL;

	return TRUE;
}


DWORD GetFileOffset(PEHANDLE hPe, PVOID pMemOffset)
{
	return (DWORD)pMemOffset - (DWORD)hPe->pFile;
}


// ==================== Normal functions

BOOL IsPeFile(PEHANDLE hPe)
{
	if (hPe->pDosHeader->e_magic == IMAGE_DOS_SIGNATURE)
	{
		if (hPe->pNtHeader->Signature == IMAGE_NT_SIGNATURE)
		{
			return TRUE;
		}
	}

	return FALSE;
}


BOOL IsPeFileEx(PEHANDLE hPe, DWORD* dwResultImcompletePeFile)
{
	*dwResultImcompletePeFile = 0x00;

	if ( !(hPe->pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) )
		*dwResultImcompletePeFile |= UNSTABLE_PE_HEADER_SIGNATURE_MZ;

	if ( !(hPe->pNtHeader->Signature == IMAGE_NT_SIGNATURE) )
		*dwResultImcompletePeFile |= UNSTABLE_PE_HEADER_SIGNATURE_PE;

	if (*dwResultImcompletePeFile > 0x00)
		return FALSE;
	
	return TRUE;
}


BOOL HasExtraSection(PEHANDLE hPe)
{
	DWORD dwTotalSectionSize = 0;
	DWORD sectionCnt = 0;
	PIMAGE_SECTION_HEADER _pSectionHeader = NULL;

	_pSectionHeader = hPe->pSectionHeader;

	for (sectionCnt = 1; sectionCnt <= (hPe->pNtHeader->FileHeader.NumberOfSections); sectionCnt++)
	{
		if (sectionCnt == (hPe->pNtHeader->FileHeader.NumberOfSections))
		{
			dwTotalSectionSize = _pSectionHeader->PointerToRawData;
			dwTotalSectionSize += _pSectionHeader->SizeOfRawData;

			break;
		}

		_pSectionHeader++;
	}

	if (dwTotalSectionSize < hPe->dwFileFullSize)
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

	for (sectionCnt = 0; sectionCnt < (hPe->pNtHeader->FileHeader.NumberOfSections); sectionCnt++)
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
	return hPe->pNtHeader->OptionalHeader.ImageBase + dwRva;
}



// ==================== IMAGE_DOS_HEADER functions

BOOL CheckElfanewValueRange(PEHANDLE hPe)
{
	if ( hPe->dwFileFullSize < GetElfanewValue(hPe) )
	{
		OutputDebugStringFormat("ERROR: CheckElfanewValueRange(), Invaild e_lfanew value.");
		return FALSE;
	}

	return TRUE;
}


DWORD GetElfanewValue(PEHANDLE hPe)
{
	return hPe->pDosHeader->e_lfanew;
}


BOOL SetElfanewValue(PEHANDLE hPe, DWORD dwNewElfanew)
{
	DWORD dwFileOffset = 0;

	dwFileOffset = GetFileOffset(hPe, &hPe->pDosHeader->e_lfanew);
	if ( !WritePEValueToFile(hPe, dwFileOffset, dwNewElfanew, sizeof(DWORD)) )
	{
		return FALSE;
	}

	return TRUE;
}


// ==================== IMAGE_FILE_HADER functions

WORD GetMachineCode(PEHANDLE hPe)
{
	return hPe->pNtHeader->FileHeader.Machine;
}


WORD GetNumberOfSections(PEHANDLE hPe)
{
	WORD wNumberOfSections = 0;

	if ((wNumberOfSections = hPe->pNtHeader->FileHeader.NumberOfSections) <= 0x00)
	{
		OutputDebugStringFormat("ERROR: GetNumberOfSections(), Invaild NumberOfSections");
		return PE_INVAILD_VALUE;
	}

	return wNumberOfSections;
}


BOOL GetMachineCodeName(PEHANDLE hPe, char* szMachineCodeName)
{
	_PTYPE_NAME_LIST pMachineCode = NULL;
	WORD wMachineCode = 0;
	
	
	wMachineCode = GetMachineCode(hPe);
	
	if (!_GetMachineCodeName(wMachineCode, szMachineCodeName))
	{
		return FALSE;
	}

	return TRUE;
}


DWORD GetTimeDataStamp(PEHANDLE hPe)
{
	return hPe->pNtHeader->FileHeader.TimeDateStamp;
}


char* GetTimeDataStampToTime(PEHANDLE hPe)
{
	char* pszTimeStamp = NULL;
	DWORD dwTimeDataStamp = 0;

	pszTimeStamp = (char*)malloc(sizeof(MAX_PATH));
	dwTimeDataStamp = GetTimeDataStamp(hPe);

	_GetTimeDataStampToTime(pszTimeStamp, MAX_PATH, dwTimeDataStamp);

	return pszTimeStamp;
}


DWORD GetPointerToSymbolTable(PEHANDLE hPe)
{
	return hPe->pNtHeader->FileHeader.PointerToSymbolTable;
}


DWORD GetNumberOfSymbls(PEHANDLE hPe)
{
	return hPe->pNtHeader->FileHeader.NumberOfSymbols;
}


WORD GetSizeOfOptionalHeader(PEHANDLE hPe)
{
	return hPe->pNtHeader->FileHeader.SizeOfOptionalHeader;
}


WORD GetFileHeaderCharacteristics(PEHANDLE hPe)
{
	return hPe->pNtHeader->FileHeader.Characteristics;
}


/*
VOID GetFileHeaderCharacteristicsElement(PEHANDLE hPe, _PTYPE_NAME_LIST fileHeaderCharacteristicsElement)
{
	WORD fhCharcteristics = hPe->ntHeader.FileHeader.Characteristics;

	_GetFileHeaderCharacteristicsElement(fileHeaderCharacteristicsElement, fhCharcteristics);
}


GetNumberOfFileHeaderCharacteristics()
{}
*/


BOOL SetNumberOfSections(PEHANDLE hPe, WORD wNewNumberOfSections)
{
	DWORD dwFileOffset = 0;

	dwFileOffset = GetFileOffset(hPe, &hPe->pNtHeader->FileHeader.NumberOfSections);
	if (!WritePEValueToFile(hPe, dwFileOffset, wNewNumberOfSections, sizeof(WORD)))
	{
		return FALSE;
	}

	return TRUE;
}


// ==================== IMAGE_OPTIONAL_HEADER functions

DWORD GetEntryPointRVA(PEHANDLE hPe)
{
	DWORD dwEntryPointRva = 0;

	if (!(dwEntryPointRva = hPe->pNtHeader->OptionalHeader.AddressOfEntryPoint))
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
	return hPe->pNtHeader->OptionalHeader.ImageBase;
}


DWORD GetSizeOfImage(PEHANDLE hPe)
{
	return hPe->pNtHeader->OptionalHeader.SizeOfImage;
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

	dwOffsetFirstSectionHeader = GetElfanewValue(hPe) + SIZE_OF_IMAGE_NT_HEAEDER;
	return dwOffsetFirstSectionHeader + (SIZE_OF_IMAGE_SECTION_HEADER * nSection);
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


