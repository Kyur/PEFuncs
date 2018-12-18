#include "PeFuncs.h"



// ========== Create/Close PE Handle

EXTERN_C __declspec(dllexport) PPEHANDLE CreatePeHandle(HANDLE hFile)
{
	DWORD lpNumberOfBytesRead = 0;
	PPEHANDLE hPe = NULL;


	// Create PEHANDLE structure
	hPe = (PPEHANDLE)VirtualAlloc(NULL, sizeof(PEHANDLE), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
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



BOOL ClosePeHandle(PPEHANDLE hPe)
{
	// Release target file data
	if (VirtualFree(hPe->pFile, 0x00, MEM_RELEASE) == 0)
		return FALSE;

	// Relase IMAGE_SECTION_HEADER
	if (VirtualFree(hPe->pSectionHeader, 0x00, MEM_RELEASE) == 0)
		return FALSE;

	// Release PEHANDLE structure
	if (VirtualFree(hPe, 0x00, MEM_RELEASE) == 0)
		return FALSE;

	return TRUE;
}



// ========== Inner Functions

BOOL ParsePE(PPEHANDLE hPe)
{

	if (!SetDosHeaderStructure(hPe))
		return FALSE;

	if (!SetNtHeaderStructure(hPe))
		return FALSE;

	if (!SetSectionHeaderStructure(hPe))
		return FALSE;
}


BOOL SetDosHeaderStructure(PPEHANDLE hPe)
{
	memcpy(&hPe->dosHeader, hPe->pFile, sizeof(IMAGE_DOS_HEADER));

	return TRUE;
}


BOOL SetNtHeaderStructure(PPEHANDLE hPe)
{
	PBYTE pNtHeader = NULL;

	pNtHeader = (PBYTE)(hPe->pFile + hPe->dosHeader.e_lfanew);
	memcpy(&hPe->ntHeader, pNtHeader, sizeof(IMAGE_NT_HEADERS));

	return TRUE;
}


BOOL SetSectionHeaderStructure(PPEHANDLE hPe)
{
	DWORD dwSectionHeaderStartOffset = 0;
	DWORD dwSectionHeaderSize = 0;
	DWORD dwNumberOfSections = 0;

	dwSectionHeaderSize = sizeof(IMAGE_SECTION_HEADER);
	dwNumberOfSections = hPe->ntHeader.FileHeader.NumberOfSections;

	hPe->pSectionHeader = (PIMAGE_SECTION_HEADER)VirtualAlloc(NULL, (dwSectionHeaderSize * dwNumberOfSections), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	dwSectionHeaderStartOffset += hPe->dosHeader.e_lfanew;
	dwSectionHeaderStartOffset += sizeof(IMAGE_NT_HEADERS);

	hPe->pSectionHeader = (PIMAGE_SECTION_HEADER)(hPe->pFile + dwSectionHeaderStartOffset);

	return TRUE;
}


BOOL CheckSectionNumberRange(PPEHANDLE hPe, DWORD nSectionCnt)
{
	if ( ( 0 < nSectionCnt ) && ( nSectionCnt <= hPe->ntHeader.FileHeader.NumberOfSections ) )
		return TRUE;

	return FALSE;
}



// ========== Service Functions

DWORD GetNumberOfSections(PPEHANDLE hPe)
{
	DWORD dwNumberOfSections = 0;

	if (!(dwNumberOfSections = hPe->ntHeader.FileHeader.NumberOfSections))
		return 0;

	return dwNumberOfSections;
}


BOOL IsPeFile(PPEHANDLE hPe)
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


DWORD GetEntryPointRVA(PPEHANDLE hPe)
{
	DWORD dwEntryPointRva = 0;

	if (!(dwEntryPointRva = hPe->ntHeader.OptionalHeader.AddressOfEntryPoint))
		return 0;

	return dwEntryPointRva;
}


DWORD GetEntryPointRAW(PPEHANDLE hPe)
{
	DWORD dwEntryPointRva = 0;
	DWORD dwEntryPointRaw = 0;

	dwEntryPointRva = GetEntryPointRVA(hPe);
	dwEntryPointRaw = RVAtoRAW(hPe, dwEntryPointRva);

	if (dwEntryPointRaw == 0)
		return 0;

	return dwEntryPointRaw;
}


DWORD RVAtoRAW(PPEHANDLE hPe, DWORD dwRva)
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


DWORD RVAtoVA(PPEHANDLE hPe, DWORD dwRva)
{
	return hPe->ntHeader.OptionalHeader.ImageBase + dwRva;
}


BOOL HasExtraSection(PPEHANDLE hPe)
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


DWORD GetSectionVirtualAddress(PPEHANDLE hPe, DWORD nSection)
{
	DWORD sectionVirtualAddress = 0;
	
	if ( CheckSectionNumberRange(hPe, nSection) )
	{
		nSection -= 1;

		sectionVirtualAddress = ((hPe->pSectionHeader) + nSection)->VirtualAddress;
		return sectionVirtualAddress;
	}
	
	return 0xFFFFFFFF;
}


DWORD GetSectionVirtualSize(PPEHANDLE hPe, DWORD nSection)
{
	DWORD sectionVirtualSize = 0;

	nSection -= 1;

	if ( CheckSectionNumberRange(hPe, nSection) )
	{
		sectionVirtualSize = ((hPe->pSectionHeader) + nSection)->Misc.VirtualSize;
		return sectionVirtualSize;
	}

	return 0xFFFFFFFF;
}


DWORD GetSectionSizeOfRawData(PPEHANDLE hPe, DWORD nSection)
{
	DWORD sectionSizeOfRawData = 0;

	nSection -= 1;

	if ( CheckSectionNumberRange(hPe, nSection) )
	{
		sectionSizeOfRawData = (hPe->pSectionHeader + nSection)->SizeOfRawData;
		return sectionSizeOfRawData;
	}

	return 0xFFFFFFFF;
}

DWORD GetSectionPointerToRawData(PPEHANDLE hPe, DWORD nSection)
{
	DWORD sectionPointerToRawdata = 0;

	nSection -= 1;

	if ( CheckSectionNumberRange(hPe, nSection) )
	{
		sectionPointerToRawdata = (hPe->pSectionHeader + nSection)->PointerToRawData;
		return sectionPointerToRawdata;
	}

	return 0xFFFFFFFF;
}


DWORD GetImageBase(PPEHANDLE hPe)
{
	return hPe->ntHeader.OptionalHeader.ImageBase;
}

DWORD GetSizeOfImage(PPEHANDLE hPe)
{
	return hPe->ntHeader.OptionalHeader.SizeOfImage;
}