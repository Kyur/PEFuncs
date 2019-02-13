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

BOOL ParsePE( PEHANDLE hPe )
{
	if ( !SetDosHeaderStructure( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: ParsePE(), fail to SetDosHeaderStructure() function." );
		return FALSE;
	}

	if ( !SetNtHeaderStructure( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: ParsePE(), fail to SetNtHeaderStructure() function." );
		return FALSE;
	}

	if ( !SetSectionHeaderStructure( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: ParsePE(), fail to SetSectionHeaderStructure() function." );
		return FALSE;
	}

	return TRUE;
}


BOOL SetDosHeaderStructure( PEHANDLE hPe )
{
	hPe->pDosHeader = (PIMAGE_DOS_HEADER) hPe->pFile;

	return TRUE;
}


BOOL SetNtHeaderStructure( PEHANDLE hPe )
{
	if ( !CheckElfanewValueRange( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: SetNtHeaderStructure(), Invaild e_lfanew value." );
		return FALSE;
	}

	hPe->pNtHeader = (PIMAGE_NT_HEADERS) ( hPe->pFile + GetElfanewValue( hPe ) );

	return TRUE;
}


BOOL SetSectionHeaderStructure( PEHANDLE hPe )
{
	DWORD dwSectionHeaderStartOffset = 0;

	dwSectionHeaderStartOffset = GetSectionHeaderOffset( hPe, FIRST_SECTION );

	if ( dwSectionHeaderStartOffset == PE_INVAILD_VALUE )
	{
		OutputDebugStringFormat( "ERROR: SetSectionHeaderStructure(), Invaild Section header start offset" );
		return FALSE;
	}

	hPe->pSectionHeader = (PIMAGE_SECTION_HEADER) ( hPe->pFile + dwSectionHeaderStartOffset );
	return TRUE;
}


BOOL CheckSectionNumberRange( PEHANDLE hPe, DWORD nSectionCnt )
{
	if ( ( 0 < nSectionCnt ) && ( nSectionCnt <= hPe->pNtHeader->FileHeader.NumberOfSections ) )
		return TRUE;

	return FALSE;
}


VOID OutputDebugStringFormat( const char* str, ... )
{
	va_list vaList_dbgStr;
	char errorStr[MAX_PATH] = { 0, };

	va_start( vaList_dbgStr, str );
	vsprintf( errorStr, str, vaList_dbgStr );
	va_end( vaList_dbgStr );

	OutputDebugString( errorStr );
}


BOOL WritePEValueToFile( PEHANDLE hPe, DWORD dwFileOffset, DWORD dwValue, DWORD cSize )
{
	DWORD lpNumberOfBytesWritten = 0;
	LARGE_INTEGER llFileOffset = { 0, };
	llFileOffset.QuadPart = dwFileOffset;


	if ( !IsValidPEFileHandle( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: WritePEValueToFile(): IsValidFileHandle()" );
		return FALSE;
	}

	if ( cSize == 0 )
	{
		OutputDebugStringFormat( "ERROR: WritePEValueToFile(): cSize cannot have 0" );
		return FALSE;
	}


	if ( !SetFilePointerEx( hPe->hFile, llFileOffset, NULL, FILE_BEGIN ) )
	{
		OutputDebugStringFormat( "ERROR: WritePEValueToFile(): SetFilePointerEx(), %08X", GetLastError() );
		return FALSE;
	}

	if ( !WriteFile( hPe->hFile, &dwValue, cSize, &lpNumberOfBytesWritten, NULL ) )
	{
		OutputDebugStringFormat( "ERROR: WritePEValueToFile(): WriteFile(), %08X", GetLastError() );
		return FALSE;
	}

	if ( lpNumberOfBytesWritten == 0 )
	{
		OutputDebugStringFormat( "ERROR: WritePEValueToFile(): lpNumberOfBytesWritten is 0" );
		return FALSE;
	}

	return TRUE;
}


/*
* Function Name : IsValidPEFileHandle
*
* Argument(1) : PEHANDLE
*
* Detail :	Use GetFileInformationByHandle() to validate the duplicate file handle.
*			Check the return value of GetFileInformationByHandle() and the returned file attributes value.
*
* Return :	(SUCCESS) TRUE
*			(FAIL) FALSE
*/
BOOL IsValidPEFileHandle( PEHANDLE hPe )
{
	BOOL bFileInfo = FALSE;
	BY_HANDLE_FILE_INFORMATION lpFileInformation = { 0x00, };


	// Try to read file information using a duplicate file handle.
	bFileInfo = GetFileInformationByHandle( hPe->hFile, &lpFileInformation );

	if ( bFileInfo == FALSE )
	{
		OutputDebugStringFormat( "ERROR: IsValidFileHandle(): GetFileInformationByHandle(), %08X", GetLastError() );
		return FALSE;
	}

	// Check file attributes
	if ( lpFileInformation.dwFileAttributes == 0x00 )
	{
		OutputDebugStringFormat( "ERROR: WritePEValueToFile(): lpFileInformation.dwFileAttributes is 0" );
		return FALSE;
	}

	return TRUE;
}


/*
* Function Name : CreatePeHandle
*
* Argument(1) : HANDLE (Handle opened with the CreateFile() function)
*
* Detail :	CreatePeHandle() must be called before to use PeDll.
*			Do the followings. Duplicate original file handle, initiate _PEHANDLE structure, read file to memory.
*			Then after, Start PE parsing(ParsePE).
*
* Return :	(SUCCESS) Pointer to _PEHANDLE structure
*			(FAIL) NULL
*/
PEHANDLE CreatePeHandle( HANDLE hFile )
{
	DWORD lpNumberOfBytesRead = 0;
	DWORD dwNumberOfSectionsTemp = 0;
	PEHANDLE hPe = NULL;


	// Allocate _PEHANDLE structure
	hPe = (PEHANDLE) VirtualAlloc( NULL, sizeof( _PEHANDLE ), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE );
	if ( hPe == NULL )
	{
		OutputDebugStringFormat( "ERROR: CreatePeHandle: VirtualAlloc(), %08X", GetLastError() );
		return NULL;
	}


	// Duplicate the original file handle with the same access right 
	// * If you want to modify data with PeDll, you need to create file handle to GENERIC_WRITE.
	if ( !DuplicateHandle( GetCurrentProcess(), hFile, GetCurrentProcess(), &hPe->hFile, NULL, FALSE, DUPLICATE_SAME_ACCESS ) )
	{
		OutputDebugStringFormat( "ERROR: CreatePeHandle: DuplicateHandle(), %08X", GetLastError() );
		return NULL;
	}

	// Validation of duplicate handle
	if ( !IsValidPEFileHandle( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: CreatePeHandle: IsValidPEFileHandle(), %08X", GetLastError() );
		return NULL;
	}


	hPe->dwFileFullSize = GetFileSize( hPe->hFile, NULL );
	hPe->pFile = NULL;

	// Allocate target file (full size)
	hPe->pFile = (PBYTE) VirtualAlloc( NULL, hPe->dwFileFullSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
	if ( hPe == NULL )
	{
		OutputDebugStringFormat( "ERROR: CreatePeHandle: VirtualAlloc(), %08X", GetLastError() );
		return NULL;
	}

	// Read target file on memory (full size)
	ReadFile( hPe->hFile, hPe->pFile, hPe->dwFileFullSize, &lpNumberOfBytesRead, NULL );
	if ( lpNumberOfBytesRead == 0 )
	{
		OutputDebugStringFormat( "ERROR: CreatePeHandle: ReadFile(), %08X", GetLastError() );
		return NULL;
	}


	// Start pasing PE header
	if ( !ParsePE( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: CreatePeHandle: ParsePE(), %08X", GetLastError() );
		return NULL;
	}

	return hPe;
}


/*
* Function Name : ClosePeHandle
*
* Argument(1) : PEHANDLE (Handle created by the CreatePeHandle() function)
*
* Detail :	PeDll uses large memory area.
*			Therefore, ClosePeHandle() must be called after you have finished using the PeDLL functions.
*
* Return :	(SUCCESS) TRUE
*			(FAIL) FALSE
*/
BOOL ClosePeHandle( PEHANDLE hPe )
{
	// Close duplicated file handle
	if ( !CloseHandle( hPe->hFile ) )
	{
		OutputDebugStringFormat( "ERROR: ClosePeHandle: CloseHandle(), %08X", GetLastError() );
		return FALSE;
	}

	// Release the memory of a read target file
	if ( !VirtualFree( hPe->pFile, 0x00, MEM_RELEASE ) )
	{
		OutputDebugStringFormat( "ERROR: ClosePeHandle: VirtualFree(), %08X", GetLastError() );
		return FALSE;
	}


	// Release pointers
	hPe->hFile = NULL;
	hPe->pDosHeader = NULL;
	hPe->pNtHeader = NULL;
	hPe->pSectionHeader = NULL;
	hPe->pFile = NULL;


	// Release _PEHANDLE structure
	if ( !VirtualFree( hPe, 0x00, MEM_RELEASE ) )
	{
		OutputDebugStringFormat( "ERROR: ClosePeHandle: VirtualFree(), %08X", GetLastError() );
		return FALSE;
	}

	// Release PEHANDLE
	hPe = NULL;

	return TRUE;
}





// ==================== Normal functions

BOOL IsPeFile( PEHANDLE hPe )
{
	if ( hPe->pDosHeader->e_magic == IMAGE_DOS_SIGNATURE )
	{
		if ( hPe->pNtHeader->Signature == IMAGE_NT_SIGNATURE )
		{
			return TRUE;
		}
	}

	return FALSE;
}


BOOL IsPe64File( PEHANDLE hPe )
{
	if ( !IsPeFile( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: IsPe64File: IsPeFile() Fail" );
		return FALSE;
	}

	// Check Optinal Header magic (0x020B)
	if ( hPe->pNtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC )
		return FALSE;

	return TRUE;
}


/*
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
*/


DWORD GetFileSizeBySection( PEHANDLE hPe )
{
	DWORD dwTotalSectionSize = 0;
	DWORD sectionCnt = 0;
	PIMAGE_SECTION_HEADER _pSectionHeader = NULL;


	_pSectionHeader = hPe->pSectionHeader;

	for ( sectionCnt = 1; sectionCnt <= ( hPe->pNtHeader->FileHeader.NumberOfSections ); sectionCnt++ )
	{
		// Find last section
		if ( sectionCnt == ( hPe->pNtHeader->FileHeader.NumberOfSections ) )
		{
			// (file offset of last section) + (size of last section)
			dwTotalSectionSize = _pSectionHeader->PointerToRawData;
			dwTotalSectionSize += _pSectionHeader->SizeOfRawData;

			return dwTotalSectionSize;
		}

		// Move next section
		_pSectionHeader++;
	}

	return PE_INVAILD_VALUE;
}


DWORD GetExtraSectionStartOffsetRAW( PEHANDLE hPe )
{
	DWORD dwFileSizeBySection = 0;

	dwFileSizeBySection = GetFileSizeBySection( hPe );

	if ( dwFileSizeBySection == PE_INVAILD_VALUE )
	{
		OutputDebugStringFormat( "ERROR: GetExtraSectionStartOffset: GetExtraSectionStartOffsetRAW(), PE_INVAILD_VALUE" );
		return PE_INVAILD_VALUE;
	}

	return dwFileSizeBySection;
}


/*
* Function Name : HasExtraSection
*
* Argument(1) : PEHANDLE
*
* Detail :	Compare the last position of the last section in the file with the size obtained with the GetFileSize() function.
*			ExtraSection exists when the size obtained by GetFIleSize() is larger.
*
* Return :	(SUCCESS) TRUE
*			(FAIL) FALSE
*/
BOOL HasExtraSection( PEHANDLE hPe )
{
	DWORD dwTotalSectionSize = 0;

	dwTotalSectionSize = GetFileSizeBySection( hPe );

	// Compare size obtained by GetFIleSize()
	if ( dwTotalSectionSize < hPe->dwFileFullSize )
		return TRUE;

	return FALSE;
}


DWORD DumpExtraSection( PEHANDLE hPe, HANDLE hFile, DWORD dwDumpSize )
{
	DWORD dwExtraSectionStartOffset = 0;
	PDWORD pExtraSectionStartOffset = NULL;


	if ( !HasExtraSection( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: DumpExtraSection: HasExtraSection(), No Extrasection" );
		return PE_INVAILD_VALUE;
	}

	dwExtraSectionStartOffset = GetExtraSectionStartOffsetRAW( hPe );
	if ( dwExtraSectionStartOffset == PE_INVAILD_VALUE )
	{
		OutputDebugStringFormat( "ERROR: DumpExtraSection: GetExtraSectionStartOffsetRAW(), PE_INVAILD_VALUE" );
		return PE_INVAILD_VALUE;
	}

	pExtraSectionStartOffset = (PDWORD)(hPe->pFile + dwExtraSectionStartOffset);

	if ( dwDumpSize == SIZEOF_FULL_DUMP )
	{
	}
	else
	{
	}
}


DWORD RVAtoRAW( PEHANDLE hPe, DWORD dwRva )
{
	DWORD returnVal = 0;
	DWORD sectionCnt = 0;
	DWORD dwSectionHeaderIndex = 0;
	PIMAGE_SECTION_HEADER _pSectionHeader = NULL;

	_pSectionHeader = hPe->pSectionHeader;

	for ( sectionCnt = 0; sectionCnt < ( hPe->pNtHeader->FileHeader.NumberOfSections ); sectionCnt++ )
	{
		if ( ( _pSectionHeader->VirtualAddress <= dwRva ) &&
			dwRva <= ( _pSectionHeader->VirtualAddress ) + ( _pSectionHeader->Misc.VirtualSize ) )
		{
			returnVal = ( dwRva - _pSectionHeader->VirtualAddress ) + _pSectionHeader->PointerToRawData;

			return returnVal;
		}

		_pSectionHeader++;
	}

	//printf("Cannot Search RVA Range.\n");
	return 0;
}


DWORD RVAtoVA( PEHANDLE hPe, DWORD dwRva )
{
	return hPe->pNtHeader->OptionalHeader.ImageBase + dwRva;
}


DWORD GetFileOffset( PEHANDLE hPe, PVOID pMemOffset )
{
	return (DWORD) pMemOffset - (DWORD) hPe->pFile;
}


// ======================================== IMAGE_DOS_HEADER functions

BOOL CheckElfanewValueRange( PEHANDLE hPe )
{
	if ( hPe->dwFileFullSize < GetElfanewValue( hPe ) )
	{
		OutputDebugStringFormat( "ERROR: CheckElfanewValueRange(), Invaild e_lfanew value." );
		return FALSE;
	}

	return TRUE;
}


DWORD GetElfanewValue( PEHANDLE hPe )
{
	return hPe->pDosHeader->e_lfanew;
}


BOOL SetDosHeaderSignature( PEHANDLE hPe, WORD wNewDosSignature )
{
	if ( !WritePEValueToFile( hPe, GetFileOffset( hPe, &hPe->pDosHeader->e_magic ), wNewDosSignature, sizeof( WORD ) ) )
	{
		return FALSE;
	}

	return TRUE;
}


BOOL SetElfanewValue( PEHANDLE hPe, DWORD dwNewElfanew )
{
	if ( !WritePEValueToFile( hPe, GetFileOffset( hPe, &hPe->pDosHeader->e_lfanew ), dwNewElfanew, sizeof( DWORD ) ) )
	{
		return FALSE;
	}

	return TRUE;
}


// ======================================== IMAGE_FILE_HADER functions

WORD GetMachineCode( PEHANDLE hPe )
{
	return hPe->pNtHeader->FileHeader.Machine;
}


WORD GetNumberOfSections( PEHANDLE hPe )
{
	WORD wNumberOfSections = 0;

	if ( ( wNumberOfSections = hPe->pNtHeader->FileHeader.NumberOfSections ) <= 0x00 )
	{
		OutputDebugStringFormat( "ERROR: GetNumberOfSections(), Invaild NumberOfSections" );
		return PE_INVAILD_VALUE;
	}

	return wNumberOfSections;
}


BOOL GetMachineCodeName( PEHANDLE hPe, char* szMachineCodeName )
{
	_PTYPE_NAME_LIST pMachineCode = NULL;
	WORD wMachineCode = 0;


	wMachineCode = GetMachineCode( hPe );

	if ( !_GetMachineCodeName( wMachineCode, szMachineCodeName ) )
	{
		return FALSE;
	}

	return TRUE;
}


DWORD GetTimeDataStamp( PEHANDLE hPe )
{
	return hPe->pNtHeader->FileHeader.TimeDateStamp;
}


char* GetTimeDataStampToTime( PEHANDLE hPe )
{
	char* pszTimeStamp = NULL;
	DWORD dwTimeDataStamp = 0;

	pszTimeStamp = (char*) malloc( sizeof( MAX_PATH ) );
	dwTimeDataStamp = GetTimeDataStamp( hPe );

	_GetTimeDataStampToTime( pszTimeStamp, MAX_PATH, dwTimeDataStamp );

	return pszTimeStamp;
}


DWORD GetPointerToSymbolTable( PEHANDLE hPe )
{
	return hPe->pNtHeader->FileHeader.PointerToSymbolTable;
}


DWORD GetNumberOfSymbols( PEHANDLE hPe )
{
	return hPe->pNtHeader->FileHeader.NumberOfSymbols;
}


WORD GetSizeOfOptionalHeader( PEHANDLE hPe )
{
	return hPe->pNtHeader->FileHeader.SizeOfOptionalHeader;
}


WORD GetFileHeaderCharacteristics( PEHANDLE hPe )
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


BOOL SetMachineCode( PEHANDLE hPe, WORD wNewMachineCode )
{
	if ( !WritePEValueToFile( hPe, GetFileOffset( hPe, &hPe->pNtHeader->FileHeader.NumberOfSections ), wNewMachineCode, sizeof( WORD ) ) )
	{
		return FALSE;
	}

	return TRUE;
}


BOOL SetNumberOfSections( PEHANDLE hPe, WORD wNewNumberOfSections )
{
	if ( !WritePEValueToFile( hPe, GetFileOffset( hPe, &hPe->pNtHeader->FileHeader.NumberOfSections ), wNewNumberOfSections, sizeof( WORD ) ) )
	{
		return FALSE;
	}

	return TRUE;
}


BOOL SetTimeDataStamp( PEHANDLE hPe, DWORD dwNewTimeDataStamp )
{
	if ( !WritePEValueToFile( hPe, GetFileOffset( hPe, &hPe->pNtHeader->FileHeader.NumberOfSections ), dwNewTimeDataStamp, sizeof( DWORD ) ) )
	{
		return FALSE;
	}

	return TRUE;
}


BOOL SetPointerToSymbolTable( PEHANDLE hPe, DWORD dwNewPointerToSymbolTable )
{
	if ( !WritePEValueToFile( hPe, GetFileOffset( hPe, &hPe->pNtHeader->FileHeader.NumberOfSections ), dwNewPointerToSymbolTable, sizeof( DWORD ) ) )
	{
		return FALSE;
	}

	return TRUE;
}


BOOL SetNumberOfSymbols( PEHANDLE hPe, DWORD dwNewNumberOfSymbols )
{
	if ( !WritePEValueToFile( hPe, GetFileOffset( hPe, &hPe->pNtHeader->FileHeader.NumberOfSections ), dwNewNumberOfSymbols, sizeof( DWORD ) ) )
	{
		return FALSE;
	}

	return TRUE;
}


BOOL SetSizeOfOptionalHeader( PEHANDLE hPe, WORD wNewSizeOfOptionalHeader )
{
	if ( !WritePEValueToFile( hPe, GetFileOffset( hPe, &hPe->pNtHeader->FileHeader.NumberOfSections ), wNewSizeOfOptionalHeader, sizeof( WORD ) ) )
	{
		return FALSE;
	}

	return TRUE;
}


BOOL SetFileHeaderCharacteristics( PEHANDLE hPe, WORD wNewFileHeaderCharacteristics )
{
	if ( !WritePEValueToFile( hPe, GetFileOffset( hPe, &hPe->pNtHeader->FileHeader.NumberOfSections ), wNewFileHeaderCharacteristics, sizeof( WORD ) ) )
	{
		return FALSE;
	}

	return TRUE;
}



// ======================================== IMAGE_OPTIONAL_HEADER functions

WORD GetNtHeaderSignature( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.Magic;
}


BYTE GetMajorLinkerVersion( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.MajorLinkerVersion;
}


BYTE GetMinorLinkerVersion( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.MinorLinkerVersion;
}


DWORD GetSizeOfCode( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.SizeOfCode;
}


DWORD GetSizeOfInitializedData( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.SizeOfInitializedData;
}


DWORD GetSizeOfUninitializedData( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.SizeOfUninitializedData;
}


DWORD GetEntryPointRVA( PEHANDLE hPe )
{
	DWORD dwEntryPointRva = 0;

	if ( !( dwEntryPointRva = hPe->pNtHeader->OptionalHeader.AddressOfEntryPoint ) )
		return 0;

	return dwEntryPointRva;
}


DWORD GetEntryPointRAW( PEHANDLE hPe )
{
	DWORD dwEntryPointRva = 0;
	DWORD dwEntryPointRaw = 0;

	dwEntryPointRva = GetEntryPointRVA( hPe );
	dwEntryPointRaw = RVAtoRAW( hPe, dwEntryPointRva );

	if ( dwEntryPointRaw == 0 )
		return 0;

	return dwEntryPointRaw;
}


DWORD GetBaseOfCode( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.BaseOfCode;
}


DWORD GetBaseOfData( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.BaseOfData;
}


DWORD GetImageBase( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.ImageBase;
}


DWORD GetSectionAlignment( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.SectionAlignment;
}


DWORD GetFileAlignment( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.FileAlignment;
}


WORD GetMajorOperatingSystemVersion( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.MajorOperatingSystemVersion;
}


WORD GetMinorOperatingSystemVersion( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.MinorOperatingSystemVersion;
}


WORD GetMajorImageVersion( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.MajorImageVersion;
}


WORD GetMinorImageVersion( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.MinorImageVersion;
}


WORD GetMajorSubsystemVersion( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.MajorSubsystemVersion;
}


WORD GetMinorSubsystemVersion( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.MinorSubsystemVersion;
}


DWORD GetWin32VersionValue( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.Win32VersionValue;
}


DWORD GetSizeOfImage( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.SizeOfImage;
}


DWORD GetCheckSum( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.CheckSum;
}


WORD GetSubsystem( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.Subsystem;
}


WORD GetDllCharacteristics( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.DllCharacteristics;
}


DWORD GetSizeOfStackReserve( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.SizeOfStackReserve;
}


DWORD GetSizeOfStackCommit( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.SizeOfStackCommit;
}


DWORD GetSizeOfHeapReserve( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.SizeOfHeapReserve;
}


DWORD GetSizeOfHeapCommit( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.SizeOfHeapCommit;
}


DWORD GetLoaderFlags( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.LoaderFlags;
}


DWORD GetNumberOfRvaAndSizes( PEHANDLE hPe )
{
	return hPe->pNtHeader->OptionalHeader.NumberOfRvaAndSizes;
}


// ======================================== IMAGE_SECTION_HEADER functions

DWORD GetSectionHeaderOffset( PEHANDLE hPe, DWORD nSection )
{
	DWORD dwOffsetFirstSectionHeader = 0;

	if ( !CheckSectionNumberRange( hPe, nSection ) )
	{
		OutputDebugStringFormat( "ERROR: GetSectionHeaderOffset(), Invaild section number." );
		return PE_INVAILD_VALUE;
	}

	ConvertUserIndex( nSection );

	dwOffsetFirstSectionHeader = GetElfanewValue( hPe ) + SIZE_OF_IMAGE_NT_HEAEDER;
	return dwOffsetFirstSectionHeader + ( SIZE_OF_IMAGE_SECTION_HEADER * nSection );
}


DWORD GetVirtualAddress( PEHANDLE hPe, DWORD nSection )
{
	DWORD sectionVirtualAddress = 0;

	if ( !CheckSectionNumberRange( hPe, nSection ) )
	{
		OutputDebugStringFormat( "ERROR: GetVirtualAddress(), Invaild section number." );
		return PE_INVAILD_VALUE;
	}

	ConvertUserIndex( nSection );

	sectionVirtualAddress = ( hPe->pSectionHeader + nSection )->VirtualAddress;
	return sectionVirtualAddress;
}


DWORD GetVirtualSize( PEHANDLE hPe, DWORD nSection )
{
	DWORD sectionVirtualSize = 0;

	if ( !CheckSectionNumberRange( hPe, nSection ) )
	{
		OutputDebugStringFormat( "ERROR: GetVirtualSize(), Invaild section number." );
		return PE_INVAILD_VALUE;
	}

	ConvertUserIndex( nSection );

	sectionVirtualSize = ( ( hPe->pSectionHeader ) + nSection )->Misc.VirtualSize;
	return sectionVirtualSize;
}


DWORD GetSizeOfRawData( PEHANDLE hPe, DWORD nSection )
{
	DWORD sectionSizeOfRawData = 0;

	if ( !CheckSectionNumberRange( hPe, nSection ) )
	{
		OutputDebugStringFormat( "ERROR: GetSizeOfRawData(), Invaild section number." );
		return PE_INVAILD_VALUE;
	}

	ConvertUserIndex( nSection );

	sectionSizeOfRawData = ( hPe->pSectionHeader + nSection )->SizeOfRawData;
	return sectionSizeOfRawData;
}


DWORD GetPointerToRawData( PEHANDLE hPe, DWORD nSection )
{
	DWORD sectionPointerToRawdata = 0;

	if ( !CheckSectionNumberRange( hPe, nSection ) )
	{
		OutputDebugStringFormat( "ERROR: GetPointerToRawData(), Invaild section number." );
		return PE_INVAILD_VALUE;
	}

	ConvertUserIndex( nSection );

	sectionPointerToRawdata = ( hPe->pSectionHeader + nSection )->PointerToRawData;
	return sectionPointerToRawdata;
}


