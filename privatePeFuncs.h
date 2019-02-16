#include <Windows.h>
#include <stdio.h>
#include <stdarg.h>


#define PE_INVAILD_VALUE 0xFFFFFFFF
#define MAX_TYPE_NAME_LIST 0x20
#define SIZEOF_NULL 0x01

#define UNSTABLE_PE_HEADER_SIGNATURE_MZ 0x00000001
#define UNSTABLE_PE_HEADER_SIGNATURE_PE 0x00000002

#define SIZEOF_FULL_DUMP 0x00
#define NO_DATADIRECTORY 0x00

#define SIZEOF_IMAGE_NT_HEAEDER32 sizeof(IMAGE_NT_HEADERS32)
#define SIZEOF_IMAGE_NT_HEAEDER64 sizeof(IMAGE_NT_HEADERS64)

#define TIMEDATASTAMP_STRING_LENGTH 0x14

// ----- Value for inner function
#define FIRST_SECTION 0x01

// ex) Man index(1) -> Computer index(0)
#define ConvertUserIndex(REAL_INDEX) (--REAL_INDEX)


typedef struct _PEHANDLE* PEHANDLE;



// ===================================== INNER FUNCTIONS ====================================

BOOL ParsePE( PEHANDLE );
BOOL SetDosHeaderStructure( PEHANDLE );
BOOL SetNtHeaderStructure( PEHANDLE );
BOOL SetSectionHeaderStructure( PEHANDLE );
BOOL SetImportDescriptorStructure( PEHANDLE );

BOOL CheckSectionNumberRange( PEHANDLE, DWORD );
BOOL CheckImportDescriptorNumberRange( PEHANDLE, DWORD );
BOOL WritePEValueToFile( PEHANDLE, DWORD, DWORD, DWORD  );
BOOL IsValidPEFileHandle( PEHANDLE  );
DWORD GetFileOffset( PEHANDLE, PVOID  );

VOID OutputDebugStringFormat( const char*, ... );




// -------------------------------------------- Service Functions --------------------------------------------


// ================================ Create / Close PE Handle ================================

EXTERN_C __declspec( dllexport ) PEHANDLE CreatePeHandle( HANDLE hFile );
EXTERN_C __declspec( dllexport ) BOOL ClosePeHandle( PEHANDLE hPe );


// ==================================== Normal Functions ====================================

EXTERN_C __declspec( dllexport ) BOOL IsPeFile( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL IsPe64File( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL IsDotNetPeFile( PEHANDLE hPe );

//EXTERN_C __declspec(dllexport) BOOL IsPeFileEx(PEHANDLE hPe, DWORD dwResultImcompletePeFile);

EXTERN_C __declspec( dllexport ) DWORD GetFileSizeBySection( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetExtraSectionStartOffsetRAW( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasExtraSection( PEHANDLE hPe );

EXTERN_C __declspec( dllexport ) DWORD DumpExtraSection( PEHANDLE hPe, HANDLE hFile, DWORD dwDumpSize );
EXTERN_C __declspec( dllexport ) DWORD RVAtoRAW( PEHANDLE hPe, DWORD dwRva );
EXTERN_C __declspec( dllexport ) DWORD RVAtoVA( PEHANDLE hPe, DWORD dwRva );


// =============================== IMAGE_DOS_HEADER Functions ===============================

EXTERN_C __declspec( dllexport ) BOOL CheckElfanewValueRange( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetElfanewValue( PEHANDLE hPe );

/* IMAGE_DOS_HEADER members
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_cblp( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_cp( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_crlc( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_cparhdr( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_minalloc( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_maxalloc( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_ss( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_sp( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_csum( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_ip( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_cs( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_lfarlc( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_ovno( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_res( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_oemid( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_oeminfo( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetDosHeader_res2( PEHANDLE hPe, WORD wNewDosSignature );
*/

EXTERN_C __declspec( dllexport ) BOOL SetDosHeaderSignature( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetElfanewValue( PEHANDLE hPe, DWORD dwNewElfanew );


// =============================== IMAGE_FILE_HEADER Functions ==============================

EXTERN_C __declspec( dllexport ) WORD GetMachineCode( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL GetMachineCodeName( PEHANDLE hPe, char* szMachineCodeName );
EXTERN_C __declspec( dllexport ) WORD GetNumberOfSections( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetTimeDataStamp( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL GetTimeDataStampToTime( PEHANDLE hPe, CHAR* szTimeStamp );

EXTERN_C __declspec( dllexport ) DWORD GetPointerToSymbolTable( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetNumberOfSymbols( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetSizeOfOptionalHeader( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetFileHeaderCharacteristics( PEHANDLE hPe );
//EXTERN_C __declspec(dllexport) VOID GetFileHeaderCharacteristicsElement(PEHANDLE hPe, _PTYPE_NAME_LIST &fileHeaderCharacteristicsElement);

EXTERN_C __declspec( dllexport ) BOOL SetMachineCode( PEHANDLE hPe, WORD wNewMachineCode );
EXTERN_C __declspec( dllexport ) BOOL SetNumberOfSections( PEHANDLE hPe, WORD wNewNumberOfSections );
EXTERN_C __declspec( dllexport ) BOOL SetTimeDataStamp( PEHANDLE hPe, DWORD dwNewTimeDataStamp );
EXTERN_C __declspec( dllexport ) BOOL SetPointerToSymbolTable( PEHANDLE hPe, DWORD dwNewPointerToSymbolTable );
EXTERN_C __declspec( dllexport ) BOOL SetNumberOfSymbols( PEHANDLE hPe, DWORD dwNewNumberOfSymbols );
EXTERN_C __declspec( dllexport ) BOOL SetSizeOfOptionalHeader( PEHANDLE hPe, WORD wNewSizeOfOptionalHeader );
EXTERN_C __declspec( dllexport ) BOOL SetFileHeaderCharacteristics( PEHANDLE hPe, WORD wNewFileHeaderCharacteristics );


// =============================== IMAGE_OPTIONAL_HEADER Functions ==========================

EXTERN_C __declspec( dllexport ) WORD GetNtHeaderSignature( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BYTE GetMajorLinkerVersion( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BYTE GetMinorLinkerVersion( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfCode( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfInitializedData( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfUninitializedData( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetEntryPointRVA( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetEntryPointRAW( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetBaseOfCode( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetBaseOfData( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetImageBase( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSectionAlignment( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetFileAlignment( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetMajorOperatingSystemVersion( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetMinorOperatingSystemVersion( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetMajorImageVersion( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetMinorImageVersion( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetMajorSubsystemVersion( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetMinorSubsystemVersion( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetWin32VersionValue( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfImage( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetCheckSum( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetSubsystem( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetDllCharacteristics( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfStackReserve( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfStackCommit( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfHeapReserve( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfHeapCommit( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetLoaderFlags( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetNumberOfRvaAndSizes( PEHANDLE hPe );


// =============================== IMAGE_SECTION_HEADER Functions ===========================

DWORD GetSectionHeaderOffset( PEHANDLE hPe, DWORD nSection );

EXTERN_C __declspec( dllexport ) DWORD GetSectionVirtualAddress( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetSectionVirtualSize( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfRawData( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetPointerToRawData( PEHANDLE hPe, DWORD nSection );


// =============================== IMAGE_DATA_DIRECTORY Functions ===========================

/*
EXTERN_C __declspec( dllexport ) BOOL HasExportTable( PEHANDLE hPe );

EXTERN_C __declspec( dllexport ) BOOL HasResourceTable( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasExceptionTable( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasSecurityTable( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasBaseRelocationTable( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasDebugDirectory( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasArchitectureSpecData( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasGlobalPointerReg( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasTlsDirectory( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasLoadConfigTable( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasBoundImportTable( PEHANDLE hPe );
*/

BOOL HasImportDirectory( PEHANDLE hPe );

EXTERN_C __declspec( dllexport ) DWORD GetImportDirectoryAddr( PEHANDLE hPe );


// =============================== IMAGE_IMPORT_DESCRIPTOR Functions ===========================

EXTERN_C __declspec( dllexport ) DWORD GetNumberOfImportDescriptor( PEHANDLE hPe );

EXTERN_C __declspec( dllexport ) DWORD GetOriginalFirstThunk( PEHANDLE hPe, DWORD nImportDescriptor );
EXTERN_C __declspec( dllexport ) DWORD GetImportTimeDataStamp( PEHANDLE hPe, DWORD nImportDescriptor );
EXTERN_C __declspec( dllexport ) DWORD GetForwarderChain( PEHANDLE hPe, DWORD nImportDescriptor );
EXTERN_C __declspec( dllexport ) DWORD GetName( PEHANDLE hPe, DWORD nImportDescriptor );
EXTERN_C __declspec( dllexport ) DWORD GetNameToString( PEHANDLE hPe, DWORD nImportDescriptor, CHAR* szDllName );
EXTERN_C __declspec( dllexport ) DWORD GetFirstThunk( PEHANDLE hPe, DWORD nImportDescriptor );






