#define PE_INVAILD_VALUE 0xFFFFFFFF
#define SIZEOF_FULL_DUMP 0x00
#define NO_DATADIRECTORY 0x00
#define TIMEDATASTAMP_STRING_LENGTH 0x14

#define SIZEOF_IMAGE_NT_HEAEDER32 sizeof(IMAGE_NT_HEADERS32)
#define SIZEOF_IMAGE_NT_HEAEDER64 sizeof(IMAGE_NT_HEADERS64)


typedef struct _PEHANDLE *PEHANDLE;


// ================================ Create / Close PE Handle ================================

EXTERN_C __declspec( dllexport ) PEHANDLE CreatePeHandle( HANDLE hFile );
EXTERN_C __declspec( dllexport ) BOOL ClosePeHandle( PEHANDLE hPe );


// ==================================== Normal Functions ====================================

EXTERN_C __declspec( dllexport ) BOOL IsPeFile( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL IsPe64File( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL IsDotNetPeFile( PEHANDLE hPe );

EXTERN_C __declspec( dllexport ) DWORD GetFileSizeBySection( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetExtraSectionStartOffsetRAW( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL HasExtraSection( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD RVAtoRAW( PEHANDLE hPe, DWORD dwRva );
EXTERN_C __declspec( dllexport ) DWORD RVAtoVA( PEHANDLE hPe, DWORD dwRva );


// =============================== IMAGE_DOS_HEADER Functions ===============================

EXTERN_C __declspec( dllexport ) BOOL CheckElfanewValueRange( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetElfanewValue( PEHANDLE hPe );

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

EXTERN_C __declspec( dllexport ) DWORD GetSectionVirtualAddress( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetSectionVirtualSize( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfRawData( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetPointerToRawData( PEHANDLE hPe, DWORD nSection );


// =============================== IMAGE_DATA_DIRECTORY Functions ===========================

EXTERN_C __declspec( dllexport ) DWORD GetImportDirectoryAddr( PEHANDLE hPe );


// ============================== IMAGE_IMPORT_DESCRIPTOR Functions =========================

EXTERN_C __declspec( dllexport ) DWORD GetNumberOfImportDescriptor( PEHANDLE hPe );

EXTERN_C __declspec( dllexport ) DWORD GetOriginalFirstThunk( PEHANDLE hPe, DWORD nImportDescriptor );
EXTERN_C __declspec( dllexport ) DWORD GetImportTimeDataStamp( PEHANDLE hPe, DWORD nImportDescriptor );
EXTERN_C __declspec( dllexport ) DWORD GetForwarderChain( PEHANDLE hPe, DWORD nImportDescriptor );
EXTERN_C __declspec( dllexport ) DWORD GetName( PEHANDLE hPe, DWORD nImportDescriptor );
EXTERN_C __declspec( dllexport ) DWORD GetNameToString( PEHANDLE hPe, DWORD nImportDescriptor, CHAR* szDllName );
EXTERN_C __declspec( dllexport ) DWORD GetFirstThunk( PEHANDLE hPe, DWORD nImportDescriptor );
