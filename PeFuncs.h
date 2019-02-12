#define PE_INVAILD_VALUE 0xFFFFFFFF

typedef struct _PEHANDLE *PEHANDLE;

#define UNSTABLE_PE_HEADER_SIGNATURE_MZ 0x00000001
#define UNSTABLE_PE_HEADER_SIGNATURE_PE 0x00000002


// Create/Close PE Handle
// ClosePeHandle must be used after you work
EXTERN_C __declspec( dllexport ) PEHANDLE CreatePeHandle( HANDLE hFile );
EXTERN_C __declspec( dllexport ) BOOL ClosePeHandle( PEHANDLE hPe );


// Normal functions
EXTERN_C __declspec( dllexport ) BOOL IsPeFile( PEHANDLE hPe );
//EXTERN_C __declspec(dllexport) BOOL IsPeFileEx(PEHANDLE hPe, DWORD dwResultImcompletePeFile);
EXTERN_C __declspec( dllexport ) BOOL HasExtraSection( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD RVAtoRAW( PEHANDLE hPe, DWORD dwRva );
EXTERN_C __declspec( dllexport ) DWORD RVAtoVA( PEHANDLE hPe, DWORD dwRva );


// IMAGE_DOS_HEADER functions
EXTERN_C __declspec( dllexport ) BOOL CheckElfanewValueRange( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetElfanewValue( PEHANDLE hPe );

EXTERN_C __declspec( dllexport ) BOOL SetDosSignature( PEHANDLE hPe, WORD wNewDosSignature );
EXTERN_C __declspec( dllexport ) BOOL SetElfanewValue( PEHANDLE hPe, DWORD dwNewElfanew );


// IMAGE_FILE_HADER functions
EXTERN_C __declspec( dllexport ) WORD GetMachineCode( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) BOOL GetMachineCodeName( PEHANDLE hPe, char* szMachineCodeName );
EXTERN_C __declspec( dllexport ) WORD GetNumberOfSections( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetTimeDataStamp( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) char* GetTimeDataStampToTime( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetPointerToSymbolTable( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetNumberOfSymbols( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetSizeOfOptionalHeader( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) WORD GetFileHeaderCharacteristics( PEHANDLE hPe );
//EXTERN_C __declspec(dllexport) VOID GetFileHeaderCharacteristicsElement(PEHANDLE hPe, TYPE_NAME_LIST &fileHeaderCharacteristicsElement);

EXTERN_C __declspec( dllexport ) BOOL SetMachineCode( PEHANDLE hPe, WORD wNewMachineCode );
EXTERN_C __declspec( dllexport ) BOOL SetNumberOfSections( PEHANDLE hPe, WORD wNewNumberOfSections );
EXTERN_C __declspec( dllexport ) BOOL SetTimeDataStamp( PEHANDLE hPe, DWORD dwNewTimeDataStamp );
EXTERN_C __declspec( dllexport ) BOOL SetPointerToSymbolTable( PEHANDLE hPe, DWORD dwNewPointerToSymbolTable );
EXTERN_C __declspec( dllexport ) BOOL SetNumberOfSymbols( PEHANDLE hPe, DWORD dwNewNumberOfSymbols );
EXTERN_C __declspec( dllexport ) BOOL SetSizeOfOptionalHeader( PEHANDLE hPe, WORD wNewSizeOfOptionalHeader );
EXTERN_C __declspec( dllexport ) BOOL SetFileHeaderCharacteristics( PEHANDLE hPe, WORD wNewFileHeaderCharacteristics );


// IMAGE_OPTIONAL_HEADER functions
EXTERN_C __declspec( dllexport ) DWORD GetEntryPointRVA( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetEntryPointRAW( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetImageBase( PEHANDLE hPe );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfImage( PEHANDLE hPe );


// IMAGE_SECTION_HEADER functions
EXTERN_C __declspec( dllexport ) DWORD GetSectionHeaderOffset( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetVirtualAddress( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetVirtualSize( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetSizeOfRawData( PEHANDLE hPe, DWORD nSection );
EXTERN_C __declspec( dllexport ) DWORD GetPointerToRawData( PEHANDLE hPe, DWORD nSection );


