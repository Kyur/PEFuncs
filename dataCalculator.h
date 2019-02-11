#include <Windows.h>
#include <time.h>
#include <stdio.h>

// max FileHeader.Machine: 0x20
// max FileHeader.Characteristics: 0xF
#define MAX_NUMBER_OF_FILEHEADER_CHARACTERISTICS 0x0F
#define MAX_NUMBER_OF_MACHINE_CODE 0x20
#define MAX_TYPE_NAME_LIST 0x20


typedef struct __TYPE_NAME_LIST
{
	DWORD dwTypeValue[MAX_TYPE_NAME_LIST];
	char* szTypeName[MAX_TYPE_NAME_LIST];
}_TYPE_NAME_LIST, *_PTYPE_NAME_LIST;


VOID _MachineCodeConstructor(_PTYPE_NAME_LIST pMachineCode);
BOOL _GetMachineCodeName(WORD machineCode, char* szMachineCodeName);
VOID _GetTimeDataStampToTime(char* pszTimeStamp, size_t bufferSize, DWORD _timeStampDate);

/*
_PTYPE_NAME_LIST _MachineCodeConstructor();
VOID _GetFileHeaderCharacteristicsElement(PVOID pFHCharacteristics, WORD wCharacteristics);
*/
