#include "dataCalculator.h""

VOID _MachineCodeConstructor( _PTYPE_NAME_LIST pMachineCode )
{
	pMachineCode->dwTypeValue[0] = 0x00;
	pMachineCode->dwTypeValue[1] = 0x0001;
	pMachineCode->dwTypeValue[2] = 0x014c;
	pMachineCode->dwTypeValue[3] = 0x0162;
	pMachineCode->dwTypeValue[4] = 0x0166;
	pMachineCode->dwTypeValue[5] = 0x0168;
	pMachineCode->dwTypeValue[6] = 0x0169;
	pMachineCode->dwTypeValue[7] = 0x0184;
	pMachineCode->dwTypeValue[8] = 0x01a2;
	pMachineCode->dwTypeValue[9] = 0x01a3;
	pMachineCode->dwTypeValue[10] = 0x01a4;
	pMachineCode->dwTypeValue[11] = 0x01a6;
	pMachineCode->dwTypeValue[12] = 0x01a8;
	pMachineCode->dwTypeValue[13] = 0x01c0;
	pMachineCode->dwTypeValue[14] = 0x01c2;
	pMachineCode->dwTypeValue[15] = 0x01c4;
	pMachineCode->dwTypeValue[16] = 0x01d3;
	pMachineCode->dwTypeValue[17] = 0x01F0;
	pMachineCode->dwTypeValue[18] = 0x01f1;
	pMachineCode->dwTypeValue[19] = 0x0200;
	pMachineCode->dwTypeValue[20] = 0x0266;
	pMachineCode->dwTypeValue[21] = 0x0284;
	pMachineCode->dwTypeValue[22] = 0x0366;
	pMachineCode->dwTypeValue[23] = 0x0466;
	pMachineCode->dwTypeValue[24] = 0x0284;
	pMachineCode->dwTypeValue[25] = 0x0520;
	pMachineCode->dwTypeValue[26] = 0x0CEF;
	pMachineCode->dwTypeValue[27] = 0x0EBC;
	pMachineCode->dwTypeValue[28] = 0x8664;
	pMachineCode->dwTypeValue[29] = 0x9041;
	pMachineCode->dwTypeValue[30] = 0xAA64;
	pMachineCode->dwTypeValue[31] = 0xC0EE;

	pMachineCode->szTypeName[0] = "IMAGE_FILE_MACHINE_UNKNOWN";
	pMachineCode->szTypeName[1] = "IMAGE_FILE_MACHINE_TARGET_HOST";
	pMachineCode->szTypeName[2] = "IMAGE_FILE_MACHINE_I386";
	pMachineCode->szTypeName[3] = "IMAGE_FILE_MACHINE_R3000";
	pMachineCode->szTypeName[4] = "IMAGE_FILE_MACHINE_R4000";
	pMachineCode->szTypeName[5] = "IMAGE_FILE_MACHINE_R10000";
	pMachineCode->szTypeName[6] = "IMAGE_FILE_MACHINE_WCEMIPSV2";
	pMachineCode->szTypeName[7] = "IMAGE_FILE_MACHINE_ALPHA";
	pMachineCode->szTypeName[8] = "IMAGE_FILE_MACHINE_SH3";
	pMachineCode->szTypeName[9] = "IMAGE_FILE_MACHINE_SH3DSP";
	pMachineCode->szTypeName[10] = "IMAGE_FILE_MACHINE_SH3E";
	pMachineCode->szTypeName[11] = "IMAGE_FILE_MACHINE_SH4";
	pMachineCode->szTypeName[12] = "IMAGE_FILE_MACHINE_SH5";
	pMachineCode->szTypeName[13] = "IMAGE_FILE_MACHINE_ARM";
	pMachineCode->szTypeName[14] = "IMAGE_FILE_MACHINE_THUMB";
	pMachineCode->szTypeName[15] = "IMAGE_FILE_MACHINE_ARMNT";
	pMachineCode->szTypeName[16] = "IMAGE_FILE_MACHINE_AM33";
	pMachineCode->szTypeName[17] = "IMAGE_FILE_MACHINE_POWERPC";
	pMachineCode->szTypeName[18] = "IMAGE_FILE_MACHINE_POWERPCFP";
	pMachineCode->szTypeName[19] = "IMAGE_FILE_MACHINE_IA64";
	pMachineCode->szTypeName[20] = "IMAGE_FILE_MACHINE_MIPS16";
	pMachineCode->szTypeName[21] = "IMAGE_FILE_MACHINE_ALPHA64";
	pMachineCode->szTypeName[22] = "IMAGE_FILE_MACHINE_MIPSFPU";
	pMachineCode->szTypeName[23] = "IMAGE_FILE_MACHINE_MIPSFPU16";
	pMachineCode->szTypeName[24] = "IMAGE_FILE_MACHINE_AXP64";
	pMachineCode->szTypeName[25] = "IMAGE_FILE_MACHINE_TRICORE";
	pMachineCode->szTypeName[26] = "IMAGE_FILE_MACHINE_CEF";
	pMachineCode->szTypeName[27] = "IMAGE_FILE_MACHINE_EBC";
	pMachineCode->szTypeName[28] = "IMAGE_FILE_MACHINE_AMD64";
	pMachineCode->szTypeName[29] = "IMAGE_FILE_MACHINE_M32R";
	pMachineCode->szTypeName[30] = "IMAGE_FILE_MACHINE_ARM64";
	pMachineCode->szTypeName[31] = "IMAGE_FILE_MACHINE_CEE";
}

BOOL _GetMachineCodeName( WORD machineCode, char* szMachineCodeName )
{
	_TYPE_NAME_LIST MachineCode;

	_MachineCodeConstructor( &MachineCode );

	for ( int cnt = 0; cnt <= MAX_NUMBER_OF_MACHINE_CODE; cnt++ )
	{
		if ( MachineCode.dwTypeValue[cnt] == machineCode )
		{
			strncpy( szMachineCodeName, MachineCode.szTypeName[cnt], strlen( MachineCode.szTypeName[cnt] ) );
			return TRUE;
		}
	}

	return FALSE;
}

VOID _GetTimeDataStampToTime( char* pszTimeStamp, size_t bufferSize, DWORD _timeStampDate )
{
	struct tm timeStruct;
	time_t timer;

	timer = (time_t) _timeStampDate;			// Get Time Stamp Data.
	localtime_s( &timeStruct, &timer );		// Division time.

	sprintf_s( pszTimeStamp, bufferSize, "%04d-%02d-%02d %02d:%02d:%02d",
		timeStruct.tm_year + 1900,
		timeStruct.tm_mon + 1,
		timeStruct.tm_mday,
		timeStruct.tm_hour,
		timeStruct.tm_min,
		timeStruct.tm_sec
	);
}


/*
_PTYPE_NAME_LIST _FileHeaderCharacteristicsConstructor()
{
	static _TYPE_NAME_LIST fileHeaderCharacteristics;
	_PTYPE_NAME_LIST pFileHeaderCharacteristics = NULL;

	fileHeaderCharacteristics.dwTypeValue[0] = 0x0001;
	fileHeaderCharacteristics.dwTypeValue[1] = 0x0002;
	fileHeaderCharacteristics.dwTypeValue[2] = 0x0004;
	fileHeaderCharacteristics.dwTypeValue[3] = 0x0008;
	fileHeaderCharacteristics.dwTypeValue[4] = 0x0010;
	fileHeaderCharacteristics.dwTypeValue[5] = 0x0020;
	fileHeaderCharacteristics.dwTypeValue[6] = 0x0080;
	fileHeaderCharacteristics.dwTypeValue[7] = 0x0100;
	fileHeaderCharacteristics.dwTypeValue[8] = 0x0200;
	fileHeaderCharacteristics.dwTypeValue[9] = 0x0400;
	fileHeaderCharacteristics.dwTypeValue[10] = 0x0800;
	fileHeaderCharacteristics.dwTypeValue[11] = 0x1000;
	fileHeaderCharacteristics.dwTypeValue[12] = 0x2000;
	fileHeaderCharacteristics.dwTypeValue[13] = 0x4000;
	fileHeaderCharacteristics.dwTypeValue[14] = 0x8000;

	fileHeaderCharacteristics.szTypeName[0] = "IMAGE_FILE_RELOCS_STRIPPED";
	fileHeaderCharacteristics.szTypeName[1] = "IMAGE_FILE_EXECUTABLE_IMAGE";
	fileHeaderCharacteristics.szTypeName[2] = "IMAGE_FILE_LINE_NUMS_STRIPPED";
	fileHeaderCharacteristics.szTypeName[3] = "IMAGE_FILE_LOCAL_SYMS_STRIPPED";
	fileHeaderCharacteristics.szTypeName[4] = "IMAGE_FILE_AGGRESIVE_WS_TRIM";
	fileHeaderCharacteristics.szTypeName[5] = "IMAGE_FILE_LARGE_ADDRESS_AWARE";
	fileHeaderCharacteristics.szTypeName[6] = "IMAGE_FILE_BYTES_REVERSED_LO";
	fileHeaderCharacteristics.szTypeName[7] = "IMAGE_FILE_32BIT_MACHINE";
	fileHeaderCharacteristics.szTypeName[8] = "IMAGE_FILE_DEBUG_STRIPPED";
	fileHeaderCharacteristics.szTypeName[9] = "IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP";
	fileHeaderCharacteristics.szTypeName[10] = "IMAGE_FILE_NET_RUN_FROM_SWAP";
	fileHeaderCharacteristics.szTypeName[11] = "IMAGE_FILE_SYSTEM";
	fileHeaderCharacteristics.szTypeName[12] = "IMAGE_FILE_DLL";
	fileHeaderCharacteristics.szTypeName[13] = "IMAGE_FILE_UP_SYSTEM_ONLY";
	fileHeaderCharacteristics.szTypeName[14] = "IMAGE_FILE_BYTES_REVERSED_HI";

	return pFileHeaderCharacteristics;
}


VOID _GetFileHeaderCharacteristicsElement(PVOID pFHCharacteristics, WORD wCharacteristics)
{
	WORD bitMask = 0x01;

	_PTYPE_NAME_LIST pFileHeaderCharacteristics = _FileHeaderCharacteristicsConstructor();

	for (int cnt = 0; cnt <= MAX_NUMBER_OF_FILEHEADER_CHARACTERISTICS; cnt++)
	{
		if (wCharacteristics & bitMask)
		{
			(_PTYPE_NAME_LIST)pFHCharacteristics->dwTypeValue[cnt] = pFileHeaderCharacteristics->dwTypeValue[cnt];
			pFHCharacteristics->szTypeName[cnt] = pFileHeaderCharacteristics->szTypeName[cnt];
		}

		bitMask << 1;

		if (bitMask & 0x40)
			bitMask << 1;
	}
}
*/