//api_resolver.c
#include "../include/common.h"

PIMAGE_EXPORT_DIRECTORY GetExportDirectory(PVOID dllBase, PHEADERS hds) {
        DWORD exportRVA = hds->nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

        if (exportRVA == 0) return NULL;

	printf("exports are correct!\n");

        return (PIMAGE_EXPORT_DIRECTORY)((PBYTE)dllBase + exportRVA);
}


PVOID GetDllBase(const wchar_t *dll_name){
	PVOID dllBase = NULL;
	
        PPEB pebAddr = (PPEB)__readgsqword(0x60);

        PLIST_ENTRY listHead = &pebAddr->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY current = listHead->Flink;
		
	while(current != listHead){
		PFULL_LDR_DATA_TABLE_ENTRY entry = (PFULL_LDR_DATA_TABLE_ENTRY)((PBYTE)current - 16);		
		if(entry->BaseDllName.Buffer != NULL){
			if(_wcsicmp(entry->BaseDllName.Buffer, dll_name) == 0){
				dllBase = entry->DllBase;
				printf("%ls is found! address: %p\n", dll_name, entry->DllBase);
				break;		
			}
		}
		current = current->Flink;
	}

        if(dllBase == NULL){
                printf("Dll Base is NULL\n");
                exit(EXIT_FAILURE);
        }
	
        return dllBase;
}


PVOID GetDllFuncAddress(PVOID dllBase, PIMAGE_EXPORT_DIRECTORY exportTable, char *funcNameString){
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dllBase;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((PBYTE)dllBase + dos->e_lfanew);

	DWORD exportDirRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportDirSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	PDWORD 	namesRvaArray = (PDWORD)((PBYTE)dllBase + exportTable->AddressOfNames);
	PWORD 	ordinalArray = (PWORD)((PBYTE)dllBase + exportTable->AddressOfNameOrdinals);
	PDWORD 	funcRvaArray = (PDWORD)((PBYTE)dllBase + exportTable->AddressOfFunctions);

	for(DWORD i = 0; i < exportTable->NumberOfNames; i++){

		char *currentFuncName = (char *)((PBYTE)dllBase + namesRvaArray[i]);

		if(strcmp(currentFuncName, funcNameString) == 0){
			WORD ordinal = ordinalArray[i];
			DWORD funcRVA = funcRvaArray[ordinal];
			PVOID funcAddr = (PVOID)((PBYTE)dllBase + funcRVA);

			if (funcRVA >= exportDirRVA && funcRVA < (exportDirRVA + exportDirSize)) {
				char forwarderName[256];
				strncpy(forwarderName, (char*)funcAddr, 255);
				forwarderName[255] = '\0';

				char *dllName = forwarderName;
				char *funcName = strchr(forwarderName, '.');
				if (!funcName) return NULL;

				*funcName = '\0';
				funcName++;

				char fullDllName[256];
				snprintf(fullDllName, 256, "%s.dll", dllName);

				WCHAR wFullDllName[256];
				mbstowcs(wFullDllName, fullDllName, 256);

				PVOID targetDllBase = GetDllBase(wFullDllName);
				HEADERS targetHds;
				GetPeHeaders(targetDllBase, &targetHds);
				PIMAGE_EXPORT_DIRECTORY targetExport = GetExportDirectory(targetDllBase, &targetHds);

				return GetDllFuncAddress(targetDllBase, targetExport, funcName);
			}

			printf("Found %s!\n", funcNameString);
			return funcAddr;
		}
	} 	
	return NULL;
}


INT InitK32(PINSTANCE inst){
	if(inst == NULL) return -1;

	PMODULE_CTX k32 = &inst->kernel32_dll;

	k32->dllBase = GetDllBase(L"kernel32.dll");

	GetPeHeaders(k32->dllBase, &k32->hds);		
	k32->hds.exports = GetExportDirectory(k32->dllBase, &k32->hds);

	k32->funcs[IDX_LoadLibraryA] = 	 GetDllFuncAddress(k32->dllBase, k32->hds.exports, "LoadLibraryA");
	k32->funcs[IDX_GetProcAddress] = GetDllFuncAddress(k32->dllBase, k32->hds.exports, "GetProcAddress");
	k32->funcs[IDX_VirtualAlloc] = 	 GetDllFuncAddress(k32->dllBase, k32->hds.exports, "VirtualAlloc");
	k32->funcs[IDX_VirtualProtect] = GetDllFuncAddress(k32->dllBase, k32->hds.exports, "VirtualProtect");
	k32->funcs[IDX_HeapAlloc] = 	 GetDllFuncAddress(k32->dllBase, k32->hds.exports, "HeapAlloc");
	k32->funcs[IDX_HeapFree] = 	 GetDllFuncAddress(k32->dllBase, k32->hds.exports, "HeapFree");
	k32->funcs[IDX_GetProcessHeap] = GetDllFuncAddress(k32->dllBase, k32->hds.exports, "GetProcessHeap");

	return 0;
	
}

INT InitBcrypt(PINSTANCE inst){
	if(inst == NULL) return -1;

	PMODULE_CTX bcrypt = &inst->bcrypt_dll;

	bcrypt->dllBase = inst->kernel32_dll.k32.pLoadLibraryA("bcrypt.dll");
	if(bcrypt->dllBase == NULL){
		printf("Failed to load bcrypt.dll\n");
		return -1;
	}

	GetPeHeaders(bcrypt->dllBase, &bcrypt->hds);

	bcrypt->hds.exports = GetExportDirectory(bcrypt->dllBase, &bcrypt->hds);

	bcrypt->funcs[IDX_BCryptOpenAlgorithmProvider] =  GetDllFuncAddress(bcrypt->dllBase, bcrypt->hds.exports, "BCryptOpenAlgorithmProvider");
  	bcrypt->funcs[IDX_BCryptSetProperty] = 	          GetDllFuncAddress(bcrypt->dllBase, bcrypt->hds.exports, "BCryptSetProperty");
  	bcrypt->funcs[IDX_BCryptGenerateSymmetricKey] =   GetDllFuncAddress(bcrypt->dllBase, bcrypt->hds.exports, "BCryptGenerateSymmetricKey");
  	bcrypt->funcs[IDX_BCryptDecrypt] = 		  GetDllFuncAddress(bcrypt->dllBase, bcrypt->hds.exports, "BCryptDecrypt");
  	bcrypt->funcs[IDX_BCryptDestroyKey] = 		  GetDllFuncAddress(bcrypt->dllBase, bcrypt->hds.exports, "BCryptDestroyKey");
  	bcrypt->funcs[IDX_BCryptCloseAlgorithmProvider] = GetDllFuncAddress(bcrypt->dllBase, bcrypt->hds.exports, "BCryptCloseAlgorithmProvider");
  	bcrypt->funcs[IDX_BCryptGetProperty] = 	          GetDllFuncAddress(bcrypt->dllBase, bcrypt->hds.exports, "BCryptGetProperty");

	return 0;

}
