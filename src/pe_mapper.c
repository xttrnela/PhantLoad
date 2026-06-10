//pe_mapper.c
#include "../include/common.h"

INT InitPEctx(PPE_CONTEXT pe_ctx){
	GetPeHeaders(pe_ctx->pRawData, &pe_ctx->hds);
	
	pe_ctx->hds.exports = GetExportDirectory(pe_ctx->pRawData, &pe_ctx->hds);
	if(pe_ctx->hds.exports == NULL){
		printf("Export directory not found (normal for EXE)\n");
	}
	return 0;
}

INT MapSections(PPE_CONTEXT pe_ctx) {
	if (pe_ctx == NULL || pe_ctx->pTargetBase == NULL || pe_ctx->pRawData == NULL) 
		return -1;

	// 1. Copy Headers
	memcpy(
		pe_ctx->pTargetBase, 
		pe_ctx->pRawData, 
		pe_ctx->hds.nt_h->OptionalHeader.SizeOfHeaders
	);

	// 2. Map Sections
	PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pe_ctx->hds.nt_h);

	for (WORD i = 0; i < pe_ctx->hds.nt_h->FileHeader.NumberOfSections; i++) {
		if (section[i].SizeOfRawData == 0) continue;

		PVOID pSource = (PVOID)((PBYTE)pe_ctx->pRawData + section[i].PointerToRawData);
		PVOID pDest = (PVOID)((PBYTE)pe_ctx->pTargetBase + section[i].VirtualAddress);

		memcpy(pDest, pSource, section[i].SizeOfRawData);

		printf("[*] Mapping section: %-8s | Offset: 0x%08X -> VA: 0x%08X\n",
			section[i].Name,
			section[i].PointerToRawData,
			section[i].VirtualAddress);
	}

	return 0;
}

INT FixRelocations(PPE_CONTEXT pe_ctx) {
	ULONG_PTR delta = (ULONG_PTR)pe_ctx->pTargetBase - (ULONG_PTR)pe_ctx->hds.nt_h->OptionalHeader.ImageBase;

	if (delta == 0) {
		printf("Payload loaded at preferred address. Skipping relocations.\n");
		return 0;
	}

	IMAGE_DATA_DIRECTORY reloc_table = pe_ctx->hds.nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (reloc_table.Size == 0) {
		printf("No relocation table found.\n");
		return 0;
	}

	PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pe_ctx->pTargetBase + reloc_table.VirtualAddress);
	DWORD bytesProcessed = 0;

	while (bytesProcessed < reloc_table.Size && pReloc->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
		DWORD entriesCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		PWORD pEntryList = (PWORD)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));

		for (DWORD i = 0; i < entriesCount; i++) {
			WORD type = pEntryList[i] >> 12;
			WORD offset = pEntryList[i] & 0x0FFF;

			if (type == IMAGE_REL_BASED_DIR64) {
				ULONG_PTR* pPatchAddr = (ULONG_PTR*)((PBYTE)pe_ctx->pTargetBase + pReloc->VirtualAddress + offset);
				*pPatchAddr += delta;
			}
		}

		bytesProcessed += pReloc->SizeOfBlock;
		pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
	}

	printf("Base relocations fixed successfully!\n");
	return 0;
}

INT ResolveImports(PPE_CONTEXT pe_ctx, PINSTANCE inst) {
	IMAGE_DATA_DIRECTORY import_table = pe_ctx->hds.nt_h->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (import_table.Size == 0) return 0;

	PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)pe_ctx->pTargetBase + import_table.VirtualAddress);
	K32_FUNCS* k = &inst->kernel32_dll.k32;

	while (pImportDesc->Name != 0) {
		char* libName = (char*)((PBYTE)pe_ctx->pTargetBase + pImportDesc->Name);
		
		HMODULE hLib = k->pLoadLibraryA(libName);
		if (hLib == NULL) {
			printf("Failed to load library: %s\n", libName);
			return -1;
		}

		PIMAGE_THUNK_DATA thunkINT = (PIMAGE_THUNK_DATA)((PBYTE)pe_ctx->pTargetBase + (pImportDesc->OriginalFirstThunk ? pImportDesc->OriginalFirstThunk : pImportDesc->FirstThunk));
		PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((PBYTE)pe_ctx->pTargetBase + pImportDesc->FirstThunk);

		while (thunkINT->u1.AddressOfData != 0) {
			PVOID funcAddr = NULL;

			if (IMAGE_SNAP_BY_ORDINAL(thunkINT->u1.Ordinal)) {
				funcAddr = k->pGetProcAddress(hLib, (LPCSTR)IMAGE_ORDINAL(thunkINT->u1.Ordinal));
			} else {
				PIMAGE_IMPORT_BY_NAME pImportName = (PIMAGE_IMPORT_BY_NAME)((PBYTE)pe_ctx->pTargetBase + thunkINT->u1.AddressOfData);
				funcAddr = k->pGetProcAddress(hLib, (LPCSTR)pImportName->Name);
				printf("Resolving: %s!%s\n", libName, pImportName->Name);
			}

			if (funcAddr == NULL) {
				printf("Could not resolve function in %s\n", libName);
				return -1;
			}

			thunkIAT->u1.Function = (ULONG_PTR)funcAddr;

			thunkINT++;
			thunkIAT++;
		}
		pImportDesc++;
	}
	return 0;
}

void wVirtualAlloc(PPE_CONTEXT pe_ctx, LPVOID pref_addr, type_VirtualAlloc pVirtualAlloc){
	
	pe_ctx->pTargetBase = pVirtualAlloc(
			pref_addr,
			pe_ctx->hds.nt_h->OptionalHeader.SizeOfImage, 
                        MEM_COMMIT | MEM_RESERVE, 
                        PAGE_READWRITE
	);
}

INT AllocateBase(PPE_CONTEXT pe_ctx, PINSTANCE inst){
	
	LPVOID pref_addr = (LPVOID)pe_ctx->hds.nt_h->OptionalHeader.ImageBase;

	wVirtualAlloc(pe_ctx, pref_addr, inst->kernel32_dll.k32.pVirtualAlloc);

	if(pe_ctx->pTargetBase == NULL){
		wVirtualAlloc(pe_ctx, NULL, inst->kernel32_dll.k32.pVirtualAlloc);
		pe_ctx->TargetBaseState = FALSE;
	} 
	else {	
		pe_ctx->TargetBaseState = TRUE;
		printf("Memory allocated at preffered address\n");
	}
	
	if(pe_ctx->pTargetBase == NULL){
		printf("Failed to allocate memory\n");
		return -1;	
	}
	
	return 0;	
}
