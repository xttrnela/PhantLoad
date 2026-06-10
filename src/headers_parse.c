//headers_parse.c
#include "../include/common.h"

void GetPeHeaders(PVOID baseAddress, PHEADERS hds){
	if(baseAddress == NULL){
		printf("Base address is NULL\n");
		exit(EXIT_FAILURE);	
	}

	PIMAGE_DOS_HEADER dos_header = (PIMAGE_DOS_HEADER)baseAddress;
	if(dos_header->e_magic != IMAGE_DOS_SIGNATURE){
		printf("Invalid DOS header\n");
		exit(EXIT_FAILURE);
	}	
	printf("DOS header's address is correct!\n");
	
	PIMAGE_NT_HEADERS nt_headers = (PIMAGE_NT_HEADERS)((PBYTE)baseAddress + dos_header->e_lfanew);
	if(nt_headers->Signature != IMAGE_NT_SIGNATURE){
		printf("Invalid NT header\n");
		exit(EXIT_FAILURE);
	}
	printf("NT header's address is correct!\n");

	hds->nt_h = nt_headers;
}

