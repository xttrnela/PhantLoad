//common.h
#ifndef COMMON_H
#define COMMON_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
//#include <wincrypt.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api_defs.h"
#include "dll_funcs.h"

typedef struct _FULL_LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY     InLoadOrderLinks;
  LIST_ENTRY     InMemoryOrderLinks;
	LIST_ENTRY     InInitializationOrderLinks;
  PVOID 				 DllBase;
  PVOID          EntryPoint;
  ULONG          SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName; 
		
} FULL_LDR_DATA_TABLE_ENTRY, *PFULL_LDR_DATA_TABLE_ENTRY;

enum KERNEL32_INDEX{
	IDX_GetProcAddress = 0,
  IDX_LoadLibraryA, 
	IDX_VirtualAlloc,
	IDX_VirtualProtect,
	IDX_HeapAlloc,
	IDX_HeapFree,
	IDX_GetProcessHeap
};

enum BCRYPT_INDEX{
  IDX_BCryptOpenAlgorithmProvider = 0,
	IDX_BCryptSetProperty,
  IDX_BCryptGenerateSymmetricKey,
  IDX_BCryptDecrypt,
	IDX_BCryptDestroyKey,
	IDX_BCryptCloseAlgorithmProvider,
	IDX_BCryptGetProperty
};


typedef struct _HEADERS{
	PIMAGE_NT_HEADERS	nt_h; 
	PIMAGE_EXPORT_DIRECTORY exports;	
}HEADERS, *PHEADERS;


typedef struct _MODULE_CTX{
	PVOID 	dllBase;
	HEADERS hds;
	union {
        	PVOID funcs[32];
          K32_FUNCS k32; 
          BC_FUNCS  bcrypt;
					U32_FUNCS u32;
  };
}MODULE_CTX, *PMODULE_CTX;


typedef struct _INSTANCE{
	MODULE_CTX kernel32_dll;
	MODULE_CTX bcrypt_dll;
	MODULE_CTX user32_dll;
	
	PVOID pPayload;
	DWORD dwPayloadSize;
	PVOID pKey;
	PVOID pIV;

	BOOL bIsDebug;
}INSTANCE, *PINSTANCE;


typedef struct _PE_CONTEXT {
  PVOID   pRawData;
  PVOID   pTargetBase;
	HEADERS hds;
	BOOL	  TargetBaseState;
} PE_CONTEXT, *PPE_CONTEXT;

// --- Function Prototypes ---

// headers_parse.c
void GetPeHeaders(PVOID baseAddress, PHEADERS hds);

// api_resolver.c
PIMAGE_EXPORT_DIRECTORY GetExportDirectory(PVOID dllBase, PHEADERS hds);
PVOID 									GetDllBase(const wchar_t *dll_name);
PVOID 									GetDllFuncAddress(PVOID dllBase, PIMAGE_EXPORT_DIRECTORY exportTable, char *funcNameString);
INT 										InitK32(PINSTANCE inst);
INT 										InitBcrypt(PINSTANCE inst);

// pe_mapper.c
INT 	InitPEctx(PPE_CONTEXT);
// pe_mapper.c
void 	wVirtualAlloc(PPE_CONTEXT pe_ctx, LPVOID pref_addr, type_VirtualAlloc pVirtualAlloc);
INT 	AllocateBase(PPE_CONTEXT pe_ctx, PINSTANCE inst);
INT 	MapSections(PPE_CONTEXT pe_ctx);
INT 	FixRelocations(PPE_CONTEXT pe_ctx);
INT 	ResolveImports(PPE_CONTEXT pe_ctx, PINSTANCE inst);

// decrypt.c
INT DecryptPayload(PINSTANCE inst);
#endif
