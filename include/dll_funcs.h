#ifndef DLL_FUNCS_H
#define DLL_FUNCS_H

typedef struct KERNEL32_DLL_FUNCTIONS{
	type_GetProcAddress 		pGetProcAddress;
	type_LoadLibraryA   		pLoadLibraryA;
	type_VirtualAlloc   		pVirtualAlloc;
	type_VirtualProtect 		pVirtualProtect;
	type_HeapAlloc 					pHeapAlloc;
	type_HeapFree 					pHeapFree;
	type_GetProcessHeap     pGetProcessHeap;
}K32_FUNCS, *PK32_FUNCS;


typedef struct USER32_DLL_FUNCTIONS{
	PVOID pCreateWindowEx;
	PVOID pMessageBoxA;
}U32_FUNCS, *PU32_FUNCS;


typedef struct BCRYPT_DLL_FUNCTIONS{
	type_BCryptOpenAlgorithmProvider  pBCryptOpenAlgorithmProvider;
	type_BCryptSetProperty 		  			pBCryptSetProperty;
	type_BCryptGenerateSymmetricKey   pBCryptGenerateSymmetricKey;
	type_BCryptDecrypt 		  					pBCryptDecrypt;
	type_BCryptDestroyKey 		  			pBCryptDestroyKey;
	type_BCryptCloseAlgorithmProvider pBCryptCloseAlgorithmProvider;
	type_BCryptGetProperty 						pBCryptGetProperty;
}BC_FUNCS, *PBC_FUNCS;

#endif
