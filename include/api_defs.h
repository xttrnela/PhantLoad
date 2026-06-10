#ifndef API_DEFS_H 
#define API_DEFS_H 

//#include <windows.h>
//#include <bcrypt.h>
//#include <winternl.h>


//kernel32.dll
//////////////
//////////////
typedef FARPROC (WINAPI *type_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

typedef HMODULE (WINAPI *type_LoadLibraryA)(LPCSTR lpLibFileName);

typedef LPVOID (WINAPI *type_VirtualAlloc)(
   	LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flAllocationType,
        DWORD  flProtect
);

typedef BOOL (WINAPI *type_VirtualProtect)(
        LPVOID lpAddress,
        SIZE_T dwSize,
        DWORD  flNewProtect,
        PDWORD lpflOldProtect
);

typedef LPVOID (WINAPI *type_HeapAlloc)(
        HANDLE hHeap,
        DWORD  dwFlags,
        SIZE_T dwBytes
);

typedef BOOL (WINAPI *type_HeapFree)(
        HANDLE hHeap,
        DWORD  dwFlags,
        LPVOID lpMem
);

typedef HANDLE (WINAPI *type_GetProcessHeap)();

//bcrypt.dll
////////////
////////////
typedef NTSTATUS (WINAPI *type_BCryptOpenAlgorithmProvider)(
	BCRYPT_ALG_HANDLE *phAlgorithm, 
	LPCWSTR 	  pszAlgId, 
	LPCWSTR 	  pszImplementation, 
	ULONG 	          dwFlags
);

typedef NTSTATUS (WINAPI *type_BCryptSetProperty)(
	BCRYPT_HANDLE hObject,
        LPCWSTR       pszProperty,
        PUCHAR        pbInput,
        ULONG         cbInput,
        ULONG         dwFlags
);

typedef NTSTATUS (WINAPI *type_BCryptGenerateSymmetricKey)(
        BCRYPT_ALG_HANDLE hAlgorithm,
        BCRYPT_KEY_HANDLE *phKey,
   	PUCHAR            pbKeyObject,
        ULONG             cbKeyObject,
        PUCHAR            pbSecret,
        ULONG             cbSecret,
        ULONG             dwFlags
);

typedef NTSTATUS (WINAPI *type_BCryptDecrypt)(
        BCRYPT_KEY_HANDLE hKey,
        PUCHAR            pbInput,
        ULONG             cbInput,
        VOID              *pPaddingInfo,
        PUCHAR            pbIV,
        ULONG             cbIV,
        PUCHAR            pbOutput,
        ULONG             cbOutput,
        ULONG             *pcbResult,
        ULONG             dwFlags
);


typedef NTSTATUS (WINAPI *type_BCryptDestroyKey)(BCRYPT_KEY_HANDLE hKey);

typedef NTSTATUS (WINAPI *type_BCryptCloseAlgorithmProvider)(
   	BCRYPT_ALG_HANDLE hAlgorithm,
        ULONG             dwFlags
);

typedef NTSTATUS (WINAPI *type_BCryptGetProperty)(
        BCRYPT_HANDLE hObject,
        LPCWSTR       pszProperty,
        PUCHAR        pbOutput,
        ULONG         cbOutput,
        ULONG         *pcbResult,
        ULONG         dwFlags
);

//user32.dll
////////////
////////////



#endif
