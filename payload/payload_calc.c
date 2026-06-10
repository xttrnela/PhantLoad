#include <windows.h>

/**
 * Payload PoC for PhantLoad testing.
 * This payload performs three common actions to verify the loader's functionality:
 * 1. Shows a Message Box (User32.dll import test)
 * 2. Spawns Calculator (Process execution test)
 * 3. Creates a marker file (File I/O test)
 */

int main() {
    // 1. Test User32.dll resolution
    MessageBoxA(NULL, 
        "PhantLoad: Reflective Loading Successful!\n\n"
        "This payload verifies that:\n"
        "- Section mapping is correct\n"
        "- Base relocations are applied\n"
        "- Import Address Table (IAT) is resolved\n"
        "- Memory protections (NX bypass) are working", 
        "PhantLoad Security Research", 
        MB_OK | MB_ICONINFORMATION);

    // 2. Test Kernel32.dll process execution
    WinExec("calc.exe", SW_SHOW);

    // 3. Test File System interaction
    HANDLE hFile = CreateFileA("phant_trace.txt", 
        GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    
    if (hFile != INVALID_HANDLE_VALUE) {
        DWORD written;
        char msg[] = "Success!\nThis file was created by a reflectively loaded payload.";
        WriteFile(hFile, msg, sizeof(msg) - 1, &written, NULL);
        CloseHandle(hFile);
    }

    return 0;
}
