#include <windows.h> 

int main(void){
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hConsole == INVALID_HANDLE_VALUE) return -1;

	const char *text = "helllllllo";
	DWORD len = (DWORD)strlen(text);
	DWORD written = 0;

	BOOL success = WriteConsole(hConsole, text, len, &written, NULL);
}
