#include <string.h>
#include <string>
#include <windows.h>
#include <iostream>
#include <fstream>
#include <d3d9.h>
#include <time.h>  
#include <cstdlib>
#include <functional> 
#include <algorithm>  


using namespace std;

void saveLog() {

	ofstream myfile;
	myfile.open("loader_log.txt");
	myfile << "INJECTION_SUCCESS!";
	myfile.close();
}

void MemSprayString(long addrToInject) {
	LPVOID getPRoce = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + addrToInject);
	HANDLE internalHandleShit = GetCurrentProcess();
	WriteProcessMemory(internalHandleShit, getPRoce, "", sizeof(""), NULL);
}
void HelloWorld()
{
	MessageBox(0, "Grabb Internal\nThanks for downloading...\nHirako Shiniji", "Grabb - Beta", MB_ICONINFORMATION);
}
void printL(const char*print) {
	MessageBox(0, print, "Grabb - Alert", MB_ICONINFORMATION);

}
void clear() {
	// CSI[2J clears screen, CSI[H moves the cursor to top-left corner
	std::cout << "\x1B[2J\x1B[H";
}
void nop(int nopLength,long offset) {
	LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + offset);
	HANDLE a = GetCurrentProcess();
	BYTE nop[] = { 0x90 };
	nop+nopLength;
	WriteProcessMemory(a, entry, nop, sizeof(nop), NULL);
}
void memSpray(long address,BYTE* offsets) {
	//Internal Memory Hack secure asf
	LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + address);
	HANDLE a = GetCurrentProcess();
	WriteProcessMemory(a, entry, offsets, 2, NULL);

}
void memSpray32(long address,  int offsets) {
	//Internal Memory Hack secure asf
	LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + address);
	HANDLE a = GetCurrentProcess();
	WriteProcessMemory(a, entry, LPCVOID(offsets), sizeof(offsets), NULL);

}
void PrintLastErrorMsg() {
	LPTSTR pTmp = NULL;
	DWORD errnum = GetLastError();
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY,
		NULL,
		errnum,
		LANG_NEUTRAL,
		(LPTSTR)&pTmp,
		0,
		NULL
	);

	cout << "Error(" << errnum << "): " << pTmp << endl;
}
std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}
int PAGE_MENU = 1;
std::string random_string(size_t length)
{
	auto randchar = []() -> char
	{
		const char charset[] =
			"0123456789"
			"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			"abcdefghijklmnopqrstuvwxyz";
		const size_t max_index = (sizeof(charset) - 1);
		return charset[rand() % max_index];
	};
	std::string str(length, 0);
	std::generate_n(str.begin(), length, randchar);
	return str;
}
void DrawMenu(BYTE* offsets) {
	
	//Internal Draw Menu using simple menu pattern.
	//Pattern Hardcoded By Hirako Shiniji
	//Menu Pattern : 60 34 47 72 61 62 62 20 4D 65 6E 75 20 76 31 2E 34 0D 0A 60 30 46 31 20 2D 20 41 6E 74 69 62 6F 75 6E 63 65 0D 0A 46 32 20 2D 20 4D 6F 64 20 46 6C 79 0D 0A 5B 2A 5D 20 43 72 65 64 69 74 73 0D 0A 5B 2A 5D 20 4D 61 64 65 20 42 79 20 48 69 72 61 6B 6F
	
	if (PAGE_MENU == 1) {
		HWND hwnd = FindWindowA(NULL, "");
		LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + 0x3F7148);
		DWORD procID;
		HANDLE OpenProce = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		OpenProce;
		HANDLE a = GetCurrentProcess();
		DWORD oldProtect = 0;
		DWORD OLDPROTECT;
		rand() % 6;
		const char* MenuPattern = "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce\n[*] F3 - AutoRespawn\nPAGE - 1 [Player Menu] ";
		//VirtualAlloc(entry, sizeof("`4Grabb Beta 1.0\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce"), PAGE_EXECUTE_READWRITE, MEM_FREE);
		VirtualProtectEx(a, entry, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `" +random_string(1) + "Grabb Menu Beta 1.6\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce\n[*] F3 - AutoRespawn\nPAGE - 1 [Player Menu] "), PAGE_EXECUTE_READWRITE, &OLDPROTECT);
		string dram="fps: %d - M : %.2f, T : %.2f A : %.2f F : %.2f\n\n `" + random_string(1) + "Grabb Menu Beta 1.6\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce\n[*] F3 - AutoRespawn\nPAGE - 1 [Player Menu] ";
		WriteProcessMemory(a, entry, &dram, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce\n[*] F3 - AutoRespawn\nPAGE - 1 [Player Menu] "), NULL);
		BOOL patternInıt = WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce\n[*] F3 - AutoRespawn\nPAGE - 1 [Player Menu] ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce\n[*] F3 - AutoRespawn\nPAGE - 1 [Player Menu] "), NULL);
		VirtualProtectEx(a, entry, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce\n[*] F3 - AutoRespawn\nPAGE - 1 [Player Menu]  "), PAGE_READONLY, &OLDPROTECT);
	}
	if (PAGE_MENU == 2) {
		HWND hwnd = FindWindowA(NULL, "");
		LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + 0x3F7148);
		DWORD procID;
		HANDLE OpenProce = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
		OpenProce;
		HANDLE a = GetCurrentProcess();
		DWORD oldProtect = 0;
		DWORD OLDPROTECT;
		const char* MenuPattern = "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4_______________________\n|`0Grabb Menu Beta 1.6`4|\n`4___________________\n`0[*] F4 - Empty\n[*] F5 - Empty\n[*] F6 - Empty\n PAGE - 2 ";
		//VirtualAlloc(entry, sizeof("`4Grabb Beta 1.0\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce"), PAGE_EXECUTE_READWRITE, MEM_FREE);
		VirtualProtectEx(a, entry, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F4 - Snow Particles\n[*] F5 - Fart Particles\n[*] F6 - Aura Particles\nPAGE - 2 [Visuals Menu] "), PAGE_EXECUTE_READWRITE, &OLDPROTECT);

		WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F4 - Snow Particles\n[*] F5 - Fart Particles\n[*] F6 - Aura Particles\nPAGE - 2 [Visuals Menu] ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F4 - Snow Particles\n[*] F5 - Fart Particles\n[*] F6 - Aura Particles\nPAGE - 2 [Visuals Menu] "), NULL);
		BOOL patternInıt = WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F4 - Snow Particles\n[*] F5 - Fart Particles\n[*] F6 - Aura Particles\nPAGE - 2 [Visuals Menu] ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F4 - Snow Particles\n[*] F5 - Fart Particles\n[*] F6 - Aura Particles\nPAGE - 2 [Visuals Menu] "), NULL);
		VirtualProtectEx(a, entry, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0[*] F4 - Snow Particles\n[*] F5 - Fart Particles\n[*] F6 - Aura Particles\nPAGE - 2 [Visuals Menu] "), PAGE_READONLY, &OLDPROTECT);
	}
	if (PAGE_MENU == 3) {

	}
	else {
		if (GetAsyncKeyState(VK_NUMPAD6)) {
			PAGE_MENU++;
		}
	}
	
	if (PAGE_MENU == 1) {

	}
	else {
		if (GetAsyncKeyState(VK_NUMPAD4)) {
			PAGE_MENU--;
		}
	}
	
	//lets relief our cpu for a while or it will die lmao :D
    Sleep(50);
	


}
void ToggleDrawMenu(BYTE* offsets,string hack1) {
	//Internal Draw Menu using simple menu pattern.
	//Pattern Hardcoded By Hirako Shiniji
	//Menu Pattern : 60 34 47 72 61 62 62 20 4D 65 6E 75 20 76 31 2E 34 0D 0A 60 30 46 31 20 2D 20 41 6E 74 69 62 6F 75 6E 63 65 0D 0A 46 32 20 2D 20 4D 6F 64 20 46 6C 79 0D 0A 5B 2A 5D 20 43 72 65 64 69 74 73 0D 0A 5B 2A 5D 20 4D 61 64 65 20 42 79 20 48 69 72 61 6B 6F
	HWND hwnd = FindWindowA(NULL, "");
	LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + 0x3F7148);
	DWORD procID;
	HANDLE OpenProce = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	OpenProce;
	HANDLE a = GetCurrentProcess();
	DWORD oldProtect = 0;
	DWORD OLDPROTECT;

	//VirtualAlloc(entry, sizeof("`4Grabb Beta 1.0\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce"), PAGE_EXECUTE_READWRITE, MEM_FREE);
	VirtualProtectEx(a, entry, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly\n[*] F2 - Antibounce\n[*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji\n [#] Supported by Commander Kaan   "), PAGE_EXECUTE_READWRITE, &OLDPROTECT);

	WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji\n [#] Supported by Commander Kaan  ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4GGrabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji\n [#] Supported by Commander Kaan "), NULL);
	BOOL patternInıt = WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji\n [#] Supported by Commander Kaan  ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji\n [#] Supported by Commander Kaan  "), NULL);






}void DebugMode()
{
	if (!AllocConsole()) {
		// Add some error handling here.
		// You can call GetLastError() to get more info about the error.
		return;
	}

	// std::cout, std::clog, std::cerr, std::cin
	FILE* fDummy;
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	std::cout.clear();
	std::clog.clear();
	std::cerr.clear();
	std::cin.clear();

	// std::wcout, std::wclog, std::wcerr, std::wcin
	HANDLE hConOut = CreateFile(("CONOUT$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE hConIn = CreateFile(("CONIN$"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	SetStdHandle(STD_OUTPUT_HANDLE, hConOut);
	SetStdHandle(STD_ERROR_HANDLE, hConOut);
	SetStdHandle(STD_INPUT_HANDLE, hConIn);
	std::wcout.clear();
	std::wclog.clear();
	std::wcerr.clear();
	std::wcin.clear();
}
bool mfly = false;
bool av = false;

FILE *fDummy;

void abhack()
{
	BYTE avON[] = { 0x90,0x90 };
	BYTE avOFF[] = { 0x75,0x10 };
	if (GetAsyncKeyState(VK_F2)) {

		if (av == true) {


			memSpray(0x2D313A, avON);

			std::cout << "Antibounce > ON" << std::endl;

			av = false;
		}
		else if (av == false) {
			memSpray(0x2D313A, avOFF);
			std::cout << "Antibounce > OFF" << std::endl;


			av = true;
		}

	}

}
bool nv = false;
void snow_mp()
{
	BYTE snON[] = { 0x84 };
	BYTE snOFF[] = { 0x85 };
	if (GetAsyncKeyState(VK_F4)) {

		if (nv == true) {


			memSpray(0xA3D0C, snON);
		
			

			nv = false;
		}
		else if (nv == false) {
			memSpray(0xA3D0C, snOFF);
	
		


			nv = true;
		}

	}

}
bool fr = false;
void fart_mp()
{
	BYTE snON[] = { 0x84 };
	BYTE snOFF[] = { 0x85 };
	if (GetAsyncKeyState(VK_F5)) {

		if (fr == true) {


			memSpray(0x9C324, snON);



			fr = false;
		}
		else if (fr == false) {
			memSpray(0x9C324, snOFF);




			fr = true;
		}

	}

}
bool aru = false;
void aura_mp()
{
	BYTE snsON[] = {0x7A};
	BYTE snsOFF[] = {0x75};
	if (GetAsyncKeyState(VK_F6)) {

		if (aru == true) {


			memSpray(0x9C43F, snsON);
			


			aru = false;
		}
		else if (aru == false) {
			memSpray(0x9C43F, snsOFF);
	



			aru = true;
		}

	}

}
void MemRelocate(string size,long address) {
	HWND hwnd = FindWindowA(NULL, "");
	LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + address);
	DWORD procID;
	HANDLE OpenProce = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
	OpenProce;
	HANDLE a = GetCurrentProcess();
	DWORD oldProtect = 0;
	DWORD OLDPROTECT;


	VirtualProtectEx(a, entry, sizeof(size), PAGE_EXECUTE_READWRITE, &OLDPROTECT);

}
void arhack()
{
	//Autorespawn
	BYTE avON[] = { 0x90};
	BYTE avOFF[] = { 0x80, 0x79, 0x12, 0x00 };
	if (GetAsyncKeyState(VK_F3)) {

		if (av == true) {
			HWND hwnd = FindWindowA(NULL, "");
			LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + 0x3F7148);
			DWORD procID;
			HANDLE OpenProce = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			OpenProce;
			HANDLE a = GetCurrentProcess();
			DWORD oldProtect = 0;
			DWORD OLDPROTECT;
			MemRelocate("/////////////////////////////", 0x2C236A);

			memSpray(0x2C236A, avON);
			VirtualProtectEx(a, entry, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n `7[+] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), PAGE_EXECUTE_READWRITE, &OLDPROTECT);

			WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n `7[+] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), NULL);
			BOOL patternInıt = WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n `7[+] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji  ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n `7[+] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), NULL);

		

			av = false;
		}
		else if (av == false) {
			MemRelocate("/////////////////////////////", 0x2C236A);

			memSpray(0x2C236A, avOFF);
			HWND hwnd = FindWindowA(NULL, "");
			LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + 0x3F7148);
			DWORD procID;
			HANDLE OpenProce = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
			OpenProce;
			HANDLE a = GetCurrentProcess();
			DWORD oldProtect = 0;
			DWORD OLDPROTECT;

			
			VirtualProtectEx(a, entry, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n `0[*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), PAGE_EXECUTE_READWRITE, &OLDPROTECT);

			WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n `0[*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), NULL);
			BOOL patternInıt = WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n `0[*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji  ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n `0[*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), NULL);




			av = true;
		}

	}

}
DWORD WINAPI LoopFunction(LPVOID lpParam)
{
	while (1) {
		
		BYTE drawPattern[] = { 0x60, 0x34, 0x47, 0x72, 0x61, 0x62, 0x62, 0x20, 0x4D, 0x65, 0x6E, 0x75, 0x20, 0x76, 0x31, 0x2E, 0x34, 0x0D, 0x0A, 0x60, 0x30, 0x46, 0x31, 0x20, 0x2D, 0x20, 0x41, 0x6E, 0x74, 0x69, 0x62, 0x6F, 0x75, 0x6E, 0x63, 0x65, 0x0D, 0x0A, 0x46, 0x32, 0x20, 0x2D, 0x20, 0x4D, 0x6F, 0x64, 0x20, 0x46, 0x6C, 0x79, 0x0D, 0x0A, 0x5B, 0x2A, 0x5D, 0x20, 0x43, 0x72, 0x65, 0x64, 0x69, 0x74, 0x73, 0x0D, 0x0A, 0x5B, 0x2A, 0x5D, 0x20, 0x4D, 0x61, 0x64, 0x65, 0x20, 0x42, 0x79, 0x20, 0x48, 0x69, 0x72, 0x61, 0x6B, 0x6F };
		arhack(); //Autorespawn
		abhack(); //Antibounce 
		snow_mp(); //Snow Particles
		fart_mp(); //Fart Particles
		aura_mp(); //Aura Particles
		DrawMenu(drawPattern); //Menu Pattern Renderer
		HWND conwin = ::FindWindow(0,("Growtopia"));
		RECT conrect;
		

	
		
		BYTE btLdrLoadDll[] = { 0x90,0x90 };

		memSpray(0x1C40A5, btLdrLoadDll);
		BYTE mflyON[] = { 0x90,0x90 };
		BYTE mflyOFF[] = { 0x84,0xC0 };
		BYTE avON[] = { 0x90,0x90 };
		BYTE avOFF[] = { 0x75,0x10 };
		//nopping still needs some work on it.
		//nop(4, 0x1C40A5);
	

		if (GetAsyncKeyState(VK_F1)) {

			if (mfly == true) {


				memSpray(0x2D28F5, mflyON);
				
				std::cout << "Mod fly > ON" << std::endl;
				HWND hwnd = FindWindowA(NULL, "");
				LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + 0x3F7148);
				DWORD procID;
				HANDLE OpenProce = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
				OpenProce;
				HANDLE a = GetCurrentProcess();
				DWORD oldProtect = 0;
				DWORD OLDPROTECT;

				//VirtualAlloc(entry, sizeof("`4Grabb Beta 1.0\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce"), PAGE_EXECUTE_READWRITE, MEM_FREE);
				VirtualProtectEx(a, entry, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`7 [+] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), PAGE_EXECUTE_READWRITE, &OLDPROTECT);

				WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`7 [+] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`7 [+] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), NULL);
				BOOL patternInıt = WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`7 [+] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`7 [+] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), NULL);



				//DrawText(wdc, "F1 - Mod Fly ON", -1, &rectx, DT_SINGLELINE | DT_NOCLIP);
				

				mfly = false;
			}
			else if (mfly == false) {
				memSpray(0x2D28F5, mflyOFF);
				std::cout << "Mod fly > OFF" << std::endl;
				HWND hwnd = FindWindowA(NULL, "");
				LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + 0x3F7148);
				DWORD procID;
				HANDLE OpenProce = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
				OpenProce;
				HANDLE a = GetCurrentProcess();
				DWORD oldProtect = 0;
				DWORD OLDPROTECT;

				//VirtualAlloc(entry, sizeof("`4Grabb Beta 1.0\n`0[*] F1 - Mod Fly\n[*] F2 - Antibounce"), PAGE_EXECUTE_READWRITE, MEM_FREE);
				VirtualProtectEx(a, entry, sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), PAGE_EXECUTE_READWRITE, &OLDPROTECT);

				WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), NULL);
				BOOL patternInıt = WriteProcessMemory(a, entry, "fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji ", sizeof("fps: %d - M: %.2f, T: %.2f A: %.2f F: %.2f\n\n `4Grabb Menu Beta 1.6\n`0 [*] F1 - Mod Fly`0\n [*] F2 - Antibounce\n [*] F3 - AutoRespawn\n`0 [-] Made By Hirako Shiniji "), NULL);

			    
				
				mfly = true;
			}
			else if (GetAsyncKeyState(VK_F2)) {

				if (av == true) {


					memSpray(0x2D313A, avON);
					
					std::cout << "Antibounce > ON" << std::endl;

					av = false;
				}
				else if (av == false) {
					memSpray(0x2D313A, avOFF);
					std::cout << "Antibounce > OFF" << std::endl;


					av = true;
				}


			}
		}
	}
	
	Sleep(50);
	return 0;
}
void CreateConsole()
{

	




	

}
void Check(long address ,BYTE*scan) {
	LPVOID entry = (LPVOID)((uintptr_t)GetModuleHandle(NULL) + address);
	HANDLE a = GetCurrentProcess();
	BYTE byte[2];
	ReadProcessMemory(a, entry, byte, sizeof(byte), NULL);
	
	if ((char)scan != (char)byte) {
		std::cout << "Hacks Not Patched!"<< std::endl;

	}
	else {
		std::cout << "Hacks Patched!"  << std::endl;

	}
	
}
#define MST (-7)
#define UTC (0)

#define CCT (+8)
bool debugging = false;
BOOL WINAPI DllMain(HINSTANCE hModule, DWORD dwAttached, LPVOID lpvReserved)
{
	time_t rawtime;
	struct tm * ptm;

	time(&rawtime);

	
	if (dwAttached == DLL_PROCESS_ATTACH) {
		CreateThread(NULL, 0, &LoopFunction ,&abhack, 0, NULL);
		

	
		saveLog();

		//Debug mode is helpful for the dev to interact with exceptions.
		if (debugging == true) {
			DebugMode();
		}
		else {

		}
		
		INPUT ip;
		ip.type = INPUT_KEYBOARD;
		ip.ki.wScan = 0;
		ip.ki.time = 0;
		ip.ki.dwExtraInfo = 0;
		ip.ki.wVk = 0x46 + VK_CONTROL;
		//For key press Flag=0
		ip.ki.dwFlags = 0;
		SendInput(1, &ip, sizeof(INPUT));
		//For key relese Flag = KEYEVENTF_KEYUP
		ip.ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, &ip, sizeof(INPUT));

		INPUT ips;
		ips.type = INPUT_KEYBOARD;
		ips.ki.wScan = 0;
		ips.ki.time = 0;
		ips.ki.dwExtraInfo = 0;
		ips.ki.wVk = VK_CONTROL;
		//For key press Flag=0
		ips.ki.dwFlags = 0;
		SendInput(1, &ips, sizeof(INPUT));
		//For key relese Flag = KEYEVENTF_KEYUP
		ips.ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(1, &ips, sizeof(INPUT));
	    //HelloWorld();
		
		

		
	
		BYTE mflyOFF[] = { 0x84,0xC0 };
		Check(0x2D28F5, mflyOFF);
	
	
	}
	return 1;
}

