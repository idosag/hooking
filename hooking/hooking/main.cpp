#include <windows.h>
#include <string.h>
#include <stdio.h>

void HookFunction(char* funcName, LPDWORD function);
LPDWORD FoundIAT(char* funcName);

int WINAPI HookMessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType);

BOOL APIENTRY DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
	if (dwReason == DLL_PROCESS_ATTACH)
	{
		MessageBox(NULL, "Injeted with success!", "Hello", NULL);
		HookFunction("MessageBoxA", (LPDWORD)&HookMessageBoxA);
	}
	return TRUE;
}

void HookFunction(char* funcName, LPDWORD function)
{
	LPDWORD pOldFunction = FoundIAT(funcName);

	DWORD accessProtectionValue, accessProtec;

	int vProtect = VirtualProtect(pOldFunction, sizeof(LPDWORD), PAGE_EXECUTE_READWRITE, &accessProtectionValue);

	*pOldFunction = (DWORD)function;

	vProtect = VirtualProtect(pOldFunction, sizeof(LPDWORD), accessProtectionValue, &accessProtec);
}

int WINAPI HookMessageBoxA(HWND hWnd, LPCTSTR lpText, LPCTSTR lpCaption, UINT uType)
{
	return MessageBoxA(hWnd, "Hello", "DLL answering here!", uType);
}

LPDWORD FoundIAT(char* funcName)
{
	DWORD test = 0;

	LPVOID pMapping = GetModuleHandle(NULL);

	if (pMapping == NULL)

		exit(-1);

	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)pMapping;

	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)

		exit(-1);

	PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((char*)DosHeader + DosHeader->e_lfanew);

	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)

		exit(-1);

	PIMAGE_DATA_DIRECTORY DataDirectory = &NtHeaders->OptionalHeader.DataDirectory[1];

	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((char*)DosHeader + DataDirectory->VirtualAddress);

	PIMAGE_THUNK_DATA32 OriginalFirstThunk = (PIMAGE_THUNK_DATA32)((char*)DosHeader + ImportDescriptor->OriginalFirstThunk);

	while (OriginalFirstThunk != 0)
	{
		DWORD name = (DWORD)((char*)pMapping + ImportDescriptor->Name);

		OriginalFirstThunk = (PIMAGE_THUNK_DATA32)((char*)DosHeader + ImportDescriptor->OriginalFirstThunk);

		PIMAGE_THUNK_DATA32 FirstThunk = (PIMAGE_THUNK_DATA32)((char*)DosHeader + ImportDescriptor->FirstThunk);

		while (OriginalFirstThunk->u1.AddressOfData != 0)
		{
			PIMAGE_IMPORT_BY_NAME NameImg = (PIMAGE_IMPORT_BY_NAME)((char*)DosHeader + (DWORD)OriginalFirstThunk->u1.AddressOfData);

			test = (DWORD)OriginalFirstThunk->u1.Function & (DWORD)IMAGE_ORDINAL_FLAG32;

			if (test == 0)
			{
				if (strcmp(funcName, (const char*)NameImg->Name) == 0)
				{
					MessageBox(NULL, NameImg->Name, "", NULL);
					return (LPDWORD)&(FirstThunk->u1.Function);
				}
			}
			OriginalFirstThunk++;
			FirstThunk++;
		}
		ImportDescriptor++;
	}
	return 0;
}