#include <Windows.h>
#include <conio.h>
#include <cstdio>

int main()
{
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)GetModuleHandleA("ntdll.dll");
	if (!pDosHeader)
	{
		printf("GetModuleHandleA failed with error = 0x%08x\n", GetLastError());
		_getch();
	}

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Incorrect e_magic == 0x%02X\n", pDosHeader->e_magic);
		_getch();
	}

	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((LPBYTE)pDosHeader + pDosHeader->e_lfanew);

	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
	{
		printf("Incorrect NtHeader Signature == 0x%08X\n", pNtHeader->Signature);
		_getch();
	}

	IMAGE_OPTIONAL_HEADER OptionalHeader = (IMAGE_OPTIONAL_HEADER)pNtHeader->OptionalHeader;
	IMAGE_DATA_DIRECTORY ExportsDataDir = (IMAGE_DATA_DIRECTORY)OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	PIMAGE_EXPORT_DIRECTORY pExportsDataDir = (PIMAGE_EXPORT_DIRECTORY)(ExportsDataDir.VirtualAddress + (PBYTE)pDosHeader);
	if (!pExportsDataDir)
	{
		printf("Cannot find exports data directory\n");
		_getch();
	}

	PDWORD pdwAddressOfNames = (PDWORD)(pExportsDataDir->AddressOfNames + (PBYTE)pDosHeader);
	PWORD pwAddressOfNameOrdinals = (PWORD)(pExportsDataDir->AddressOfNameOrdinals + (PBYTE)pDosHeader);
	PDWORD pdwAddressOfFunctions = (PDWORD)(pExportsDataDir->AddressOfFunctions + (PBYTE)pDosHeader);

	ULONG sig = 0xB8D18B4C;

	for (DWORD i = 0; i < pExportsDataDir->NumberOfFunctions; i++)
	{
		PCHAR pcName = (PCHAR)pDosHeader + pdwAddressOfNames[i];
		PULONG lpAddress = (PULONG)((LPBYTE)pDosHeader + pdwAddressOfFunctions[pwAddressOfNameOrdinals[i]]);

		if (IsBadReadPtr(lpAddress, 4))
			break;

		if (*(ULONG*)lpAddress == (ULONG)sig)
		{
			DWORD syscallId = *(++lpAddress);
			printf("0x%04X\t%s\n", syscallId, pcName);
		}
	}

	_getch();
	return 0;
}