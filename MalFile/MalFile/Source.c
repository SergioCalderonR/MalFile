#include <Windows.h>
#include <wchar.h>
#include <Dpapi.h>
#include <stdio.h>

#pragma comment(lib, "Crypt32.lib")

#define BYTESTOREAD 1000

VOID ShowHelp()
{
	fwprintf(stderr, L"\nMalFile 1.0\n"
		L"Copyrigth (C) 2018 Sergio Calderon\n"
		L"Sample file tool to test Controlled Folder Access in Windows 10\n");

	fwprintf(stderr, L"\nUsage: MalFile.exe [Option] [Path]\n"
		L"\n[Option]:\n"
		L"-nf \t Create a new plaintext file.\n"
		L"-ef \t Encrypt a given plaintext file using Cryptography API: Next Generation (CNG)\n"
		L"-df \t Decrypt a given encrypted file using Cryptography API: Next Generation (CNG)\n"
		L"\n[Path]: Path to a file.\n");

	fwprintf(stderr, L"\nExamples:\n"
		L"MalFile.exe -nf C:\\Demo\\NewFile.txt\n"
		L"MalFile.exe -ef C:\\Demo\\NewFile.txt C:\\Demo\\NewEncryptedFile.neu\n"
		L"MalFile.exe -df C:\\Demo\\NewEncryptedFile.neu C:\\Demo\\DecryptedFile.txt\n");

}

VOID ShowError(DWORD errorCode)
{
	//FormatMessageW
	DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
		FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS;
	LPWSTR errorMessage;
	DWORD size = 0;

	if (!FormatMessageW(flags, NULL, errorCode, 0, (LPWSTR)&errorMessage, size, NULL))
	{
		fwprintf(stderr, L"Could not get the format message, error code: %u\n", GetLastError());
		exit(1);
	}

	wprintf(L"\n%s", errorMessage);

	LocalFree(errorMessage);
}

int wmain(int argc, WCHAR * argv[])
{

	if (argc < 2 || argc > 4)
	{
		ShowHelp();
		return 1;
	}


	// Creating a simple file
	if (_wcsicmp(argv[1], L"-nf") == 0)
	{
		HANDLE hNewFile;
		LPCWSTR pPathToNewFile = (LPCWSTR)argv[2];

		hNewFile = CreateFileW(
			pPathToNewFile,
			GENERIC_WRITE | GENERIC_WRITE,
			FILE_SHARE_WRITE,
			NULL, // Gets default security descriptor
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hNewFile != INVALID_HANDLE_VALUE)
		{
			//------------------------------------------------------------------------------
			// First plaintext file
			BYTE *dataToWrite= (BYTE*)L"This is a test file.";
			DWORD nNumberOfBytes = (wcslen((WCHAR*)dataToWrite) + 1) * (sizeof(WCHAR));
			DWORD nNumberOfBytesWritten;

			if (!WriteFile(
				hNewFile,
				dataToWrite,
				nNumberOfBytes,
				&nNumberOfBytesWritten,
				NULL))
			{
				ShowError(GetLastError());
				CloseHandle(hNewFile);
				return 1;
			}

			wprintf(L"\nThe new file, %s, has been created.\n", pPathToNewFile);
			CloseHandle(hNewFile);		

		}
		else
		{
			ShowError(GetLastError());
			return 1;
		}
		
	} // Ending -nf parameter

	// Encrypting an existing file
	else if (_wcsicmp(argv[1], L"-ef") == 0)
	{
		// CreateFile
		HANDLE hSourceFile;
		LPWSTR fileName = argv[2];

		//---------------------------------------------
		// Opening source file to get the data
		hSourceFile = CreateFileW(fileName,
			FILE_READ_DATA,
			FILE_SHARE_READ,
			NULL,
			OPEN_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hSourceFile == INVALID_HANDLE_VALUE)
		{
			ShowError(GetLastError());
			return 1;
		}

		// ReadFile variables
		BYTE dataRead[BYTESTOREAD];
		DWORD bytesRead;

		//--------------------------------------------------
		// Reading data from source file to encrypt
		if (!ReadFile(
			hSourceFile,
			dataRead,
			BYTESTOREAD,
			&bytesRead,
			NULL))
		{
			ShowError(GetLastError());
			CloseHandle(hSourceFile);
			return 1;

		}

		// CryptProtectData variables
		DATA_BLOB DataIn;
		DATA_BLOB DataOut;
		/*BYTE * pDataInput = (BYTE*)L"Hello, funcking world.";
		DWORD cbDataInput = (wcslen((WCHAR*)pDataInput)+1) * (sizeof(WCHAR));*/

		DataIn.pbData = dataRead;
		DataIn.cbData = bytesRead;

		//----------------------------------------------------
		// Encrypting data from source file
		if (CryptProtectData(
			&DataIn,
			L"This is the info you lost. =/",
			NULL,
			NULL,
			NULL,
			0,
			&DataOut))
		{
			wprintf(L"\nEncryption of data from %s was successful. \n", fileName);
		}
		else
		{
			ShowError(GetLastError());
			CloseHandle(hSourceFile);
			return 1;
		}

		// CreateFile
		HANDLE hDestinationFile;
		LPWSTR pDestFileName = argv[3]; // Destination path passed as argument
		DWORD destDesiredAccess = FILE_GENERIC_WRITE | FILE_GENERIC_READ;
		DWORD destShareMode = FILE_SHARE_WRITE;
		DWORD destCreationDisposition = CREATE_ALWAYS;


		//---------------------------------------------------------
		// Creating a new encrypted file, always
		hDestinationFile = CreateFileW(
			pDestFileName,
			destDesiredAccess,
			destShareMode,
			NULL,
			destCreationDisposition,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hDestinationFile == INVALID_HANDLE_VALUE)
		{
			ShowError(GetLastError());
			CloseHandle(hSourceFile);
			return 1;
		}

		// WriteFile variables
		DWORD bytesWritten = 0;

		//--------------------------------------------------
		// Writing encrypted data to the destination file
		if (!WriteFile(
			hDestinationFile,
			DataOut.pbData,
			DataOut.cbData,
			&bytesWritten,
			NULL))
		{
			ShowError(GetLastError());
			CloseHandle(hSourceFile);
			CloseHandle(hDestinationFile);
			return 1;
		}
		else
		{
			wprintf(L"\nEncrypted data has been written to %s \n", pDestFileName);
		}

		CloseHandle(hSourceFile);
		CloseHandle(hDestinationFile);

	}

	// Decrypting an existing encrypted file
	else if (_wcsicmp(argv[1], L"-df") == 0)
	{
		
		HANDLE hExistingFile;
		LPWSTR pExitingFile = argv[2];

		hExistingFile = CreateFileW(
			pExitingFile,
			FILE_READ_DATA,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hExistingFile == INVALID_HANDLE_VALUE)
		{
			ShowError(GetLastError());
			return 1;
		}


		BYTE buffer[BYTESTOREAD];
		DWORD bytRead;

		if (!ReadFile(
			hExistingFile,
			buffer,
			BYTESTOREAD,
			&bytRead,
			NULL))
		{
			ShowError(GetLastError());
			CloseHandle(hExistingFile);
		}

		CloseHandle(hExistingFile);

		// CryptUnprotectData variables
		DATA_BLOB eDataIn;
		DATA_BLOB dDataOut;
		LPWSTR dataDescrip = NULL;
		DWORD dFlags = 0;

		eDataIn.pbData = buffer;
		eDataIn.cbData = bytRead;

		if (CryptUnprotectData(
			&eDataIn,
			NULL,
			NULL,
			NULL,
			NULL,
			0,
			&dDataOut))
		{
			wprintf(L"\nData from %s was decrypted.\n", pExitingFile);

		}
		else
		{
			ShowError(GetLastError());
		}

		HANDLE hFinalFile;
		LPWSTR pRecoveredFile = argv[3];

		hFinalFile = CreateFileW(
			pRecoveredFile,
			FILE_WRITE_DATA,
			FILE_SHARE_WRITE,
			NULL,
			CREATE_ALWAYS,
			FILE_ATTRIBUTE_NORMAL,
			NULL);

		if (hFinalFile == INVALID_HANDLE_VALUE)
		{
			ShowError(GetLastError());
			exit(1);
		}

		DWORD finalBytes;

		if (!WriteFile(
			hFinalFile,
			dDataOut.pbData,
			dDataOut.cbData,
			&finalBytes,
			NULL))
		{
			ShowError(GetLastError());
			CloseHandle(hFinalFile);
			LocalFree(dDataOut.pbData);
			return 1;
		}
		else
		{
			wprintf(L"\nDecrypted data has been written to %s. \n", pRecoveredFile);
			CloseHandle(hFinalFile);
			LocalFree(dDataOut.pbData);
		}

	}

	else
	{
		ShowHelp();
		return 1;
	}

	
	return 0;
}