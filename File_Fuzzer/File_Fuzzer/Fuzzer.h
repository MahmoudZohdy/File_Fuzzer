#pragma once

#pragma warning(disable : 4996)
#pragma comment (lib, "Dbghelp.lib")

#include <iostream>
#include <Windows.h>
#include <string>
#include <time.h>
#include <filesystem>
#include <TlHelp32.h>
#include <processsnapshot.h>
#include <DbgHelp.h>
#include <sstream>
using namespace std;
namespace fs = std::filesystem;

struct FUZZ_INFO {
	string OriginalFile;
	DWORD DebuggePID;
	HANDLE DebugeHandle;
	HANDLE DebuggeThreadHandle;
};

string SamplesDirectory = ".\\examples\\";
string ExePath =  "C:\\Windows\\System32\\notepad.exe";
string FileExtension = ".txt";
BOOL CreateCrashDump = FALSE;
string TestCases[4] = { "%s%n%s%n%s%n", "\xff", "\x00", "A" };
DWORD NumberOfFilesInTheSampleDirectory = 0;

DWORD MutateFile(FUZZ_INFO* FuzzInfo);
BOOL ChooseTestFile(FUZZ_INFO* FuzzInfo);
DWORD StartExecutableAsSuspended(FUZZ_INFO* FuzzInfo);
DWORD WINAPI StartDebugging(LPVOID FuzzInfo);
void  HandleAccessViolation(FUZZ_INFO* FuzzInfo);
void GenerateCrashDump(FUZZ_INFO* FuzzInfo);
void ResumeProcess(FUZZ_INFO* FuzzInfo);
static BOOL CALLBACK MinidumpCallback(__in PVOID Param, __in const PMINIDUMP_CALLBACK_INPUT Input, __inout PMINIDUMP_CALLBACK_OUTPUT Output);
void DumpProcess(FUZZ_INFO* FuzzInfo);
void MoveDumpAndTestCaseToNewDirectory(FUZZ_INFO* FuzzInfo);
void GetNumberOfFilesInSamplesDirectory();

void Fuzz() {

	GetNumberOfFilesInSamplesDirectory();
	DWORD TestCount = 1;
	while (TRUE) {
		
		printf("Starting the Test Case Number %ld\n",TestCount);
		TestCount++;

		FUZZ_INFO* FuzzInfo = new FUZZ_INFO;
		
		DWORD bResult;

		bResult = ChooseTestFile(FuzzInfo);
		if (!bResult) {
			printf("Failed to Choose File\n");
			Sleep(1000);
			continue;
		}

		bResult = MutateFile(FuzzInfo);
		if (bResult == -1) {
			printf("Failed to Mutate the File Data\n");
			Sleep(1000);
			continue;
		}

		bResult = StartExecutableAsSuspended(FuzzInfo);
		if (bResult == -1) {
			printf("Failed to Start Executable\n");
			Sleep(1000);
			continue;
		}

		CreateThread(NULL, 0, StartDebugging, FuzzInfo, 0, NULL);

		Sleep(5000);
	}

	return;
}

void GetNumberOfFilesInSamplesDirectory() {
	for (const auto& entry : fs::directory_iterator(SamplesDirectory)) {
		NumberOfFilesInTheSampleDirectory++;
	}
}

BOOL ChooseTestFile(FUZZ_INFO* FuzzInfo) {

	srand(time(NULL));
	int index;	

	index = rand() % NumberOfFilesInTheSampleDirectory + 1;
	int count = 0;

	//pick random file from the directory
	for (const auto& entry : fs::directory_iterator(SamplesDirectory)) {

		wstring TempPath(entry.path().c_str());
		std::string FilePath(TempPath.begin(), TempPath.end());

		int found = FilePath.find(FileExtension);
		if (found != std::string::npos && found == FilePath.size()-FileExtension.size())
			count++;

		if (count == index) {
			FuzzInfo->OriginalFile = FilePath;
			break;
		}
	}
	return !(FuzzInfo->OriginalFile.empty());
}

DWORD MutateFile(FUZZ_INFO* FuzzInfo) {
	srand(time(NULL));

	HANDLE hFileOrig, hFileMutate;
	BOOL bResult = FALSE;
	DWORD cbRead = 0, cbWritten = 0;

	hFileOrig = CreateFileA(FuzzInfo->OriginalFile.c_str(), GENERIC_WRITE | GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileOrig == INVALID_HANDLE_VALUE) {
		printf("Failed To open File Error Code is 0x%x\n", GetLastError());
		return -1;
	}

	int FileSize = GetFileSize(hFileOrig, 0);
	if (FileSize == INVALID_FILE_SIZE) {
		printf("Failed To get File size Error Code is 0x%x\n", GetLastError());
		return -1;
	}

	BYTE* FileContents = new BYTE[FileSize];
	ZeroMemory(FileContents, FileSize);

	bResult = ReadFile(hFileOrig, FileContents, FileSize, &cbRead, NULL);
	if (bResult == FALSE) {
		printf("Failed To Read File Data Error Code is 0x%x\n", GetLastError());
		return -1;
	}

	int TestCaseIndex = rand() % 4;
	string UsedTestCase = TestCases[TestCaseIndex];

	int NumberOfTimesToRepeteTheTestCase = rand() % 1000 + 1;
	string RepetedTestCase = "";
	for (int i = 0; i < NumberOfTimesToRepeteTheTestCase; i++) {
		RepetedTestCase += UsedTestCase;
	}

	int RandomoffsetInTheFile;
	RandomoffsetInTheFile = rand() % FileSize + 1;

	BYTE* NewFileContents = new BYTE[FileSize + RepetedTestCase.size()];
	RtlCopyMemory(NewFileContents, FileContents, RandomoffsetInTheFile);


	RtlCopyMemory(NewFileContents + RandomoffsetInTheFile, RepetedTestCase.c_str(), RepetedTestCase.size());

	RtlCopyMemory(NewFileContents + RandomoffsetInTheFile + RepetedTestCase.size(), FileContents + RandomoffsetInTheFile, FileSize - RandomoffsetInTheFile);

	CloseHandle(hFileOrig);

	hFileOrig = CreateFileA(FuzzInfo->OriginalFile.c_str(), GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFileOrig == INVALID_HANDLE_VALUE) {
		printf("Failed To Create File For Mutated Data Error Code is 0x%x\n", GetLastError());
		return -1;
	}

	bResult = WriteFile(hFileOrig, NewFileContents, FileSize + RepetedTestCase.size(), &cbWritten, NULL);
	if (bResult == FALSE) {
		printf("Failed To Write File Mutated Data Error Code is 0x%x\n", GetLastError());
		return -1;
	}

	CloseHandle(hFileOrig);

	return 0;
}

DWORD StartExecutableAsSuspended(FUZZ_INFO* FuzzInfo) {
	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };

	si.cb = sizeof(si);

	char CommandLine[MAX_PATH];
	strcpy(CommandLine, FuzzInfo->OriginalFile.c_str());

	if (CreateProcessA(ExePath.c_str(), CommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi) == FALSE) {
		printf("Failed to Create Process Error code is 0x%x\n", GetLastError());
		return -1;
	}
	FuzzInfo->DebuggePID = pi.dwProcessId;
	FuzzInfo->DebugeHandle = pi.hProcess;
	FuzzInfo->DebuggeThreadHandle = pi.hThread;
	return 0;
}

DWORD WINAPI StartDebugging(LPVOID Parametar) {


	FUZZ_INFO* FuzzInfo = (FUZZ_INFO*)Parametar;
	DWORD PID = FuzzInfo->DebuggePID;

	BOOL status = DebugActiveProcess(PID);
	if (!status) {
		printf("Failed to Attach to Process Error Code 0x%x \n", GetLastError());
		TerminateProcess(FuzzInfo->DebugeHandle, 0);
		return 0;
	}

	ResumeProcess(FuzzInfo);

	DWORD Start = GetTickCount();

	DWORD dwContinueStatus = DBG_CONTINUE;
	DEBUG_EVENT DebugEv;
	CONTEXT Context;
	HANDLE hThread;
	DWORD count;
	BOOL bResult;
	for (;;)
	{
		DWORD WaitTime = 3000;
		WaitForDebugEvent(&DebugEv, WaitTime);

		DWORD End = GetTickCount();
		DWORD NumberOfSecondSinceTestStartExecution = End - Start;
		DWORD NumberOfSecondToRun = 15000;

		if (GetLastError() != WAIT_TIMEOUT && !DebugEv.u.Exception.dwFirstChance && DebugEv.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {

			HandleAccessViolation(FuzzInfo);
			break;
		}
		else if (NumberOfSecondSinceTestStartExecution > NumberOfSecondToRun) {
			
			break;
		}
		ContinueDebugEvent(DebugEv.dwProcessId, DebugEv.dwThreadId, dwContinueStatus);
	}

	bResult = DebugActiveProcessStop(PID);
	if (!bResult) {
		printf("Faile to Deattach From Process Error Code is 0x%x\n", GetLastError());
	}
	bResult = TerminateProcess(FuzzInfo->DebugeHandle, 0);
	if (!bResult) {
		printf("Failed to Termentate Test Process %x\n", GetLastError());
	}
	CloseHandle(FuzzInfo->DebugeHandle);

	delete Parametar;

	//TerminateThread(GetCurrentThread(), 0);

	return 0;
}


void ResumeProcess(FUZZ_INFO* FuzzInfo) {
	ResumeThread(FuzzInfo->DebuggeThreadHandle);
}

void HandleAccessViolation(FUZZ_INFO* FuzzInfo) {

	GenerateCrashDump(FuzzInfo);
	MoveDumpAndTestCaseToNewDirectory(FuzzInfo);
}

void GenerateCrashDump(FUZZ_INFO* FuzzInfo) {
	DumpProcess(FuzzInfo);
}

void MoveDumpAndTestCaseToNewDirectory(FUZZ_INFO* FuzzInfo) {

	SYSTEMTIME CurrentTime;
	GetSystemTime(&CurrentTime);
	string DirectoryName = FuzzInfo->OriginalFile + "_" + to_string(CurrentTime.wDayOfWeek) + "_" + to_string(CurrentTime.wDay) + "_"
		+ to_string(CurrentTime.wHour) + "_" + to_string(CurrentTime.wMinute) + "_" + to_string(CurrentTime.wSecond);	
	
	DWORD attributes = GetFileAttributesA(DirectoryName.c_str());

	if (attributes == INVALID_FILE_ATTRIBUTES) {
		BOOL status = CreateDirectoryA(DirectoryName.c_str(), NULL);

		if (!status) {
			printf("Failed to Create Directory For Test Case and Dump 0x%x\n", GetLastError());
			return;
		}
	}

	vector <string> tokens;
	stringstream check1(FuzzInfo->OriginalFile);
	string intermediate;

	while (getline(check1, intermediate, '\\'))
	{
		tokens.push_back(intermediate);
	}

	string NewFileName = DirectoryName + "\\" + tokens[tokens.size() - 1];
	string NewDumpName = DirectoryName + "\\" + tokens[tokens.size() - 1] + ".DUMP";
	string OldDumpPath = FuzzInfo->OriginalFile + ".DUMP";

	//copt the test case to be used in future fuzz
	CopyFileA(FuzzInfo->OriginalFile.c_str(), NewFileName.c_str(), FALSE);
	//move the dump
	MoveFileA(OldDumpPath.c_str(), NewDumpName.c_str());
	return;
}

void DumpProcess(FUZZ_INFO* FuzzInfo)
{
	DWORD rc;
	HRESULT hr;
	DWORD ProcessId;
	HANDLE ProcessHandle;
	HPSS SnapshotHandle;

	HANDLE FileHandle;
	DWORD DumpType;
	MINIDUMP_CALLBACK_INFORMATION CallbackInfo;

	static const DWORD CaptureFlags = PSS_CAPTURE_VA_CLONE
		| PSS_CAPTURE_VA_SPACE
		| PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION
		| PSS_CAPTURE_HANDLE_TRACE
		| PSS_CAPTURE_HANDLES
		| PSS_CAPTURE_HANDLE_BASIC_INFORMATION
		| PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION
		| PSS_CAPTURE_HANDLE_NAME_INFORMATION
		| PSS_CAPTURE_THREADS
		| PSS_CAPTURE_THREAD_CONTEXT
		| PSS_CREATE_MEASURE_PERFORMANCE;


	ProcessId = FuzzInfo->DebuggePID;

	ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS,
		FALSE,
		ProcessId);

	string DumpFileName = FuzzInfo->OriginalFile + ".DUMP";

	FileHandle = CreateFileA(DumpFileName.c_str(),
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		0,
		NULL);

	if (FileHandle == INVALID_HANDLE_VALUE) {
		printf("CreateFile failed: Win32 error 0x%x.\n", GetLastError());
		return;
	}

	rc = PssCaptureSnapshot(ProcessHandle,
		(PSS_CAPTURE_FLAGS)CaptureFlags,
		CONTEXT_ALL,
		&SnapshotHandle);

	if (rc != ERROR_SUCCESS) {
		printf("PssCaptureSnapshot failed: Win32 error 0x%x.\n",GetLastError());
		return;
	}

	printf("Snapshot captured.\n");

	ZeroMemory(&CallbackInfo, sizeof(MINIDUMP_CALLBACK_INFORMATION));
	CallbackInfo.CallbackRoutine = MinidumpCallback;
	CallbackInfo.CallbackParam = NULL;


	DumpType = (DWORD)MiniDumpWithDataSegs | MiniDumpWithProcessThreadData | MiniDumpWithHandleData
		| MiniDumpWithPrivateReadWriteMemory | MiniDumpWithUnloadedModules | MiniDumpWithPrivateWriteCopyMemory
		| MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo | MiniDumpWithTokenInformation;

	rc = MiniDumpWriteDump((HANDLE)SnapshotHandle,
		ProcessId,
		FileHandle,
		(MINIDUMP_TYPE)DumpType,
		NULL,
		NULL,
		&CallbackInfo);

	if (!rc) {
		hr = (HRESULT)GetLastError();
		wprintf(L"MiniDumpWriteDump failed: HRESULT %08X.\n", hr);
		return;
	}

	wprintf(L"Snapshot dumped.\n");

	PssFreeSnapshot(GetCurrentProcess(), SnapshotHandle);

	CloseHandle(FileHandle);
	return;
}

static BOOL CALLBACK MinidumpCallback(__in PVOID Param, __in const PMINIDUMP_CALLBACK_INPUT Input, __inout PMINIDUMP_CALLBACK_OUTPUT Output) {
	UNREFERENCED_PARAMETER(Param);

	switch (Input->CallbackType) {

	case IsProcessSnapshotCallback:
		Output->Status = S_FALSE;
		return TRUE;

	case CancelCallback:
		Output->Cancel = FALSE;
		Output->CheckCancel = FALSE;
		return TRUE;

	case ReadMemoryFailureCallback:
		Output->Status = S_OK;
		return TRUE;

	default:
		return TRUE;
	}
}

