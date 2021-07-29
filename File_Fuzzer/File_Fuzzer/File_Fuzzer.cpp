#include "Fuzzer.h"

//BOOL CreateDump = FALSE;	-c 
//string ExePath = "C:\\Windows\\System32\\notepad.exe";	-e
//string FileExtension = ".txt";	-t

void ParseArgument(int argc, char* argv[]) {

    return;
}

int main(int argc,char* argv[])
{
	ParseArgument(argc, argv);
	
	Fuzz();


	/*FUZZ_INFO* FuzzInfo = new FUZZ_INFO;

	//FuzzInfo->DebuggePID = atoi(argv[1]);
	//FuzzInfo->DebugeHandle = OpenProcess(PROCESS_ALL_ACCESS, NULL, FuzzInfo->DebuggePID);
	FuzzInfo->OriginalFile = ".\\bb.txt";
	SYSTEMTIME CurrentTime;
	GetSystemTime(&CurrentTime);
	string DirectoryName = FuzzInfo->OriginalFile +"_"+ to_string(CurrentTime.wDayOfWeek) + "_" + to_string(CurrentTime.wDay) + "_" 
		+ to_string(CurrentTime.wHour) + "_" + to_string(CurrentTime.wMinute) + "_" + to_string(CurrentTime.wSecond);
	cout << DirectoryName << endl;
	CrashDump(FuzzInfo);*/

	return 0;
}