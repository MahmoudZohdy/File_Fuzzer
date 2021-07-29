#include "Fuzzer.h"

void ParseArgument(int argc, char* argv[]) {
	
	CHAR CommandLineArgument[2][10] = { "-x","-e" };
	int index = 0;
	for (int i = 0; i < argc; i++) {
		if (strcmp(argv[i], CommandLineArgument[index]) == 0)
		{
			if (index == 0) {
				ExePath = argv[i + 1];
				index++;
			}
			else if (index == 1) {
				FileExtension = argv[i + 1];
				index++;
			}
		}
	}
    return;
}

int main(int argc,char* argv[])
{
	if(argc<2){
		printf("Usage: File_Fuzzer.exe -e <Executable Path> -x <File Extension>");
		return 0;
	}
	ParseArgument(argc, argv);
	
	Fuzz();

	return 0;
}