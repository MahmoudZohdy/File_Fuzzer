#include "Fuzzer.h"

void ParseArgument(int argc, char* argv[]) {

    return;
}

int main(int argc,char* argv[])
{
	ParseArgument(argc, argv);
	
	Fuzz();

	return 0;
}