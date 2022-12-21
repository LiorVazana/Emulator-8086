#include <iostream>
#include <string>
#include <fstream>
#include "Emulator.h"
#include "EmulatorException.h"

int main(int argc, char* argv[])
{
	std::string instruction = "";
	std::ifstream myFile;
	bool isFile = false;
	bool status = true;

	if (argc == 2)
	{
		isFile = true;
		myFile.open(argv[1]);
	}

	while (status)
	{
		if (!isFile)
		{
			std::cout << ">> ";
			std::getline(std::cin, instruction);
		}
		else
		{
			std::getline(myFile, instruction);
			status = myFile.good();

			if (!status)
				instruction = "run";
		}
		try
		{
			Helper::trim(instruction);

			if (instruction == "run")
				Emulator::executeInstructions();
			else
				Emulator::pushInstruction(instruction);
		}
		catch (const EmulatorException& e)
		{
			std::cerr << e.what() << std::endl;
		}
	}

	return 0;
}
