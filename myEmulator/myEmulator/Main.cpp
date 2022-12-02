#include <iostream>
#include <string>
#include "Emulator.h"
#include "EmulatorException.h"

int main()
{
	std::string instruction = "";

	while (true)
	{
		std::cout << ">> ";
		std::getline(std::cin, instruction);

		try
		{
			Emulator::ExecuteInstruction(instruction);
		}
		catch (const EmulatorException& e)
		{
			std::cerr << e.what() << std::endl;
		}
	}

	return 0;
}
