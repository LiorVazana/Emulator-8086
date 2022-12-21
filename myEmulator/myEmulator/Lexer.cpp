#include "Lexer.h"


Instruction Lexer::processInstruction(std::string instruction)
{
	Helper::trim(instruction);

	size_t firstSpaceIndex = instruction.find_first_of(" \t");
	std::string opcode = instruction.substr(0, firstSpaceIndex);

	std::stringstream operandsStream(instruction.substr(firstSpaceIndex + 1));
	std::vector<std::string> operands;
	std::string operand;

	while (std::getline(operandsStream, operand, ','))
	{
		Helper::trim(operand);
		operands.push_back(operand);
	}

	return Instruction{ opcode, operands };
}
