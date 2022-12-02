#include "Emulator.h"

std::vector<byte> Emulator::memoryVec(MEMORY_SIZE);
std::unordered_map<std::string, word> Emulator::regs = {{"ax", 0}, {"bx", 0}, {"cx", 0}, {"dx", 0},
														{"si", 0}, {"di", 0}, {"ds", 0}, {"ss", 0},
														{"sp", 0}, {"bp", 0}, {"cs", 0}, {"es", 0} };
std::unordered_map<std::string, InstructionHandler> Emulator::instructions = { {"mov", movHandler},
										{"lea", leaHandler}, {"add", addHandler}, {"sub", subHandler},
										{"mul", mulHandler}, {"div", divHandler}, {"inc", incHandler},
										{"dec", decHandler}};

void Emulator::ExecuteInstruction(const std::string& unprocessedInstruction)
{
	Instruction processedInstruction = Parser::ProcessInstruction(unprocessedInstruction);

	if (instructions.count(processedInstruction.opcode) != 0)
		instructions[processedInstruction.opcode](processedInstruction.operands);
	else
		throw InvalidOpcode(processedInstruction.opcode);
}

void Emulator::movHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(2, operands.size());

	if (Helper::isImmediate(operands[0]))
		throw InvalidOperand("First operand (" + operands[0] + ") cannot be a number.");

	if (Helper::isMemory(operands[0]) && Helper::isMemory(operands[1]))
		throw MemoryAccessVaiolation("can't access the memory twice at the same time.");

	if (Helper::isMemory(operands[0]) && !Helper::isMemoryAllowedRegister(operands[0].substr(1, operands[0].size()-1)))
		throw MemoryAccessVaiolation("Accessing the memory requires using specific registers.");
}

void Emulator::leaHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(2, operands.size());
}

void Emulator::addHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(2, operands.size());
}

void Emulator::subHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(2, operands.size());
}

void Emulator::mulHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(1, operands.size());
}

void Emulator::divHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(1, operands.size());
}

void Emulator::incHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(1, operands.size());
}

void Emulator::decHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(1, operands.size());
}
