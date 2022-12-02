#include "Emulator.h"

std::vector<byte> Emulator::memoryVec(MEMORY_SIZE);
std::unordered_map<std::string, word> Emulator::regs = {{"ax", 0}, {"bx", 0}, {"cx", 0}, {"dx", 0},
														{"si", 0}, {"di", 0}, {"ds", 0}, {"ss", 0},
														{"sp", 0}, {"bp", 0}, {"cs", 0}, {"es", 0} };
std::unordered_map<std::string, InstructionHandler> Emulator::instructions = { {"mov", movHandler},
										{"lea", leaHandler}, {"add", addHandler}, {"sub", subHandler},
										{"mul", mulHandler}, {"div", divHandler}, {"inc", incHandler},
										{"dec", decHandler}, {"print", printHandler}};

void Emulator::ExecuteInstruction(const std::string& unprocessedInstruction)
{
	Instruction processedInstruction = Parser::ProcessInstruction(unprocessedInstruction);

	if (instructions.count(processedInstruction.opcode) != 0)
		instructions[processedInstruction.opcode](processedInstruction.operands);
	else
		throw InvalidOpcode(processedInstruction.opcode);
}

word Emulator::GetRegisterValue(const std::string& reg)
{
	const byte BITS_IN_BYTE = 8;
	std::string regAccess = reg;

	if (reg.size() == 2 && reg[1] == 'l' || reg[1] == 'h')
		regAccess[1] = 'x';

	if (regs.count(regAccess) != 0)
	{
		word regValue = regs[regAccess];

		if (regAccess == reg)
			return regValue;

		if (reg[1] == 'l')
			return regValue & 0x00ff; // 0x14fd & 0xff  => 0x00fd

		if (reg[1] == 'h')
			return regValue >> BITS_IN_BYTE; // 0x14fd => 0x0014
	}

	throw InvalidRegisterAccess(reg);
}

void Emulator::SetRegisterValue(const std::string& reg, const word value)
{
	const byte BITS_IN_BYTE = 8;
	std::string regAccess = reg;

	if (reg.size() == 2 && (reg[1] == 'l' || reg[1] == 'h'))
		regAccess[1] = 'x';

	if (regs.count(regAccess) != 0)
	{
		if (regAccess == reg)
		{
			regs[regAccess] = value;
			return;
		}

		if (reg[1] == 'l')
		{
			if (value > 0xff)
				throw InappropriateSize("the value must be one byte max");

			regs[regAccess] = (regs[regAccess] & 0xff00) | value; // 0x14fd => 0x1400 | 0x0012 = > 0x1412
			
			return;
		}

		if (reg[1] == 'h')
		{
			if (value > 0xff)
				throw InappropriateSize("the value must be one byte max");

			regs[regAccess] = (regs[regAccess] & 0x00ff) | (value << BITS_IN_BYTE); // 0x14fd => 0x00fd | (0x0012 << 8 => 0x1200) => 0x12fd

			return;
		}
	}

	throw InvalidRegisterAccess(reg);
}

void Emulator::movHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(2, operands.size());

	if (Helper::isImmediate(operands[DST]))
		throw InvalidOperand("First operand (" + operands[DST] + ") cannot be a immediate.");

	if (Helper::isMemory(operands[DST]) && Helper::isMemory(operands[SRC]))
		throw MemoryAccessViolation("can't access the memory twice at the same time.");

	if (Helper::isRegister(operands[DST]) && Helper::isRegister(operands[SRC]))
		SetRegisterValue(operands[DST], GetRegisterValue(operands[SRC]));

	if (Helper::isRegister(operands[DST]) && Helper::isImmediate(operands[SRC]))
		SetRegisterValue(operands[DST], std::stoi(operands[SRC]));
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

void Emulator::printHandler(const std::vector<std::string>& operands)
{
	if (Helper::isRegister(operands[0]))
		std::cout << GetRegisterValue(operands[0]) << std::endl;
}
