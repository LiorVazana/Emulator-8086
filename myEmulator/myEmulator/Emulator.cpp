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

	throw InvalidArgument(reg);
}

void Emulator::SetRegisterValue(const std::string& reg, const word value)
{
	
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

	throw InvalidArgument(reg);
}

byte Emulator::GetValueFromMemoryAddr(const dword address)
{
	if (address >= MEMORY_SIZE)
		throw MemoryAccessViolation("Address not valid.");

	return memoryVec[address];
}

byte Emulator::GetValueFromMemoryAccess(const std::string& memory)
{
	std::string memoryAccess = Helper::getMemoryAccess(memory);

	dword address = 0;

	if (Helper::isMemoryAllowedRegister(memoryAccess))
		address = GetRegisterValue(memoryAccess);
	else
		address = std::stoi(memoryAccess);

	return GetValueFromMemoryAddr(address);
}

void Emulator::SetValueInMemoryAddr(const dword address, const byte value)
{
	if (address >= MEMORY_SIZE)
		throw MemoryAccessViolation("Address not valid.");

	memoryVec[address] = value;
}

void Emulator::SetValueInMemoryAccess(const std::string& memory, const byte value)
{
	std::string memoryAccess = Helper::getMemoryAccess(memory);

	dword address = 0;

	if (Helper::isMemoryAllowedRegister(memoryAccess))
		address = GetRegisterValue(memoryAccess);
	else
		address = std::stoi(memoryAccess);

	SetValueInMemoryAddr(address, value);
}

void Emulator::movHandler(const std::vector<std::string>& operands)
{
	Helper::validateNumOfOperands(2, operands.size());

	if (Helper::isImmediate(operands[DST]))
		throw InvalidOperand("First operand '" + operands[DST] + "' cannot be a immediate.");

	if (Helper::isMemory(operands[DST]) && Helper::isMemory(operands[SRC]))
		throw MemoryAccessViolation("can't access the memory twice at the same time.");

	if (Helper::isRegister(operands[DST]) && Helper::isRegister(operands[SRC]))
		SetRegisterValue(operands[DST], GetRegisterValue(operands[SRC]));

	if (Helper::isRegister(operands[DST]) && Helper::isImmediate(operands[SRC]))
		SetRegisterValue(operands[DST], std::stoi(operands[SRC]));

	if (Helper::isRegister(operands[DST]) && Helper::isMemory(operands[SRC]))
	{
		std::string memoryAccess = Helper::getMemoryAccess(operands[SRC]);

		dword address = 0;

		if (Helper::isMemoryAllowedRegister(memoryAccess))
			address = GetRegisterValue(memoryAccess);
		else
			address = std::stoi(memoryAccess);

		if (operands[DST][1] == 'l' || operands[DST][1] == 'h')
		{
			SetRegisterValue(operands[DST], GetValueFromMemoryAddr(address));
		}
		else
		{
			word value = GetValueFromMemoryAddr(address);
			value |= (static_cast<word>(GetValueFromMemoryAddr(address + 1)) << BITS_IN_BYTE);//שנייה

			SetRegisterValue(operands[DST], value);
		}
	}
	if (Helper::isMemory(operands[DST]) && Helper::isRegister(operands[SRC]))
	{
		std::string memoryAccess = Helper::getMemoryAccess(operands[DST]);

		dword address = 0;

		if (Helper::isMemoryAllowedRegister(memoryAccess))
			address = GetRegisterValue(memoryAccess);
		else
			address = std::stoi(memoryAccess);

		if (operands[SRC][1] == 'l' || operands[SRC][1] == 'h')
		{
			SetValueInMemoryAddr(address, GetRegisterValue(operands[SRC]));
		}
		else
		{
			word value = GetRegisterValue(operands[SRC]);
			SetValueInMemoryAddr(address, value & 0x00ff);
			SetValueInMemoryAddr(address + 1, value >> BITS_IN_BYTE);
		}
	}

	if (Helper::isMemory(operands[DST]) && Helper::isImmediate(operands[SRC]))
	{
		std::string memoryAccess = Helper::getMemoryAccess(operands[DST]);

		dword address = 0;

		if (Helper::isMemoryAllowedRegister(memoryAccess))
			address = GetRegisterValue(memoryAccess);
		else
			address = std::stoi(memoryAccess);

		word value = std::stoi(operands[SRC]);
		SetValueInMemoryAddr(address, value & 0x00ff);
		SetValueInMemoryAddr(address + 1, value >> BITS_IN_BYTE);
	}
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

	else if (Helper::isImmediate(operands[0]))
		std::cout << operands[0] << std::endl;

	else if (Helper::isMemory(operands[0]))
		std::cout << static_cast<word>(GetValueFromMemoryAccess(operands[0])) << std::endl;

	else
		throw InvalidArgument("print must get an immediate number, memory address or register.");
}
