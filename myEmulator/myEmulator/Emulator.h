#pragma once
#include <vector>
#include <unordered_map>
#include "Instruction.h"
#include "Parser.h"
#include "InvalidOpcode.h"
#include "InvalidOperand.h"
#include "MemoryAccessVaiolation.h"

// use this typedef in the memory vector;
typedef unsigned char byte;
typedef unsigned short word;

typedef void (*InstructionHandler) (const std::vector<std::string>&);

class Emulator
{
public:
	static void ExecuteInstruction(const std::string& unprocessedInstruction);

private:
	// opcode functions
	static void movHandler(const std::vector<std::string>& operands);
	static void leaHandler(const std::vector<std::string>& operands);
	static void addHandler(const std::vector<std::string>& operands);
	static void subHandler(const std::vector<std::string>& operands);
	static void mulHandler(const std::vector<std::string>& operands);
	static void divHandler(const std::vector<std::string>& operands);
	static void incHandler(const std::vector<std::string>& operands);
	static void decHandler(const std::vector<std::string>& operands);

private:
	static const size_t MEMORY_SIZE = 1000;
	static std::vector<byte> memoryVec;
	static std::unordered_map<std::string, word> regs;
	static std::unordered_map<std::string, InstructionHandler> instructions;
};
