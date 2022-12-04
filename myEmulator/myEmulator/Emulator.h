#pragma once
#include <vector>
#include <unordered_map>
#include <memory>
#include "Instruction.h"
#include "Parser.h"
#include "InvalidOpcode.h"
#include "InvalidOperand.h"
#include "MemoryAccessViolation.h"
#include "InvalidRegisterAccess.h"
#include "InappropriateSize.h"
#include "InvalidArgument.h"
#include "ZeroDivision.h"

// use this typedef in the memory vector;
typedef unsigned char byte;
typedef unsigned short word;
typedef unsigned int dword;
typedef void (*InstructionHandler) (const std::vector<std::string>&);

enum OperandsOptions
{
	DST, SRC
};

enum class MathOperation
{
	MOV, ADD, SUB,
	MUL, DIV
};

class Emulator
{
public:
	static void ExecuteInstruction(const std::string& instructionStr);

private:

	static word GetRegisterValue(const std::string& reg);
	static void SetRegisterValue(const std::string& reg, const word value);
	static byte GetValueFromMemoryAddr(const dword address);
	static byte GetValueFromMemoryAccess(const std::string& memory);
	static void SetValueInMemoryAddr(const dword address, const byte value);
	static void SetValueInMemoryAccess(const std::string& memory, const byte value);
	static word GetValueFromImmediate(const std::string& str);
	static void MathController(const std::vector<std::string>& operands, const MathOperation op);

	// opcode functions
	static void movHandler(const std::vector<std::string>& operands);
	static void leaHandler(const std::vector<std::string>& operands);
	static void addHandler(const std::vector<std::string>& operands);
	static void subHandler(const std::vector<std::string>& operands);
	static void mulHandler(const std::vector<std::string>& operands);
	static void divHandler(const std::vector<std::string>& operands);
	static void incHandler(const std::vector<std::string>& operands);
	static void decHandler(const std::vector<std::string>& operands);
	static void printHandler(const std::vector<std::string>& operands);
	static void printStrHandler(const std::vector<std::string>& operands);
	static void jmpHandler(const std::vector<std::string>& operands);
	static void pauseHandler(const std::vector<std::string>& operands);
	static void resumeHandler(const std::vector<std::string>& operands);

private:
	static const byte BITS_IN_BYTE = 8;
	static const size_t MEMORY_SIZE = 1000;
	static std::vector<byte> memoryVec;
	static std::unordered_map<std::string, word> regs;
	static std::unordered_map<std::string, InstructionHandler> instructions;
	static std::vector<std::string> instructionVec;
	static std::unordered_map<std::string, size_t> symbols;
	static bool isPaused;
	static size_t pausedLine;
	static bool keepTrack;
};
