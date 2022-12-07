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
	static void PushInstruction(const std::string& instructionStr);
	static void ExecuteInstructions();

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
	static void loopHandler(const std::vector<std::string>& operands);
	static void cmpHandler(const std::vector<std::string>& operands);

	// je - Jump Equal | jz - Jump Zero
	static void jeJzHandler(const std::vector<std::string>& operands);

	// jne - Jump not Equal | jnz - Jump Not Zero
	static void jneJnzHandler(const std::vector<std::string>& operands);

	// jg - Jump Greater | jnle - Jump Not Less/Equal
	static void jgJnleHandler(const std::vector<std::string>& operands);

	// jge - Jump Greater/Equal | jnl - Jump Not Less
	static void jgeJnlHandler(const std::vector<std::string>& operands);

	// jl - Jump Less | jnge - Jump Not Greater/Equal
	static void jlJngeHandler(const std::vector<std::string>& operands);

	// jle - Jump Less/Equal | jng - Jump Not Greater
	static void jleJngHandler(const std::vector<std::string>& operands);

	// ja - Jump Above | Jnbe - Jump Not Below/Equal
	static void jaJnbeHandler(const std::vector<std::string>& operands);

	// jxcz - Jump if CX is Zero
	static void jxczHandler(const std::vector<std::string>& operands);

	// jae Jump Above/Equal | jnb - Jump Not Below
	static void jaeJnbHandler(const std::vector<std::string>& operands);

	// jb - Jump Below | jnae - Jump Not Above/Equal
	static void jbJnaeHandler(const std::vector<std::string>& operands);

	// jbe - Jump Below/Equal | jna - Jump Not Above
	static void jbeJnaHandler(const std::vector<std::string>& operands);

	// jc - Jump If Carry
	static void jcHandler(const std::vector<std::string>& operands);

	// jnc - Jump If No Carry
	static void jncHandler(const std::vector<std::string>& operands);

	// jo - Jump If Overflow
	static void joHandler(const std::vector<std::string>& operands);

	// jno - Jump If No Overflow
	static void jnoHandler(const std::vector<std::string>& operands);

	// jp - Jump Parity | jpe - Jump Parity Even	
	static void jpJpeHandler(const std::vector<std::string>& operands);

	// jnp - Jump No Parity | jpo - Jump Parity Odd
	static void jnpJpoHandler(const std::vector<std::string>& operands);

	// js - Jump Sign (negative value)
	static void jsHandler(const std::vector<std::string>& operands);

	// jns - Jump No Sign (positiv value)
	static void jnsHandler(const std::vector<std::string>& operands);


private:
	static const byte BITS_IN_BYTE = 8;
	static const size_t MEMORY_SIZE = 1000;
	static std::vector<byte> memoryVec;
	static std::unordered_map<std::string, word> regs;
	static std::unordered_map<std::string, InstructionHandler> instructions;
	static std::vector<std::string> instructionVec;
	static std::unordered_map<std::string, size_t> symbols;
	static size_t instructionPointer;
};
