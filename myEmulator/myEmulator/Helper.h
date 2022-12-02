#pragma once
#include <string>
#include <array>
#include "WrongNumberOfOperands.h"
#include "MemoryAccessViolation.h"

class Helper
{
public:
	// Remove the spaces from the left and the right of the string
	static void trim(std::string& str);

	static void validateNumOfOperands(const size_t expected, const size_t given);
	static bool isRegister(const std::string& str);
	static bool isImmediate(const std::string& str);
	static bool isMemory(const std::string& str); 
	static bool isMemoryAllowedRegister(const std::string& str);

private:
	static const size_t NUM_OF_REGS = 12;
	static std::array < std::string, NUM_OF_REGS> regs;
};
