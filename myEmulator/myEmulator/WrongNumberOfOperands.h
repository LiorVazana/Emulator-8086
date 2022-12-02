#pragma once
#include "EmulatorException.h"


class WrongNumberOfOperands : public EmulatorException
{
public:
	WrongNumberOfOperands(const size_t expected, const size_t given)
		:	EmulatorException("the opcode expected " + std::to_string(expected) + " operands and recived " + std::to_string(given) + " operands")
	{
	}
};
