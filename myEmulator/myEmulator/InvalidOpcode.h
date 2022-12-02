#pragma once
#include "EmulatorException.h"

class InvalidOpcode : public EmulatorException
{
public:
	InvalidOpcode(const std::string& opcode)
		: EmulatorException("The opcode '" + opcode + "' isn't supported!")
	{
	}
};