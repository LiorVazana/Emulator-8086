#pragma once
#include "EmulatorException.h"

class MemoryAccessViolation : public EmulatorException
{
public:
	MemoryAccessViolation(const std::string& msg)
		:	EmulatorException(msg)
	{
	}
};