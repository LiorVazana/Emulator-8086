#pragma once
#include "EmulatorException.h"

class MemoryAccessVaiolation : public EmulatorException
{
public:
	MemoryAccessVaiolation(const std::string& msg)
		:	EmulatorException(msg)
	{
	}
};