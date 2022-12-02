#pragma once
#include "EmulatorException.h"

class InvalidOperand : public EmulatorException
{
public:
	InvalidOperand(const std::string& msg)
		: EmulatorException(msg)
	{
	}
};