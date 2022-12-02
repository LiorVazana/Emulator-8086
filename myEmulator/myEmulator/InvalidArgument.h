#pragma once
#include "EmulatorException.h"

class InvalidArgument : public EmulatorException
{
public:
	InvalidArgument(const std::string& msg)
		: EmulatorException(msg)
	{
	}
};