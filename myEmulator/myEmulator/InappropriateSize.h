#pragma once
#include "EmulatorException.h"

class InappropriateSize : public EmulatorException
{
public:
	InappropriateSize(const std::string& msg)
		: EmulatorException(msg)
	{
	}
};