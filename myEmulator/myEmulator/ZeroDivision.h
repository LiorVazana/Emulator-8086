#pragma once
#include "EmulatorException.h"

class ZeroDivision : public EmulatorException
{
public:
	ZeroDivision()
		:	EmulatorException("Can't divide by zero!")
	{
	}
};