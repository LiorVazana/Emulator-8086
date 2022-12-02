#pragma once
#include "EmulatorException.h"

class InvalidRegisterAccess : public EmulatorException
{
public:
	InvalidRegisterAccess(const std::string& regName)
		: EmulatorException("The register '" + regName + "' not exist")
	{
	}
};