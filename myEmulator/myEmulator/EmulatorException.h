#pragma once
#include <stdexcept>
#include <string>

class EmulatorException : public std::runtime_error
{
public:
	EmulatorException(const std::string& msg)
		:	std::runtime_error(msg)
	{
	}
};
