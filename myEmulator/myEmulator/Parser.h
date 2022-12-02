#pragma once
#include "Instruction.h"
#include "Helper.h"
#include <iostream>
#include <sstream>
#include <vector>


class Parser
{
public:
	static Instruction ProcessInstruction(std::string instruction);
};
