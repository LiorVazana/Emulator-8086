#pragma once
#include "Instruction.h"
#include "Helper.h"
#include <iostream>
#include <sstream>
#include <vector>


class Lexer
{
public:
	static Instruction processInstruction(std::string instruction);
};
