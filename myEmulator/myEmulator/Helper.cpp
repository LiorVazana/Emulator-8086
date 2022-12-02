#include "Helper.h"

std::array<std::string, Helper::NUM_OF_REGS> Helper::regs = { "ax", "bx", "cx", "dx",
															  "si", "di", "ds", "ss",
					                                          "sp", "bp", "cs", "es" };

void Helper::trim(std::string& str)
{
	if (str.empty())
		return;
	
	size_t firstNotSpace = str.find_first_not_of(" \t");

	// left trim
	if (firstNotSpace != str.npos)
		str = str.substr(str.find_first_not_of(" \t"));

	// right trim
	str = str.substr(0, str.find_last_not_of(" \t") + 1);
}

void Helper::validateNumOfOperands(const size_t expected, const size_t given)
{
	if (expected != given)
		throw WrongNumberOfOperands(expected, given);
}

bool Helper::isRegister(const std::string& str)
{
	std::string regAccess = str;

	if (str.size() == 2 && (str[1] == 'l' || str[1] == 'h'))
		regAccess[1] = 'x';

	return std::find(std::begin(regs), std::end(regs), regAccess) != std::end(regs);
}

bool Helper::isImmediate(const std::string& str)
{
	try
	{
		(void)std::stoi(str);
		return true;
	}
	catch(const std::exception&)
	{
		return false;
	}
}

bool Helper::isMemory(const std::string& str)
{
	if (str.empty())
		return false;

	if (str[0] == '[' && str[str.size() - 1] == ']')
	{
		std::string trimedStr = str.substr(1, str.size() - 2);
		trim(trimedStr);

		if (isMemoryAllowedRegister(trimedStr) || isImmediate(trimedStr))
			return true;
		else
			throw MemoryAccessViolation("You can't access the memory with '" + trimedStr + "'.");
	}

	return false;
}

bool Helper::isMemoryAllowedRegister(const std::string& str)
{
	return str == "bx" || str == "si" || str == "di";
}

std::string Helper::getMemoryAccess(const std::string& str)
{
	if (!isMemory(str))
		throw InvalidArgument("Argument must be memory accessable but recived '" + str + "'");

	return str.substr(1, str.size() - 2);

}
