#include "Emulator.h"

std::vector<byte> Emulator::memoryVec(MEMORY_SIZE);
std::unordered_map<std::string, word> Emulator::regs = { {"ax", 0}, {"bx", 0}, {"cx", 0}, {"dx", 0},
                                                        {"si", 0}, {"di", 0}, {"ds", 0}, {"ss", 0},
                                                        {"sp", 0}, {"bp", 0}, {"cs", 0}, {"es", 0} };
std::unordered_map<std::string, InstructionHandler> Emulator::instructions = { {"mov", movHandler},
                               {"lea", leaHandler}, {"add", addHandler}, {"sub", subHandler}, {"mul", mulHandler}, {"div", divHandler},
                               {"inc", incHandler}, {"dec", decHandler}, {"print", printHandler}, {"print_str", printStrHandler}, {"jmp", jmpHandler},
                               {"loop", loopHandler}, {"cmp", cmpHandler}, {"je", jeJzHandler}, {"jz", jeJzHandler}, {"jne", jneJnzHandler}, {"jnz", jneJnzHandler},
                               {"jg", jgJnleHandler}, {"jnle", jgJnleHandler}, {"jge", jgeJnlHandler}, {"jnl", jgeJnlHandler}, {"jl", jlJngeHandler},
                               {"jnge", jlJngeHandler}, {"jle", jleJngHandler}, {"jng", jleJngHandler}, {"jcxz", jcxzHandler}, {"ja", jaJnbeHandler},
                               {"jnbe", jaJnbeHandler}, {"jae", jaeJnbHandler}, {"jnb", jaeJnbHandler}, {"jb", jbJnaeHandler}, {"jnae", jbJnaeHandler},
                               {"jbw", jbeJnaHandler}, {"jna", jbeJnaHandler}, {"jc", jcHandler}, {"jnc", jncHandler}, {"jo", joHandler}, {"jno", jnoHandler},
                               {"jp", jpJpeHandler}, {"jpe", jpJpeHandler}, {"jnp", jnpJpoHandler}, {"jpo", jnpJpoHandler}, {"js", jsHandler}, {"jns", jnsHandler} };

std::vector<std::string> Emulator::instructionVec;
std::unordered_map<std::string, size_t> Emulator::symbols;
size_t Emulator::instructionPointer = 0;

void Emulator::pushInstruction(const std::string& instructionStr)
{
    if (instructionStr.empty())
        return;
    Instruction instruction = Lexer::processInstruction(instructionStr);

    if (instructions.count(instruction.opcode) != 0)
    {
        instructionVec.push_back(instructionStr);
    }
    else if (Helper::isLabel(instruction.opcode))
    {
        if (symbols.count(instruction.opcode) != 0)
            throw InvalidArgument("label is already exist.");

        symbols[instruction.opcode] = instructionVec.size();
    }
    else
    {
        throw InvalidOpcode(instruction.opcode);
    }
}

void Emulator::executeInstructions()
{
    for (instructionPointer; instructionPointer < instructionVec.size(); ++instructionPointer)
    {
        Instruction instruction = Lexer::processInstruction(instructionVec[instructionPointer]);
        instructions[instruction.opcode](instruction.operands);
    }
}

word Emulator::getRegisterValue(const std::string& reg)
{
    std::string regAccess = reg;

    if (reg.size() == 2 && reg[1] == 'l' || reg[1] == 'h')
        regAccess[1] = 'x';

    if (regs.count(regAccess) != 0)
    {
        word regValue = regs[regAccess];

        if (regAccess == reg)
            return regValue;

        if (reg[1] == 'l')
            return regValue & 0x00ff; // 0x14fd & 0xff  => 0x00fd

        if (reg[1] == 'h')
            return regValue >> BITS_IN_BYTE; // 0x14fd => 0x0014
    }

    throw InvalidArgument("the reg '" + reg + "' isnt valid");
}

void Emulator::setRegisterValue(const std::string& reg, const word value)
{
    
    std::string regAccess = reg;

    if (reg.size() == 2 && (reg[1] == 'l' || reg[1] == 'h'))
        regAccess[1] = 'x';

    if (regs.count(regAccess) != 0)
    {
        if (regAccess == reg)
        {
            regs[regAccess] = value;
            return;
        }

        if (reg[1] == 'l')
        {
            if (value > 0xff)
                throw InappropriateSize("the value must be one byte max");

            regs[regAccess] = (regs[regAccess] & 0xff00) | value; // 0x14fd => 0x1400 | 0x0012 = > 0x1412
            
            return;
        }

        if (reg[1] == 'h')
        {
            if (value > 0xff)
                throw InappropriateSize("the value must be one byte max");

            regs[regAccess] = (regs[regAccess] & 0x00ff) | (value << BITS_IN_BYTE); // 0x14fd => 0x00fd | (0x0012 << 8 => 0x1200) => 0x12fd

            return;
        }
    }

    throw InvalidArgument(reg);
}

byte Emulator::getValueFromMemoryAddr(const dword address)
{
    if (address >= MEMORY_SIZE)
        throw MemoryAccessViolation("Address not valid.");

    return memoryVec[address];
}

byte Emulator::getValueFromMemoryAccess(const std::string& memory)
{
    std::string memoryAccess = Helper::getMemoryAccess(memory);

    dword address = 0;

    if (Helper::isMemoryAllowedRegister(memoryAccess))
        address = getRegisterValue(memoryAccess);
    else
        address = std::stoi(memoryAccess);

    return getValueFromMemoryAddr(address);
}

void Emulator::setValueInMemoryAddr(const dword address, const byte value)
{
    if (address >= MEMORY_SIZE)
        throw MemoryAccessViolation("Address not valid.");

    memoryVec[address] = value;
}

void Emulator::setValueInMemoryAccess(const std::string& memory, const byte value)
{
    std::string memoryAccess = Helper::getMemoryAccess(memory);

    dword address = 0;

    if (Helper::isMemoryAllowedRegister(memoryAccess))
        address = getRegisterValue(memoryAccess);
    else
        address = std::stoi(memoryAccess);

    setValueInMemoryAddr(address, value);
}

word Emulator::getValueFromImmediate(const std::string& str)
{
    try
    {
        return std::stoi(str);
    }
    catch (const std::exception&)
    {
        // accept only ascii values surrounded by single quotes
        std::regex pattern("'[ -~]'");

        if (std::regex_match(str, pattern))
            return str[1];
    }

    throw InvalidArgument("the given argument isn't immediate");
}

void Emulator::mathController(const std::vector<std::string>& operands, const MathOperation op)
{
    Helper::validateNumOfOperands(2, operands.size());

    if (Helper::isImmediate(operands[DST]))
        throw InvalidOperand("First operand '" + operands[DST] + "' cannot be a immediate.");

    if (Helper::isMemory(operands[DST]) && Helper::isMemory(operands[SRC]))
        throw MemoryAccessViolation("can't access the memory twice at the same time.");

    if (Helper::isRegister(operands[DST]) && Helper::isRegister(operands[SRC]))
    {
        switch (op)
        {
            case MathOperation::MOV:
                setRegisterValue(operands[DST], getRegisterValue(operands[SRC]));
                break;

            case MathOperation::ADD:
                setRegisterValue(operands[DST], getRegisterValue(operands[DST]) + getRegisterValue(operands[SRC]));
                break;

            case MathOperation::SUB:
                setRegisterValue(operands[DST], getRegisterValue(operands[DST]) - getRegisterValue(operands[SRC]));
                break;

            case MathOperation::MUL:
                setRegisterValue(operands[DST], getRegisterValue(operands[DST]) * getRegisterValue(operands[SRC]));
                break;

            case MathOperation::DIV:
                setRegisterValue("dx", getRegisterValue(operands[DST]) % getRegisterValue(operands[SRC]));
                setRegisterValue(operands[DST], getRegisterValue(operands[DST]) / getRegisterValue(operands[SRC]));
                break;
        }
    }
    else if (Helper::isRegister(operands[DST]) && Helper::isImmediate(operands[SRC]))
    {
        switch (op)
        {
            case MathOperation::MOV:
                setRegisterValue(operands[DST], getValueFromImmediate(operands[SRC]));
                break;

            case MathOperation::ADD:
                setRegisterValue(operands[DST], getRegisterValue(operands[DST]) + getValueFromImmediate(operands[SRC]));
                break;

            case MathOperation::SUB:
                setRegisterValue(operands[DST], getRegisterValue(operands[DST]) - getValueFromImmediate(operands[SRC]));
                break;

            case MathOperation::MUL:
                setRegisterValue(operands[DST], getRegisterValue(operands[DST]) * getValueFromImmediate(operands[SRC]));
                break;

            case MathOperation::DIV:
                setRegisterValue("dx", getRegisterValue(operands[DST]) % getValueFromImmediate(operands[SRC]));
                setRegisterValue(operands[DST], getRegisterValue(operands[DST]) / getValueFromImmediate(operands[SRC]));
                break;
        }
        return;
    }
    else if (Helper::isRegister(operands[DST]) && Helper::isMemory(operands[SRC]))
    {
        std::string memoryAccess = Helper::getMemoryAccess(operands[SRC]);

        dword address = 0;

        if (Helper::isMemoryAllowedRegister(memoryAccess))
            address = getRegisterValue(memoryAccess);
        else
            address = std::stoi(memoryAccess);

        if (operands[DST][1] == 'l' || operands[DST][1] == 'h')
        {
            switch (op)
            {
                case MathOperation::MOV:
                    setRegisterValue(operands[DST], getValueFromMemoryAddr(address));
                    break;

                case MathOperation::ADD:
                    setRegisterValue(operands[DST], getRegisterValue(operands[DST]) + getValueFromMemoryAddr(address));
                    break;

                case MathOperation::SUB:
                    setRegisterValue(operands[DST], getRegisterValue(operands[DST]) - getValueFromMemoryAddr(address));
                    break;

                case MathOperation::MUL:
                    setRegisterValue(operands[DST], getRegisterValue(operands[DST]) * getValueFromMemoryAddr(address));
                    break;

                case MathOperation::DIV:
                    setRegisterValue("dx", getRegisterValue(operands[DST]) % getValueFromMemoryAddr(address));
                    setRegisterValue(operands[DST], getRegisterValue(operands[DST]) / getValueFromMemoryAddr(address));
                    break;
            }
        }
        else
        {
            word value = getValueFromMemoryAddr(address);
            value |= (static_cast<word>(getValueFromMemoryAddr(address + 1)) << BITS_IN_BYTE);//ùðééä

            switch (op)
            {
                case MathOperation::MOV:
                    setRegisterValue(operands[DST], value);
                    break;

                case MathOperation::ADD:
                    setRegisterValue(operands[DST], getRegisterValue(operands[DST]) + value);
                    break;

                case MathOperation::SUB:
                    setRegisterValue(operands[DST], getRegisterValue(operands[DST]) - value);
                    break;

                case MathOperation::MUL:
                    setRegisterValue(operands[DST], getRegisterValue(operands[DST]) * value);
                    break;

                case MathOperation::DIV:
                    setRegisterValue("dx", getRegisterValue(operands[DST]) % value);
                    setRegisterValue(operands[DST], getRegisterValue(operands[DST]) / value);
                    break;
            }
        }

    }
    else if (Helper::isMemory(operands[DST]) && Helper::isRegister(operands[SRC]))
    {
        std::string memoryAccess = Helper::getMemoryAccess(operands[DST]);

        dword address = 0;

        if (Helper::isMemoryAllowedRegister(memoryAccess))
            address = getRegisterValue(memoryAccess);
        else
            address = std::stoi(memoryAccess);

        if (operands[SRC][1] == 'l' || operands[SRC][1] == 'h')
        {
            switch (op)
            {
                case MathOperation::MOV:
                    setValueInMemoryAddr(address, getRegisterValue(operands[SRC]));
                    break;

                case MathOperation::ADD:
                    setValueInMemoryAddr(address, getValueFromMemoryAccess(operands[DST]) + getRegisterValue(operands[SRC]));
                    break;

                case MathOperation::SUB:
                    setValueInMemoryAddr(address, getValueFromMemoryAccess(operands[DST]) - getRegisterValue(operands[SRC]));
                    break;

                case MathOperation::MUL:
                    setValueInMemoryAddr(address, getValueFromMemoryAccess(operands[DST]) * getRegisterValue(operands[SRC]));
                    break;

                case MathOperation::DIV:
                    setRegisterValue("dx", getValueFromMemoryAccess(operands[DST]) % getRegisterValue(operands[SRC]));
                    setValueInMemoryAddr(address, getValueFromMemoryAccess(operands[DST]) / getRegisterValue(operands[SRC]));
                    break;
            }
        }
        else
        {
            word value = 0;
            switch (op)
            {
                case MathOperation::MOV:
                    value = getRegisterValue(operands[SRC]);
                    break;

                case MathOperation::ADD:
                    value = getRegisterValue(operands[DST]) + getRegisterValue(operands[SRC]);
                    break;

                case MathOperation::SUB:
                    value = getRegisterValue(operands[DST]) - getRegisterValue(operands[SRC]);
                    break;

                case MathOperation::MUL:
                    value = getRegisterValue(operands[DST]) * getRegisterValue(operands[SRC]);
                    break;

                case MathOperation::DIV:
                    setRegisterValue("dx", getRegisterValue(operands[DST]) % getRegisterValue(operands[SRC]));
                    value = getRegisterValue(operands[DST]) / getRegisterValue(operands[SRC]);
                    break;
            }

            setValueInMemoryAddr(address, (value & 0x00ff));
            setValueInMemoryAddr(address + 1, value >> BITS_IN_BYTE);
        }
    }
    else if (Helper::isMemory(operands[DST]) && Helper::isImmediate(operands[SRC]))
    {
        std::string memoryAccess = Helper::getMemoryAccess(operands[DST]);

        dword address = 0;

        if (Helper::isMemoryAllowedRegister(memoryAccess))
            address = getRegisterValue(memoryAccess);
        else
            address = getValueFromImmediate(memoryAccess);

        word value = 0;
        switch (op)
        {
        case MathOperation::MOV:
            value = getValueFromImmediate(operands[SRC]);
            break;

        case MathOperation::ADD:
            value = getValueFromMemoryAccess(operands[DST]) + getValueFromImmediate(operands[SRC]);
            break;

        case MathOperation::SUB:
            value = getValueFromMemoryAccess(operands[DST]) - getValueFromImmediate(operands[SRC]);
            break;

        case MathOperation::MUL:
            value = getValueFromMemoryAccess(operands[DST]) * getValueFromImmediate(operands[SRC]);
            break;

        case MathOperation::DIV:
            setRegisterValue("dx", getValueFromMemoryAccess(operands[DST]) % getValueFromImmediate(operands[SRC]));
            value = getValueFromMemoryAccess(operands[DST]) / getValueFromImmediate(operands[SRC]);
            break;
        }

        setValueInMemoryAddr(address, value & 0x00ff);
        setValueInMemoryAddr(address + 1, value >> BITS_IN_BYTE);
    }
    else 
    {
        throw InvalidOperand("unsupported operand");
    }
}

void Emulator::movHandler(const std::vector<std::string>& operands)
{
    mathController(operands, MathOperation::MOV);
}

void Emulator::leaHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(2, operands.size());

    if (!Helper::isRegister(operands[DST]))
        throw InvalidOperand("first arg must be register");

    if (!Helper::isMemory(operands[SRC]))
        throw InvalidOperand("second arg must be memory");
        
    std::string memoryAccess = Helper::getMemoryAccess(operands[SRC]);

    dword address = 0;

    if (Helper::isMemoryAllowedRegister(memoryAccess))
        address = getRegisterValue(memoryAccess);
    else
        address = getValueFromImmediate(memoryAccess);

    setRegisterValue(operands[DST], address);

}

void Emulator::addHandler(const std::vector<std::string>& operands)
{
    mathController(operands, MathOperation::ADD);
}

void Emulator::subHandler(const std::vector<std::string>& operands)
{
    mathController(operands, MathOperation::SUB);
}

void Emulator::mulHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());

    std::vector<std::string> newOperands = operands;
    newOperands.insert(newOperands.begin(), 1, "ax");

    mathController(newOperands, MathOperation::MUL);
}

void Emulator::divHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());

    std::vector<std::string> newOperands = operands;
    newOperands.insert(newOperands.begin(), 1, "ax");

    if ((Helper::isImmediate(operands[0]) && getValueFromImmediate(operands[0]) == 0) || (Helper::isRegister(operands[0]) && getRegisterValue(operands[0]) == 0) ||
        (Helper::isMemory(operands[0]) && getValueFromMemoryAccess(operands[0]) == 0))
        throw ZeroDivision();

    mathController(newOperands, MathOperation::DIV);
}

void Emulator::incHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());

    std::vector<std::string> newOperands = operands;
    newOperands.push_back("1");

    mathController(newOperands, MathOperation::ADD);

}

void Emulator::decHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());

    std::vector<std::string> newOperands = operands;
    newOperands.push_back("1");

    mathController(newOperands, MathOperation::SUB);
}

void Emulator::printHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());

    if (Helper::isRegister(operands[0]))
        std::cout << getRegisterValue(operands[0]) << std::endl;

    else if (Helper::isImmediate(operands[0]))
        std::cout << operands[0] << std::endl;

    else if (Helper::isMemory(operands[0]))
        std::cout << static_cast<word>(getValueFromMemoryAccess(operands[0])) << std::endl;

    else
        throw InvalidArgument("print must get an immediate number, memory address or register.");
}

void Emulator::printStrHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());

    dword address;
    byte chr = ' ';

    if (Helper::isRegister(operands[0]))
        address = getRegisterValue(operands[0]);

    else if (Helper::isImmediate(operands[0]))
        address = std::stoi(operands[0]);

    else
        throw InvalidArgument("print_str expect immediate number or register");

    while ((chr = getValueFromMemoryAddr(address)) != '\0')
    {
        std::cout << chr;
        ++address;
    }

    std::cout << std::endl;
}

void Emulator::jmpHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    
    std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidArgument(operands[0] + " doesnt exist");

    instructionPointer = symbols[label] - 1;
}

void Emulator::loopHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    word cx = getRegisterValue("cx");
    std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidArgument(operands[0] + " doesnt exist");

    if (--cx != 0)
    {
        setRegisterValue("cx", cx);
        jmpHandler(operands);
    }

    setRegisterValue("cx", cx);
}

void Emulator::cmpHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(2, operands.size());

    word result;
    word firstOpVal;
    word secondOpVal;

    if (Helper::isMemory(operands[0]))
    {
        if (Helper::isMemory(operands[1]))
            throw MemoryAccessViolation("cant access the memory twice at same time");

        firstOpVal = getValueFromMemoryAccess(operands[0]);
    }

    else if (Helper::isImmediate(operands[0]))
        throw InvalidOperand("first operand cannot be an immidiate value");

    else if (Helper::isRegister(operands[0]))
        firstOpVal = getRegisterValue(operands[0]);
    else
        throw InvalidArgument("cmp operand are invalid (invalid operand: immediate, memory or register)");


    if (Helper::isMemory(operands[1]))
        secondOpVal = getValueFromMemoryAccess(operands[1]);

    else if (Helper::isImmediate(operands[1]))
        secondOpVal = std::stoi(operands[1]);

    else if (Helper::isRegister(operands[1]))
        secondOpVal = getRegisterValue(operands[1]);
    else
        throw InvalidArgument("cmp operand are invalid (invalid operand: immediate, memory or register)");

    result = firstOpVal - secondOpVal;
}

void Emulator::jeJzHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");
}

void Emulator::jneJnzHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jgJnleHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jgeJnlHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jlJngeHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jleJngHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jaJnbeHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jcxzHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jaeJnbHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jbJnaeHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jbeJnaHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jcHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jncHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::joHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jnoHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jpJpeHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jnpJpoHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jsHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}

void Emulator::jnsHandler(const std::vector<std::string>& operands)
{
    Helper::validateNumOfOperands(1, operands.size());
    const std::string label = operands[0] + ":";

    if (symbols.count(label) == 0)
        throw InvalidOperand("the enterd label doesnt exist");


}
