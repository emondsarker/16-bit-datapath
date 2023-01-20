#Emon Sarker 1931461642

def errorHandler(type, count):
    line = str(count)
    if type == "Incorrect Instruction":
        print("[Input error in line: "+line+" | "+type+"]")
        writef.write("[Input error in line: "+line+" | "+type+"]")
    if type == "Incorrect Register":
        print("[Input error in line: "+line+" | "+type+"]")
        writef.write("[Input error in line: "+line+" | "+type+"]")
    quit()

def binToHex(bin):
    hex =" "
    if bin == "0000":
        hex = "0"
    elif bin == "0001":
        hex = "1"
    elif bin == "0010":
        hex = "2"
    elif bin == "0011":
        hex = "3"
    elif bin == "0100":
        hex = "4"
    elif bin == "0101":
        hex = "5"
    elif bin == "0110":
        hex = "6"
    elif bin == "0111":
        hex = "7"
    elif bin == "1000":
        hex = "8"
    elif bin == "1001":
        hex = "9"
    elif bin == "1010":
        hex = "A"
    elif bin == "1011":
        hex = "B"
    elif bin == "1100":
        hex = "C"
    elif bin == "1101":
        hex = "D"
    elif bin == "1110":
        hex = "E"
    elif bin == "1111":
        hex = "F"
    return hex


def convertInstructionToBinary(inst):
    binaryInstruction = " "

    if inst == "nop":
        binaryInstruction = "0000"
    elif  inst == "beq":
        binaryInstruction = "0001"
    elif inst == "sub":
        binaryInstruction = "0010"
    elif inst == "sll":
        binaryInstruction = "0011"
    elif inst == "and":
        binaryInstruction = "0100"
    elif inst == "sw":
        binaryInstruction = "0101"
    elif inst == "slt":
        binaryInstruction = "0110"
    elif inst == "jmp":
        binaryInstruction = "0111"
    elif inst == "add":
        binaryInstruction = "1000"
    elif inst == "addi":
        binaryInstruction = "1001"
    elif inst == "lw":
        binaryInstruction = "1010"
    else:
        errorHandler()

    return binaryInstruction


def convertRegisterToBinary(reg, count):

    convertReg = ""
    if  reg == "$zero":
        convertReg ="0000" 
    elif reg == "$s1":
        convertReg ="0001"
    elif reg == "$s2":
        convertReg ="0010"
    elif reg == "$s3":
        convertReg ="0011"
    elif reg == "$s4":
        convertReg ="0100"
    elif reg == "$s5":
        convertReg ="0101"
    elif reg == "$s6":
        convertReg ="0110"
    elif reg == "$s7":
        convertReg ="0111"
    elif reg == "$s8":
        convertReg ="1000"
    elif reg == "$s9":
        convertReg ="1001"
    elif reg == "$s10":
        convertReg ="1010"
    elif reg == "$s11":
        convertReg ="1011"
    elif reg == "$s12":
        convertReg ="1100"
    elif reg == "$s13":
        convertReg ="1101"
    elif reg == "$s14":
        convertReg ="1110"
    elif reg == "$s15":
        convertReg ="1111"
    else:
        errorHandler("Incorrect Register", count)
        
    return convertReg


def decimalToBinary(num):

    if(num<0):
        num =  16 + num

    ext = ""
    result = ""
    
    while(num>0):
        if num % 2 == 0:
            result = "0" + result
        else:
            result = "1" + result

        num = num//2

    for i in range(4-len(result)):
        ext = "0" + ext

    result = ext + result


    return result


readf = open("inputs.txt","r")
writef = open("outputs.txt","w")
writef.write("Output(Hex):\n")

count = 0
for i in readf:
    splitted = i.split()
    count = count + 1
    #R-type
    if(splitted[0] == "sub" or splitted[0] == "and" or splitted[0] == "slt" or splitted[0] == "add"):
        conv_inst = binToHex(convertInstructionToBinary(splitted[0]))
        conv_rs = binToHex(convertRegisterToBinary(splitted[1],count))
        conv_rt = binToHex(convertRegisterToBinary(splitted[2],count))
        conv_rd = binToHex(convertRegisterToBinary(splitted[3],count))

        out = conv_inst + conv_rs + conv_rt + conv_rd
        print(out)
        writef.write(out+"\n")

    elif(splitted[0] == "beq" or splitted[0] == "sll" or splitted[0] == "sw" or splitted[0] == "addi" or splitted[0] == "lw"):
        conv_inst = binToHex(convertInstructionToBinary(splitted[0]))
        conv_rs = binToHex(convertRegisterToBinary(splitted[1],count))
        conv_rt = binToHex(convertRegisterToBinary(splitted[2],count))
        conv_im = binToHex(decimalToBinary(int(splitted[3])))

        out = conv_inst + conv_rs + conv_rt + conv_im
        print(out)
        writef.write(out+"\n")  
     
    elif(splitted[0] == "jmp"):
        conv_inst = binToHex(convertInstructionToBinary(splitted[0]))
        hexval = hex(int(splitted[1]))
        exF2 = hexval[2:]
        ext = ""
        for i in range(3 - len(exF2)):
            ext = "0" + ext

        conv_target = ext + exF2

        out = conv_inst + conv_target
        print(out)
        writef.write(out+"\n") 
    else:
        errorHandler("Incorrect Instruction", count)

    
