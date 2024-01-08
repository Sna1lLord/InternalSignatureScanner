# Internal Signature Scanner
- Welcome to the internal version of the signature scanner!
- This project is not complete, and will require tuning in order to work for your project

# Usage
- Make sure to allocate a console in your project if you want the debug logs to be printed, i.e the scan time
- In "signatures.hpp", line 63, make sure to change the process file name
- In "signatures.cpp", line 119, there's a basic example of how to use the scanner. 
  Make sure to change the signature
- Included in the scanner is a couple of functions for handling the resulting address:
  - Add : adds a value to the resulting address
  - Sub : subtracts a value from the resulting address
  - Rip : gets an address located a couple of opcodes away from the resulting address
  - Cast : *required* function which returns the final value and can be casted to specific type

# External
- I will shortly be releasing an external version of this signature scanner
