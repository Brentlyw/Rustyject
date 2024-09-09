# Rustyject
An undetected Rust based shellcode injector. 

# Features
- **Custom encoding of the payload**
  - The payload is stored as an array of 3 character strings.
  - The first two characters come from a defined alphabet, these are used to construct an *intermediate byte*
  - The first character is found in the alphabet, and it's index shifted left by 4 bits (*16), *representing the higher nibble of the byte.*
  - The second character is also found in the alphabet, it's value is used directly as the *lower nibble of the byte.*
  - These nibbles are combined using a bitwise OR operation to form the *complete byte.*
  - The complete byte is XORed with the ASCII value of the third character - which is the *final encoded byte.*
- **XOR decryption reverses this and is performed just-in-time before injection**
  - Decryption and injection is performed byte-by-byte as to never store the entire decoded payload in memory.
- Function pointers for memory calls
- Gargoyle technique with variable delay
- Dynamically targets explorer's PID

# Note
This proof of concept project is meant to be educational, please keep it that way and do no harm.

# Detection Rate?
As of late August 2024, 2/75 via Virustotal.
