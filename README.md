# Rustyject
A Rust based shellcode injector, utilizes XOR encryption and the gargoyle technique.

# Features
- XOR encryption .py script (formats msfvenom to rust byte array)
- XOR decryption just-in-time before injection
- Gargoyle technique with variable delay
- Dynamically targets explorer.exe
- Can easily be modified to be evasive, and have very low detections.

# Note
This is NOT designed to be evasive, have low detections, etc. 
