# Rustyject
A Rust based shellcode injector, utilizes XOR encryption and the gargoyle technique.

# Features
- XOR encryption .py script (formats msfvenom to rust byte array)
- XOR decryption just-in-time before injection
- Function pointers for memory calls (helps w/ static)
- Gargoyle technique with variable delay
- Dynamically targets explorer.exe
- Can easily be modified to be evasive, and have very low detections.

# Note
This is NOT designed to be evasive, have low detections, etc. 

# Scans
[https://www.virustotal.com/gui/file/5c122d32e0c85e887d264bce7fac076d8c783f7d661235ea9c2f174e07d0a0b9?nocache=1](https://www.virustotal.com/gui/file/114df112928620ca953b40d85cf9fa163cfbdbe2640ff342f633841cd2fc5ada?nocache=1)
