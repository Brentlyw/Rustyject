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

# Scans
https://www.virustotal.com/gui/file/5c122d32e0c85e887d264bce7fac076d8c783f7d661235ea9c2f174e07d0a0b9?nocache=1
