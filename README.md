# PhantLoad

**PhantLoad** is an advanced Reflective PE Loader written in C, designed for exploring Windows security mechanisms. It enables loading and executing entire Portable Executable (EXE) files directly from memory, bypassing standard system loading calls and leaving no traces on the disk.

## 🚀 Key Features

- **Custom API Resolver**: Completely avoids using the loader's own static Import Address Table (IAT). All necessary Windows functions are discovered dynamically by parsing the Process Environment Block (PEB) and DLL Export Directories.
- **Forwarded Export Support**: Intelligent resolution of API redirections. For instance, when `kernel32.dll!HeapAlloc` forwards the call to `ntdll.dll!RtlAllocateHeap`, the loader automatically resolves the final code address.
- **AES-256 CBC Decryption**: Payloads are stored encrypted and decrypted only in RAM immediately before execution.
- **Manual Mapping**: Implements the full manual PE image mapping cycle:
  - Header copying and section alignment to virtual addresses.
  - **Base Relocations**: Adjustment of absolute addresses (Type 10 - DIR64) to ensure correct operation at any memory base.
  - **IAT Resolution**: Manual filling of the payload's Import Address Table using custom resolvers.
- **DEP/NX Bypass**: Dynamic management of memory page protections via `VirtualProtect` to ensure code execution capability.

## 📁 Project Structure

- `src/`: Core loader source code.
- `include/`: Header files and Windows API definitions.
- `payload/`: Scripts for payload preparation and encryption.

## 🛠 Usage Instructions

### 1. Requirements
- Linux OS (Debian/Ubuntu/Kali).
- `x86_64-w64-mingw32-gcc` cross-compiler.
- Python 3 with the `pycryptodome` library installed.

### 2. Payload Preparation
Place your payload source code in the `payload/` folder (e.g., `payload_calc.c`):

```bash
# Compile payload to EXE
x86_64-w64-mingw32-gcc payload/payload_calc.c -o payload/payload_calc.exe -luser32 -lkernel32

# Encrypt and create the payload.h header file
# IMPORTANT: payload.h must be placed where main.c expects it
python3 payload/encrypt.py payload/payload_calc.exe payload/payload.h
```

### 3. Building the Loader
From the project root directory:

```bash
# Compile the loader
x86_64-w64-mingw32-gcc src/*.c -o PhantLoad.exe -lbcrypt
```

### 4. Running
Run the resulting `PhantLoad.exe` in a Windows environment or via Wine:
```bash
wine PhantLoad.exe
```

## 🧠 Technical Details

The most interesting part of the project is the implementation of `GetDllFuncAddress`. Unlike simple loaders, PhantLoad checks if the discovered function RVA is part of the Export Section. If so, the loader parses the forwarder string (e.g., `NTDLL.RtlAllocateHeap`), recursively finds the `ntdll.dll` base, and calculates the actual function address. This allows the loader to remain stable even on modern Windows versions where `kernel32.dll` acts merely as a wrapper.

## ⚠️ Disclaimer

This project was created solely for educational purposes and security testing. The author is not responsible for any illegal use of this tool. Use it only within the scope of ethical hacking and legal research.
