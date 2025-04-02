## About the project
The project was developed to automate the string decryption process in a .NET binary obfuscated with [ConfuserEx 2](https://mkaring.github.io/ConfuserEx/). The primary motivation behind creating the alternative string decryption tool was to use a custom user-chosen Powershell version which can support more modern .NET versions, considering limitations of the default Windows 10 default Powershell.

A full deobfuscation guide that includes a context in which the script can be used can be found here: 

[`https://iterasec.com/blog/understanding-confuserex2-net-obfuscation-and-deobfuscation-techniques`](https://iterasec.com/blog/understanding-confuserex2-net-obfuscation-and-deobfuscation-techniques)

## Caution
The script decrypts string constants by utilizing .NET Reflection which means that ConfuserEx 2 internal functions are used with discovered encrypted values to restore the original strings. Be sure to execute the script in a safe isolated environment in case an obfuscated binary sample contains modified malicious code inside the internal decryption functions that will be executed automatically upon the script invocation.
## Prerequisites
* [python3](https://www.python.org/)
* [pythonnet](https://github.com/pythonnet/pythonnet) python library
    ```
    pip install pythonnet
    ```
* [dnlib](https://github.com/0xd4d/dnlib)
    ```
    the script tested with a dnlib library compiled from source with .NET Framework 4.5 
    but should work as expected with other versions as well
    ```
* at least one obfuscated .NET target binary with packing and anti-tamper protection removed
## Usage

### A single file
```
python decryptor.py -l "C:\Users\User\dnlib.dll" -f "C:\Users\User\obfuscated_binary.exe" -v
```
### Multiple files in a directory
```
python decryptor.py -l "C:\Users\User\dnlib.dll" -d "C:\Users\User" -e ".dll" -o "C:\Users\User\output_dir" -v
```
### Using a different Powershell version
There are cases when a preinstalled Powershell version does not support newer versions of .NET on top of which an obfuscated target binary may be compiled. In this case a custom Powershell binary can be specified with the `-s` flag.
```
python decryptor.py -l "C:\Users\User\dnlib.dll" -f "C:\Users\User\obfuscated_binary.exe" -s "C:\Program Files\PowerShell\7\pwsh.exe"
```
