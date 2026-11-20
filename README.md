# DO NOT USE
This tool is not the best way to do this and will miss updates to the MSVC++ redistributable that you depend on. It only checks if certain DLLs are present, which is not the correct way. Instead check the registry key `SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\x64` for the information you need.

# Microsoft Visual C++ Redistributable Helper
This tool checks for a specific version of the redistributable and if it is not found, will install it. 

## Usage:
`msvc-redist-helper [msvc-version]`

## Dependencies
- Windows
- CURL with HTTPS support
