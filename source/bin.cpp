/*
 * Detecting MS VC Redist 2015+:
 * - 2015: msvcp140, vcruntime140
 * - 2017: msvcp140_1, vcruntime140_1, plus above
 * - 2019, msvcp140_2, plus all above.
 **/

#include <filesystem>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string_view>
#include <vector>

#include <ShlObj.h>
#include <Windows.h>

#include "curl.hpp"

#if defined(__x86_64__) || defined(_M_X64)
#define IS_X86
#define IS_64BIT
#elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
#define IS_X86
#define IS_32BIT
#elif defined(__aarch64__) || defined(_M_ARM64)
#define IS_ARM
#define IS_64BIT
#elif defined(__arm__) || defined(_M_ARM)
#define IS_ARM
#define IS_32BIT
#endif

struct redists {
	std::set<int32_t>                              versions;
	std::set<std::filesystem::path>                libs;
	std::list<std::pair<std::string, std::string>> urls;
};

const std::list<redists> known_redists = {
	{
		// 80
		{2005},
		{
			//			"atl80.dll",
			"mfc80.dll",
			"mfc80u.dll",
			"mfcm80.dll",
			"mfcm80u.dll",
			"msvcm80.dll",
			"msvcp80.dll",
			"msvcr80.dll",
			"vcomp80.dll",
		},
		{
#if defined(IS_X86) && defined(IS_64BIT)
			{"https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x64.EXE",
			 "/Q"},
#elif defined(IS_X86) && defined(IS_32BIT)
			{"https://download.microsoft.com/download/8/B/4/8B42259F-5D70-43F4-AC2E-4B208FD8D66A/vcredist_x86.EXE",
			 "/Q"},
#endif
		},
	},
	{
		// 90
		{2008},
		{
			//			"atl90.dll",
			"mfc90.dll",
			"mfc90u.dll",
			"mfcm90.dll",
			"mfcm90u.dll",
			"msvcp90.dll",
			"msvcr90.dll",
			"vcomp90.dll",
		},
		{
#if defined(IS_X86) && defined(IS_64BIT)
			{"https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe",
			 "/q"},
#elif defined(IS_X86) && defined(IS_32BIT)
			{"https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe",
			 "/q"},
#endif
		},
	},
	{
		// 100
		{2010},
		{
			"atl100.dll",
			"mfc100.dll",
			"mfc100u.dll",
			"mfcm100.dll",
			"mfcm100u.dll",
			"mrt100.dll",
			"msvcp100.dll",
			"msvcr100.dll",
			"pdmproxy100.dll",
			"vcomp100.dll",
		},
		{
#if defined(IS_X86) && defined(IS_64BIT)
			{"https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe",
			 "/install /quiet /norestart"},
#elif defined(IS_X86) && defined(IS_32BIT)
			{"https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe",
			 "/install /quiet /norestart"},
#endif
		},
	},
	{
		// 110
		{2012},
		{
			"atl110.dll",
			"mfc110.dll",
			"mfc110u.dll",
			"mfcm110.dll",
			"mfcm110u.dll",
			"msvcp110.dll",
			"msvcr110.dll",
			"vcamp110.dll",
			"vccorlib110.dll",
			"vcomp110.dll",
		},
		{
#if defined(IS_X86) && defined(IS_64BIT)
			{"https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe",
			 "/install /quiet /norestart"},
#elif defined(IS_X86) && defined(IS_32BIT)
			{"https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe",
			 "/install /quiet /norestart"},
#elif defined(IS_ARM) && defined(IS_32BIT)
			{"https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_arm.exe",
			 "/install /quiet /norestart"},
#endif
		},
	},
	{
		// 120
		{2013},
		{
			"mfc120.dll",
			"mfc120u.dll",
			"mfcm120.dll",
			"mfcm120u.dll",
			"msvcp120.dll",
			"msvcr120.dll",
			"vcamp120.dll",
			"vccorlib120.dll",
			"vcomp120.dll",
		},
		{
#if defined(IS_X86) && defined(IS_64BIT)
			{"https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe",
			 "/install /quiet /norestart"},
#elif defined(IS_X86) && defined(IS_32BIT)
			{"https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe",
			 "/install /quiet /norestart"},
#elif defined(IS_ARM) && defined(IS_32BIT)
			{"https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_arm.exe",
			 "/install /quiet /norestart"},
#endif
		},
	},
	{
		// 140
		{2015, 2017, 2019, 2022},
		{
			"concrt140.dll",
#if defined(IS_X86) && defined(IS_64BIT)
			"libomp140.x86_64.dll",
#elif defined(IS_X86) && defined(IS_32BIT)
			"libomp140.x86.dll",
#elif defined(IS_ARM) && defined(IS_64BIT)
			"libomp140.arm64.dll",
#endif
			"mfc140.dll",
			"mfc140u.dll",
			"mfcm140.dll",
			"mfcm140u.dll",
			"msvcp140.dll",
			"msvcp140_1.dll",
			"msvcp140_2.dll",
			"msvcp140_atomic_wait.dll",
			"msvcp140_codecvt_ids.dll",
			"vcamp140.dll",
			"vccorlib140.dll",
			"vcomp140.dll",
			"vcruntime140.dll",
			"vcruntime140_1.dll",
		},
		{
#if defined(IS_X86) && defined(IS_64BIT)
			{"https://aka.ms/vs/17/release/vc_redist.x64.exe", "/install /quiet /norestart"},
#elif defined(IS_X86) && defined(IS_32BIT)
			{"https://aka.ms/vs/17/release/vc_redist.x86.exe", "/install /quiet /norestart"},
#elif defined(IS_ARM) && defined(IS_64BIT)
			{"https://aka.ms/vs/17/release/vc_redist.arm64.exe", "/install /quiet /norestart"},
#endif
		},
	},
};

std::string format_string(std::string_view format, ...)
{
	std::vector<char> buffer;
	va_list           args1;
	va_list           args2;

	va_start(args1, format);
	int sz = vsnprintf(nullptr, 0, format.data(), args1);
	va_end(args1);

	if (sz == -1) {
		throw std::runtime_error("Failed to format string.");
	}

	buffer.resize(sz + 1);
	if (buffer.size() == 0) {
		throw std::runtime_error("Failed to reserve memory.");
	}

	va_start(args2, format);
	vsnprintf(buffer.data(), buffer.size(), format.data(), args2);
	va_end(args2);

	return std::string{buffer.begin(), buffer.end() - 1};
}

std::wstring widen(std::string str)
{
	std::vector<WCHAR> buffer;

	int size = MultiByteToWideChar(CP_UTF8, DWORD(0), str.data(), static_cast<int>(str.size()), NULL, int(0));
	buffer.resize(static_cast<size_t>(size) + 1);
	MultiByteToWideChar(CP_UTF8, DWORD(0), str.data(), static_cast<int>(str.size()), buffer.data(),
						static_cast<int>(buffer.size()));
	return {buffer.begin(), buffer.end() - 1};
}

static void helper_free_handle(void* handle)
{
	CloseHandle(static_cast<HANDLE>(handle));
}

void download_file(const std::string& url, const std::filesystem::path& file)
{
	std::ofstream stream{file, std::ios::out | std::ios::binary};
	if (!stream.is_open() || stream.bad()) {
		throw std::runtime_error(format_string("Failed to open file '%s'.", file.string().c_str()));
	}

	util::curl curl;
	curl.set_option(CURLOPT_HTTPGET, 1);
	curl.set_option(CURLOPT_URL, url);
	curl.set_option(CURLOPT_FOLLOWLOCATION, 1);
	curl.set_option(CURLOPT_CRLF, 0);
	curl.set_write_callback([&stream](void* data, size_t bytes, size_t count) {
		stream.write(static_cast<char*>(data), bytes * count);
		return bytes * count;
	});
	curl.set_xferinfo_callback([](uint64_t total, uint64_t now, uint64_t, uint64_t) { return int32_t(0); });

	std::cout << "Downloading '" << url << "'..." << std::endl;
	CURLcode res = curl.perform();
	stream.close();

	if (res != CURLE_OK) {
		std::filesystem::remove(file);
		throw std::runtime_error(
			format_string("Failed to download file '%s' from '%s'.", file.string().c_str(), url.c_str()));
	}
}

void launch_file(const std::filesystem::path& file, std::string command_line_u8)
{
	std::cout << format_string("Launching '%s' with command line '%s'...", file.u8string().c_str(),
							   command_line_u8.c_str())
			  << std::endl;

	// Build an acceptable command line ([0] = module, [1...] = arguments)
	std::wstring       module_name = file.wstring();
	std::vector<WCHAR> command_line;
	{
		std::wstringstream wstr;
		wstr << L"\"" << module_name << L"\"" << L" ";
		wstr << widen(command_line_u8);

		std::wstring raw = wstr.str();
		command_line     = {raw.begin(), raw.end()};
		command_line.push_back(0);
	}

	PROCESS_INFORMATION pi{0};

	STARTUPINFOW si{0};
	si.cb = sizeof(STARTUPINFOW);

	SECURITY_ATTRIBUTES sa{0};
	sa.nLength        = sizeof(SECURITY_ATTRIBUTES);
	sa.bInheritHandle = TRUE;

	std::shared_ptr<void> managed_process_handle;
	std::shared_ptr<void> managed_thread_handle;
	BOOL res = CreateProcessW(module_name.data(), command_line.data(), &sa, &sa, TRUE, CREATE_UNICODE_ENVIRONMENT, NULL,
							  NULL, &si, &pi);
	managed_process_handle = std::shared_ptr<void>(static_cast<void*>(pi.hProcess), helper_free_handle);
	managed_thread_handle  = std::shared_ptr<void>(static_cast<void*>(pi.hThread), helper_free_handle);

	if (!res) {
		DWORD error = GetLastError();
		throw std::runtime_error(
			format_string("Failed to launch '%s', error code: %ld.", file.string().c_str(), error));
	}

	while (WaitForSingleObject(pi.hProcess, 1000) == WAIT_TIMEOUT) {
		std::cout << ".";
		std::cout.flush();
	}
	std::cout << std::endl;

	DWORD exitcode = 0;
	GetExitCodeProcess(pi.hProcess, &exitcode);
	if (exitcode != 0) {
		throw std::runtime_error("Installing Redistributable failed.");
	}
}

void install_libraries(int32_t version, const std::list<std::pair<std::string, std::string>>& urls)
{
	std::filesystem::path file;
	file = std::filesystem::temp_directory_path();
	file /= format_string("msvc-redist-%ld-%lld.exe", version, static_cast<int64_t>(time(NULL)));

	std::cout << "Installing Microsoft Visual C/C++ Redistributable version " << version << "..." << std::endl;
	for (const auto& kv : urls) {
		try {
			download_file(kv.first, file);
			launch_file(file, kv.second);
		} catch (const std::exception& ex) {
			if (std::filesystem::exists(file)) {
				std::filesystem::remove(file);
			}
			throw ex;
		}
	}
}

bool test_libraries(const std::set<std::filesystem::path>& libs)
{
	for (auto& lib : libs) {
		auto    lib_name   = lib.wstring();
		HMODULE lib_handle = LoadLibraryW(lib_name.data());
		auto    lib_ref    = std::shared_ptr<void>(static_cast<void*>(lib_handle),
                                             [](void* ptr) { FreeLibrary(static_cast<HMODULE>(ptr)); });
		if (!lib_ref) {
			std::cout << format_string("Missing library '%s'.", lib.string().c_str()) << std::endl;
			return false;
		}
	}
	return true;
}

int32_t main(int32_t argc, const char* argv[])
{
	// Args:
	// [0] binary
	// [1] Microsoft Visual C/C++ Redistributable version to test and install.
	// >=[2] error out.

	if (argc == 1) {
		std::cout << "Usage: " << std::endl;
		std::cout << "  " << argv[0] << " [msvc-version]" << std::endl;
		return 1;
	} else if (argc > 2) {
		std::cerr << "Too many arguments." << std::endl;
		return 1;
	}

	// Find the matching Microsoft Visual C/C++ Redistributable.
	int32_t msvc_version = atoi(argv[1]); // Unsafe.
	bool    known        = false;
	for (const auto& kv : known_redists) {
		// Is this the correct entry?
		if (auto v = kv.versions.find(msvc_version); v == kv.versions.end()) {
			// No, so we skip it.
			continue;
		}
		std::cout << "Checking if all necessary DLLs for MSVC version " << msvc_version << " exist..." << std::endl;

		if (test_libraries(kv.libs)) {
			std::cout << "Installed MSVC redistributable is up to date." << std::endl;
			return 0;
		} else {
			try {
				install_libraries(msvc_version, kv.urls);
				std::cout << "Successfully updated MSVC " << msvc_version << " Redistributable to latest version."
						  << std::endl;
				return 0;
			} catch (const std::exception& ex) {
				std::cerr << ex.what() << std::endl;
				return 1;
			}
		}
	}

	std::cerr << "Unknown Microsoft Visual C/C++ Redistributable version." << std::endl;
	return 1;
}
