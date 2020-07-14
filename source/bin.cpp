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
#include <sstream>
#include <string_view>
#include <vector>

#include <ShlObj.h>
#include <Windows.h>

#include "curl.hpp"

#ifdef _WIN64
const std::map<int32_t, std::string_view> redist_urls = {
	{2015, "https://aka.ms/vs/16/release/vc_redist.x64.exe"},
	{2017, "https://aka.ms/vs/16/release/vc_redist.x64.exe"},
	{2019, "https://aka.ms/vs/16/release/vc_redist.x64.exe"},
};
#else
const std::map<int32_t, std::string_view> redist_urls = {
	{2015, "https://aka.ms/vs/16/release/vc_redist.x86.exe"},
	{2017, "https://aka.ms/vs/16/release/vc_redist.x86.exe"},
	{2019, "https://aka.ms/vs/16/release/vc_redist.x86.exe"},
};
#endif

const std::map<int32_t, std::list<std::string_view>> redist_dlls = {
	{2015,
	 {
		 "msvcp140.dll",
		 "vcruntime140.dll",
	 }},
	{2017,
	 {
		 "msvcp140.dll",
		 "vcruntime140.dll",
		 "msvcp140_1.dll",
		 "vcruntime140_1.dll",
	 }},
	{2019,
	 {
		 "msvcp140.dll",
		 "vcruntime140.dll",
		 "msvcp140_1.dll",
		 "vcruntime140_1.dll",
		 "msvcp140_2.dll",
	 }},
};

static void helper_free_handle(void* handle)
{
	CloseHandle(static_cast<HANDLE>(handle));
}

int32_t main(int32_t argc, const char* argv[])
{
	// Args:
	// [0] binary
	// [1] msvc version to test and download.
	// >=[2] error out.

	if (argc == 1) {
		std::cout << "Usage: " << std::endl;
		std::cout << "  " << argv[0] << " [msvc-version]" << std::endl;
		return 1;
	} else if (argc > 2) {
		std::cerr << "Too many arguments." << std::endl;
		return 1;
	}

	int32_t msvc_version = atoi(argv[1]);

	auto url_found = redist_urls.find(msvc_version);
	if (url_found == redist_urls.end()) {
		std::cerr << "The selected MSVC version has no known download URLs." << std::endl;
		return 1;
	}

	auto dlls_found = redist_dlls.find(msvc_version);
	if (dlls_found == redist_dlls.end()) {
		std::cerr << "The selected MSVC version has no known DLLs and can't be tested for." << std::endl;
		return 1;
	}

	std::cout << "Checking if all necessary DLLs for MSVC version " << msvc_version << " exist..." << std::endl;

	bool missing_dll = false;
	for (auto dll : dlls_found->second) {
		std::vector<WCHAR> buf;

		int size = MultiByteToWideChar(CP_UTF8, DWORD(0), dll.data(), static_cast<int>(dll.size()), NULL, int(0));
		buf.resize(static_cast<size_t>(size) + 1);
		MultiByteToWideChar(CP_UTF8, DWORD(0), dll.data(), static_cast<int>(dll.size()), buf.data(),
							static_cast<int>(buf.size()));

		HMODULE libh = LoadLibraryW(buf.data());
		auto    lib =
			std::shared_ptr<void>(static_cast<void*>(libh), [](void* ptr) { FreeLibrary(static_cast<HMODULE>(ptr)); });
		if (lib) {
			std::cout << "  " << dll << ": Found" << std::endl;
		} else {
			std::cout << "  " << dll << ": Missing" << std::endl;
			missing_dll = true;
		}
	}

	if (!missing_dll) {
		std::cout << "Installed MSVC redistributable is up to date." << std::endl;
		return 0;
	}

	std::filesystem::path path = std::filesystem::temp_directory_path();
	{
		std::cout << "Missing required DLLs, downloading installer..." << std::endl;

		// Open a temporary file.
		std::ofstream file;
		{
			std::stringstream sstr;
			sstr << "ms-vcredist-" << msvc_version << "-" << static_cast<int64_t>(time(NULL)) << ".exe";
			path.concat(sstr.str().c_str());

			file.open(path, std::ios::out | std::ios::binary);
			if (!file.is_open() || file.bad()) {
				std::cerr << "Failed to create installer file." << std::endl;
				return 1;
			}
		}

		util::curl curl;
		curl.set_option(CURLOPT_HTTPGET, 1);
		curl.set_option(CURLOPT_URL, url_found->second);
		curl.set_option(CURLOPT_FOLLOWLOCATION, 1);
		curl.set_option(CURLOPT_CRLF, 0);
		curl.set_write_callback([&file](void* buf, size_t n, size_t c) {
			file.write(static_cast<char*>(buf), n * c);
			return n * c;
		});
		curl.set_xferinfo_callback([](uint64_t total, uint64_t now, uint64_t, uint64_t) { return int32_t(0); });
		CURLcode res = curl.perform();
		file.close();
		if (res != CURLE_OK) {
			std::cerr << "Failed to download installer." << std::endl;
			return 1;
		}
	}

	{
		PROCESS_INFORMATION   pi{0};
		STARTUPINFOW          si{0};
		SECURITY_ATTRIBUTES   sa{0};
		std::shared_ptr<void> processh;
		std::shared_ptr<void> threadh;
		std::wstring          file_path    = path.wstring();
		std::wstring          command_line = L"/install /quiet /norestart";
		std::vector<WCHAR>    command_line_buf(command_line.size() + 1);
		memcpy(command_line_buf.data(), command_line.data(), command_line.size() * sizeof(WCHAR));

		si.cb             = sizeof(STARTUPINFOW);
		sa.nLength        = sizeof(SECURITY_ATTRIBUTES);
		sa.bInheritHandle = TRUE;

		BOOL res = CreateProcessW(file_path.data(), command_line_buf.data(), &sa, &sa, TRUE, CREATE_UNICODE_ENVIRONMENT,
								  NULL, NULL, &si, &pi);
		processh = std::shared_ptr<void>(static_cast<void*>(pi.hProcess), helper_free_handle);
		threadh  = std::shared_ptr<void>(static_cast<void*>(pi.hThread), helper_free_handle);

		if (!res) {
			DWORD error = GetLastError();

			std::cerr << "Failed to launch installer, code " << error << "." << std::endl;
			return 1;
		}
		std::cout << "Installer for MSVC " << msvc_version << " launched, waiting...";
		std::cout.flush();

		while (WaitForSingleObject(pi.hProcess, 5000) == WAIT_TIMEOUT) {
			std::cout << ".";
			std::cout.flush();
		}
		std::cout << std::endl;

		DWORD exitcode = 0;
		GetExitCodeProcess(pi.hProcess, &exitcode);

		if (exitcode != 0) {
			std::cerr << "There was an error installing or repairing the redistributable." << std::endl;
			return 1;
		}
	}

	// Clean up.
	std::filesystem::remove(path);

	std::cout << "Successfully updated MSVC " << msvc_version << " Redistributable to latest version." << std::endl;
	return 0;
}
