# Insert License

################################################################################
# Setup / Bootstrap
################################################################################

# CMake Setup
cmake_minimum_required(VERSION 3.17.0)

# Search Paths
set(CMAKE_MODULE_PATH
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/clang"
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules"
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake"
)

# CMake Modules
include("util")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Clang/Clang.cmake")
	include("Clang")
	set(HAVE_CLANG ON)
endif()

# Automatic Versioning
set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)
set(VERSION_PATCH 0)
set(VERSION_TWEAK 0)
set(VERSION_SUFFIX "")
if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/.git")
	set(GIT_RESULT "")
	set(GIT_OUTPUT "")
	execute_process(
		COMMAND git rev-list --count --topo-order ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}${VERSION_SUFFIX}..HEAD
		WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
		RESULT_VARIABLE GIT_RESULT
		OUTPUT_VARIABLE GIT_OUTPUT
		OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_STRIP_TRAILING_WHITESPACE ERROR_QUIET
	)
	if(GIT_RESULT EQUAL 0)
		set(VERSION_TWEAK ${GIT_OUTPUT})
	endif()
	execute_process(
		COMMAND git rev-parse --short=8 HEAD
		WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
		RESULT_VARIABLE GIT_RESULT
		OUTPUT_VARIABLE GIT_OUTPUT
		OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_STRIP_TRAILING_WHITESPACE ERROR_QUIET
	)
	if(GIT_RESULT EQUAL 0)
		set(PROJECT_COMMIT ${GIT_OUTPUT})
	endif()
endif()
if(PROJECT_COMMIT)
	set(VERSION_STRING "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.${VERSION_TWEAK}${VERSION_SUFFIX}-${PROJECT_COMMIT}")
else()
	set(VERSION_STRING "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.${VERSION_TWEAK}${VERSION_SUFFIX}")
endif()

################################################################################
# Project
################################################################################
project(msvc-redist-helper
	LANGUAGES CXX;C
	DESCRIPTION "MSVC Redistributable Helper"
	VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.${VERSION_TWEAK}
	HOMEPAGE_URL "https://blog.xaymar.com/"
)

# Detect Architecture
set(BITS "64")
math(EXPR BITS "8*${CMAKE_SIZEOF_VOID_P}")
set(ARCH "x64")
if("${BITS}" STREQUAL "32")
	set(ARCH "x86")
endif()

# Apply compiler specific changes.
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC" OR (WIN32 AND CMAKE_CXX_COMPILER_ID STREQUAL "Clang"))
	message(STATUS "Applying custom flags for MSVC style build.")

	# MSVC/ClangCL
	# - Statically link Microsoft C/C++ Redistributable.
	# - Enable /W3 and disable useless warnings.
	# - Enable C++ exceptions with SEH exceptions.
	# - Enable multi-processor compiling.

	# Enable most useful warnings.
	set(DISABLED_WARNINGS 
		"/wd4061" "/wd4100" "/wd4180" "/wd4201" "/wd4464" "/wd4505" "/wd4514"
		"/wd4571" "/wd4623" "/wd4625" "/wd4626" "/wd4668" "/wd4710" "/wd4774"
		"/wd4820" "/wd5026" "/wd5027" "/wd5039" "/wd5045" "/wd26812"
	)
	add_compile_options("/W3")
	foreach(WARN ${DISABLED_WARNINGS})
		add_compile_options("${WARN}")
	endforeach()

	# Build with static MSVC linkage.
    add_compile_options(
        $<$<CONFIG:>:/MT>
        $<$<CONFIG:Debug>:/MTd>
        $<$<CONFIG:Release>:/MT>
        $<$<CONFIG:RelWithDebInfo>:/MT>
        $<$<CONFIG:MinSizeRel>:/MT>
    )

	# C++ Exceptions & SEH
	add_compile_options("/EHa")

	# Multiprocessor compiling
	add_compile_options("/MP")

elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang" OR CMAKE_CXX_COMPILER_ID STREQUAL "AppleClang" OR CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	message(STATUS "Applying custom flags for GNU style build.")
	
	# Clang/AppleClang/GNU
	# - Don't export by default.
	# - Enable all and extra warnings.
	
	add_compile_options("-Wall")
	add_compile_options("-Wextra")
	add_compile_options("-fvisibility=hidden")

endif()

# C++ Standard and Extensions
## Use C++17 and no non-standard extensions.
set(_CXX_STANDARD 17)
set(_CXX_EXTENSIONS OFF)

################################################################################
# Options
################################################################################


# Code Signing
set(${PropertyPrefix}SIGN_ENABLED FALSE CACHE BOOL "Enable signing builds.")
set(${PropertyPrefix}SIGN_KEY "" CACHE FILEPATH "Path to the private key with which to sign.")
set(${PropertyPrefix}SIGN_PASSWORD "" CACHE STRING "Password for the private key.")

################################################################################
# Project Setup
################################################################################
set(PROJECT_SOURCE
	source/bin.cpp
	source/bin.hpp
	source/curl.cpp
	source/curl.hpp
)
set(PROJECT_DATA
)
set(PROJECT_LIBRARIES
	libcurl
)
set(PROJECT_DEFINITIONS
	CURL_STATICLIB
)
set(PROJECT_INCLUDE_DIRS
)

# Dependencies
set(CURL_STATIC_CRT ON)
set(CURL_DISABLE_FTP ON)
set(CURL_DISABLE_LDAP ON)
set(CURL_DISABLE_TELNET ON)
set(CURL_DISABLE_DICT ON)
set(CURL_DISABLE_FILE ON)
set(CURL_DISABLE_TFTP ON)
set(CURL_DISABLE_LDAPS ON)
set(CURL_DISABLE_RTSP ON)
set(CURL_DISABLE_POP3 ON)
set(CURL_DISABLE_IMAP ON)
set(CURL_DISABLE_SMTP ON)
set(CURL_DISABLE_GOPHER ON)
set(BUILD_SHARED_LIBS OFF)
set(BUILD_CURL_EXE OFF)
set(CMAKE_USE_WINSSL ON)
add_subdirectory(third-party/curl)

# Create Library
add_executable(${PROJECT_NAME}
	${PROJECT_SOURCE}
)
target_link_libraries(${PROJECT_NAME}
	${PROJECT_LIBRARIES}
)
target_include_directories(${PROJECT_NAME}
	PRIVATE
		${PROJECT_INCLUDE_DIRS}
)

# Definitions
target_compile_definitions(${PROJECT_NAME}
	PRIVATE
		${PROJECT_DEFINITIONS}
)
if(MSVC)
	target_compile_definitions(${PROJECT_NAME}
		PRIVATE
			_CRT_SECURE_NO_WARNINGS
			_ENABLE_EXTENDED_ALIGNED_STORAGE
	)
endif()
if(WIN32)
	target_compile_definitions(${PROJECT_NAME}
		PRIVATE
			# windows.h
			WIN32_LEAN_AND_MEAN
			NOGPICAPMASKS
			NOVIRTUALKEYCODES
			#NOWINMESSAGES
			NOWINSTYLES
			NOSYSMETRICS
			NOMENUS
			NOICONS
			NOKEYSTATES
			NOSYSCOMMANDS
			NORASTEROPS
			NOSHOWWINDOW
			NOATOM
			NOCLIPBOARD
			NOCOLOR
			#NOCTLMGR
			NODRAWTEXT
			#NOGDI
			NOKERNEL
			#NOUSER
			#NONLS
			NOMB
			NOMEMMGR
			NOMETAFILE
			NOMINMAX
			#NOMSG
			NOOPENFILE
			NOSCROLL
			NOSERVICE
			NOSOUND
			#NOTEXTMETRIC
			NOWH
			NOWINOFFSETS
			NOCOMM
			NOKANJI
			#NOHELP
			NOPROFILER
			NODEFERWINDOWPOS
			NOMCX
			NOIME
			NOMDI
			NOINOUT
	)
endif()

# C++ Standard and Extensions
set_target_properties(
	${PROJECT_NAME}
	PROPERTIES
		CXX_STANDARD ${_CXX_STANDARD}
		CXX_STANDARD_REQUIRED ON
		CXX_EXTENSIONS ${_CXX_EXTENSIONS}
)

# File Version
if(WIN32)
	set_target_properties(
		${PROJECT_NAME}
		PROPERTIES
		VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}.${PROJECT_VERSION_TWEAK}
		SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}.${PROJECT_VERSION_TWEAK}
	)
else()
	set_target_properties(
		${PROJECT_NAME}
		PROPERTIES
		VERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}.${PROJECT_VERSION_TWEAK}
		SOVERSION ${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}.${PROJECT_VERSION_TWEAK}
	)
endif()

# Clang Tools
if(HAVE_CLANG)
	generate_compile_commands_json(
		TARGETS ${PROJECT_NAME}
	)
	clang_tidy(
		TARGETS ${PROJECT_NAME}		
		VERSION 9.0.0
	)
	clang_format(
		TARGETS ${PROJECT_NAME}
		DEPENDENCY
		VERSION 9.0.0
	)
endif()

# Signing
if(${PropertyPrefix}SIGN_ENABLED)
	# Investigate: https://github.com/Monetra/mstdlib/blob/master/CMakeModules/CodeSign.cmake
	if(MSVC) 
		find_program(${PropertyPrefix}SIGN_TOOL
			NAMES "signtool"
			DOC "Path to the signing tool."
			REQUIRED
		)
		
		if(${PropertyPrefix}SIGN_TOOL)
			message(STATUS "${PROJECT_NAME}: Signing enabled")
			add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
				COMMAND ${${PropertyPrefix}SIGN_TOOL}
				ARGS sign /p "${${PropertyPrefix}SIGN_PASSWORD}" /f "${${PropertyPrefix}SIGN_KEY}" $<TARGET_FILE:${PROJECT_NAME}>
			)
		endif()
	endif()
endif()

################################################################################
# Installation
################################################################################

