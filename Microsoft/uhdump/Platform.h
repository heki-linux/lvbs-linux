#pragma once


#define RUNTIME_ASSERT(condition, exceptionMsg)                    \
    do                                                             \
    {                                                              \
        if (!(condition))                                          \
        {                                                          \
            throw std::runtime_error(std::string(__FILE__) + ":" + \
                    std::to_string(__LINE__) + ":" +               \
                    exceptionMsg);                                 \
        }                                                          \
    }                                                              \
    while(0)
    
#if defined(_MSC_VER)

#   define CL_WINDOWS

#   if !defined(_M_AMD64) && !defined(_M_ARM64)
#       error Unsupported target CPU
#   endif

#   if defined(_M_AMD64)
#   define CPU_ARCH "amd64"
#   endif

#   if defined(_M_ARM64)
#   define CPU_ARCH "arm64"
#   endif

    // Compiling for Windows x64 or arm64

#   include <tchar.h>
#   include <sal.h>
#   include <Windows.h>
#   include <evntrace.h>
#   include <aclapi.h>
#   include <inaddr.h>
#   include <rpc.h>
#   include <WinCrypt.h>
#   include <WinHttp.h>
#   include <StrSafe.h>
#   include <TraceLoggingProvider.h> 
#   include <winmeta.h>
#   include <oacr.h>

#   define WIDEN2(x) L ## x
#   define WIDEN(x) WIDEN2(x)

#   define __TFILE__ WIDEN(__FILE__)
#   define __TFUNCTION__ WIDEN(__FUNCTION__)

#   define HRESULT_ERROR_FILE_NOT_FOUND HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND)

#elif defined(__GNUC__) || defined(__clang__)

#   define CL_LINUX

#   if !defined (__linux__)
#       error Unsupported OS    
#   endif

#   if !defined(__amd64) && !defined(__aarch64__)
#       error Unsupported target CPU    
#   endif

#   if defined(__amd64)
#   define CPU_ARCH "amd64"
#   endif

#   if defined(__aarch64__)
#   define CPU_ARCH "arm64"
#   endif

    // Constants

#   define TRACE_LEVEL_CRITICAL     1
#   define TRACE_LEVEL_ERROR        2
#   define TRACE_LEVEL_WARNING      3
#   define TRACE_LEVEL_INFORMATION  4
#   define TRACE_LEVEL_VERBOSE      5

#   define S_OK                         0
#   define ERROR_SUCCESS                0
#   define HRESULT_ERROR_FILE_NOT_FOUND 0x80070002

    // SAL stubs

#   define _In_
#   define _In_opt_
#   define _Out_
#   define _Inout_
#   define _In_z_
#   define _Printf_format_string_
#   define _Inout_count_(C)
#   define _Inout_updates_bytes_(C) 
#   define _In_reads_bytes_(C)
#   define _In_bytecount_(C)
#   define _Success_(C)

#   include <sys/time.h>
#   include <sys/types.h>
#   include <sys/syscall.h>
#   include <sys/types.h>
#   include <sys/stat.h>
#   include <sys/mman.h>
#   include <netinet/in.h> 
#   include <arpa/inet.h>

#   include <uuid/uuid.h>

#   include <pthread.h>
#   include <semaphore.h>
#   include <unistd.h>
#   include <signal.h>
#   include <syslog.h>
#   include <inttypes.h>
#   include <errno.h>
#   include <fcntl.h>
#   include <stdio.h>
#   include <stdlib.h>
#   include <string.h>
#   include <strings.h>
#   include <dirent.h>
#   include <ifaddrs.h>

    // Macros

#   define ARRAYSIZE(x) (sizeof(x)/sizeof(x[0]))
#   define UNREFERENCED_PARAMETER(x) (void)(x)
#   define HRESULT_FROM_WIN32(x) (x)

#   define WIDEN2(x) L ## x
#   define WIDEN(x) WIDEN2(x)

#   define TEXT(x) x

#   define __TFILE__ __FILE__
#   define __TFUNCTION__ __FUNCTION__

#   define UNUSED_PARAMETER(A) ((void)(A))

#   define MAX_PATH PATH_MAX
#   define INFINITE 0xFFFFFFFF

#else

#   error Unsupported compiler

#endif

#if defined (__cplusplus)

#include <atomic>
#include <string>
#include <map>
#include <vector>
#include <list>
#include <stack>
#include <set>
#include <unordered_map>
#include <memory>
#include <stdexcept>
#include <exception>
#include <system_error>
#include <functional>
#include <tuple>
#include <utility>
#include <chrono>
#include <type_traits>
#include <algorithm>

#ifndef __cplusplus_cli
#include <thread>
#endif

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <cstdarg>

#endif

#ifdef CL_WINDOWS

typedef const wchar_t*     PCTSTR;
typedef wchar_t*           PTSTR;

#define FILE_HANDLE        HANDLE

#if defined (__cplusplus)

typedef std::wstring tstring;
#define to_tstring to_wstring

#define PATH_SEPARATOR_CHAR L'\\'
#define PATH_SEPARATOR_STR L"\\"

#endif

#endif

#ifdef CL_LINUX

typedef uint8_t         BYTE;
typedef uint16_t        WORD;
typedef int16_t         SHORT;
typedef char            CHAR;
typedef char            TCHAR;
typedef const char*     PCTSTR;
typedef const char*     PCTCH;
typedef char*           PTSTR;
typedef const char*     PCSTR;
typedef char*           PSTR;
typedef uint32_t        ULONG;
typedef uint32_t*       PULONG;
typedef uint32_t        ULONG32;
typedef uint32_t        UINT32;
typedef int32_t         LONG;
typedef int64_t         LONG64;
typedef uint64_t        ULONG64;
typedef uint32_t        DWORD;
typedef uint64_t        ULONGLONG;
typedef uint64_t*       PULONGLONG;
typedef uint64_t        SIZE_T;
typedef uint64_t        ULARGE_INTEGER;
typedef BYTE*           PBYTE;
typedef unsigned char   BOOL;
typedef unsigned char*  PBOOL;

typedef LONG            HRESULT;

typedef uint16_t        INTERNET_PORT;

typedef uuid_t          IID;

typedef uint32_t        ALG_ID;

typedef struct timespec FILETIME;
typedef struct timeval  SYSTEMTIME;

#if defined (__cplusplus)

typedef std::string     tstring;

#endif

#define HTTP_STATUS_CREATED 201

#define _tcsftime strftime
#define _ttoi atoi
#define _istspace isspace
#define _tcschr strchr
#define _tprintf printf
#define _sntprintf snprintf
#define _tcscmp strcmp
#define _tstoi atoi
#define _tcsncmp strncmp
#define _tcsicmp strcasecmp
#define _tcsnicmp strncasecmp
#define _tcstol strtol
#define _tcstod strtod
#define _totupper toupper
#define _tcslen strlen
#define _tremove remove

#define to_tstring to_string

#define WINAPI
#define LPVOID void*
#define FILE_HANDLE FILE*
#define INVALID_HANDLE_VALUE nullptr

#define  CALG_AES_128 0x0000660eUL
#define  CALG_AES_192 0x0000660fUL
#define  CALG_AES_256 0x00006610UL

#define TRUE ((BOOL)1)
#define FALSE ((BOOL)0)

#define E_FAIL 0x80004005

#define PATH_SEPARATOR_CHAR '/'
#define PATH_SEPARATOR_STR "/"

#define _tmain main

inline int GetLastError()
{
    return errno;
}

inline void GetSystemTime(SYSTEMTIME* SystemTime)
{
    gettimeofday(SystemTime, NULL);
}

inline void SystemTimeToFileTime(SYSTEMTIME* SystemTime, FILETIME* FileTime)
{
    FileTime->tv_sec = SystemTime->tv_sec;
    FileTime->tv_nsec = SystemTime->tv_usec*1000;
}

inline void GetSystemTimeAsFileTime(FILETIME* FileTime)
{
    SYSTEMTIME systemTime;

    GetSystemTime(&systemTime);
    SystemTimeToFileTime(&systemTime, FileTime);
}

#endif

#if defined (__cplusplus)

// Fundamental assumptions about sizes

static_assert(sizeof(CHAR) == 1, "sizeof(CHAR) != 1");
static_assert(sizeof(BYTE) == 1, "sizeof(BYTE) != 1");

#ifdef CL_LINUX

// -fshort-wchar is used to make the wchar_t 2 bytes-sized
// That requires recompiling the C++ library that we cannot do
static_assert(sizeof(TCHAR) == 1, "sizeof(TCHAR) != 4");

#endif

#ifdef CL_WINDOWS

static_assert(sizeof(TCHAR) == 2, "sizeof(WCHAR) != 2");

#endif

static_assert(sizeof(WORD) == 2, "sizeof(WORD) != 2");
static_assert(sizeof(ULONG) == 4, "sizeof(ULONG) != 4");
static_assert(sizeof(LONG) == 4, "sizeof(LONG) != 4");
static_assert(sizeof(DWORD) == 4, "sizeof(DWORD) != 4");
static_assert(sizeof(ULONGLONG) == 8, "sizeof(ULONGLONG) != 8");

#define MIN(a, b) (((a) < (b)) ? (a) : (b))

#endif
