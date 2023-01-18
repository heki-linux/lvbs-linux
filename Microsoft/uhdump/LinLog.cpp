#include <LinLog.h>

#include <cstdio>

#define RESET   "\e[0m"

#define BLACK   "\e[30m"
#define RED     "\e[31m"
#define GREEN   "\e[32m"
#define YELLOW  "\e[33m"
#define BLUE    "\e[34m"
#define MAGENTA "\e[35m"
#define CYAN    "\e[36m"
#define WHITE   "\e[37m"

#define BRIGHT_BLACK   "\e[1m\e[30m"
#define BRIGHT_RED     "\e[1m\e[31m"
#define BRIGHT_GREEN   "\e[1m\e[32m"
#define BRIGHT_YELLOW  "\e[1m\e[33m"
#define BRIGHT_BLUE    "\e[1m\e[34m"
#define BRIGHT_MAGENTA "\e[1m\e[35m"
#define BRIGHT_CYAN    "\e[1m\e[36m"
#define BRIGHT_WHITE   "\e[1m\e[37m"

//#define FORMAT "%04d-%02d-%02d %02d:%02d:%02d.%03luZ, %u, %lu, %i, %i, %s, %s, %u"
#define FORMAT 

CrashListener::Logging::ConsoleLog::ConsoleLog(_In_ LONG MaxLevel) : ILog(MaxLevel)
{    
}

CrashListener::Logging::ConsoleLog::~ConsoleLog()
{
    fputs(WHITE, stderr);
}

void CrashListener::Logging::ConsoleLog::MessageV(
    _In_ LONG Level,
    _In_ LONG Code,
    _In_z_ PCTSTR File,
    _In_z_ PCTSTR Function,
    _In_   ULONG Line,
    _In_z_ _Printf_format_string_ PCTSTR Format,
    _In_ va_list VaArg) const noexcept
{
    constexpr int BUFFER_SIZE = 512;

    struct timeval timeVal = {0, 0}; 
    struct tm timeUtc = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    char context[BUFFER_SIZE];
    char message[BUFFER_SIZE];

    memset(context, 0, sizeof(context));
    memset(message, 0, sizeof(message));

    gettimeofday(&timeVal, NULL);
    gmtime_r(&timeVal.tv_sec, &timeUtc);
    
    PCTSTR file = strrchr(File, '/');

    if (file == nullptr)
    {
        file = File;
    }
    else
    {
        ++file;
    }

    const char* format = RESET FORMAT;

    switch (Level)
    {
        case TRACE_LEVEL_CRITICAL:
            format = BRIGHT_RED FORMAT;
            break;

        case TRACE_LEVEL_ERROR:
            format = BRIGHT_RED FORMAT;
            break;

        case TRACE_LEVEL_WARNING:
            format = BRIGHT_YELLOW FORMAT;
            break;

        case TRACE_LEVEL_INFORMATION:
            format = BRIGHT_CYAN FORMAT;
            break;

        case TRACE_LEVEL_VERBOSE:
            format = BRIGHT_MAGENTA FORMAT;
            break;
    
        default:
            format = RESET FORMAT;
            break;
    }
/*
    snprintf(
        context,
        ARRAYSIZE(context) - 1,
        format,
        timeUtc.tm_year + 1900,
        timeUtc.tm_mon + 1,
        timeUtc.tm_mday,
        timeUtc.tm_hour,
        timeUtc.tm_min,
        timeUtc.tm_sec,
        timeVal.tv_usec/1000,
        getpid(),
        syscall(SYS_gettid),
        Level,
        Code,
        file,
        Function,
        Line);
*/
    vsnprintf(
        message,
        ARRAYSIZE(message) - 1,
        Format,
        VaArg);

    fprintf(stderr, "%s%s\n" WHITE, format, message);
};

CrashListener::Logging::SysLog::SysLog(_In_ LONG MaxLevel) : ILog(MaxLevel)
{    
}

CrashListener::Logging::SysLog::~SysLog()
{    
}

void CrashListener::Logging::SysLog::MessageV(
    _In_ LONG Level,
    _In_ LONG Code,
    _In_z_ PCTSTR File,
    _In_z_ PCTSTR Function,
    _In_   ULONG Line,
    _In_z_ _Printf_format_string_ PCTSTR Format,
    _In_ va_list VaArg) const noexcept
{    
    constexpr int BUFFER_SIZE = 1024;

    char message[BUFFER_SIZE];

    int priority = LOG_USER;

    memset(message, 0, sizeof(message));

    vsnprintf(
        message,
        ARRAYSIZE(message) - 1,
        Format,
        VaArg);

    PCTSTR file = strrchr(File, '/');

    if (file == nullptr)
    {
        file = File;
    }
    else
    {
        ++file;
    }

    switch (Level)
    {
    case TRACE_LEVEL_CRITICAL:
        priority |= LOG_CRIT;
        break;

    case TRACE_LEVEL_ERROR:
        priority |= LOG_ERR;
        break;

    case TRACE_LEVEL_WARNING:
        priority |= LOG_WARNING;
        break;

    case TRACE_LEVEL_INFORMATION:
        priority |= LOG_INFO;
        break;

    case TRACE_LEVEL_VERBOSE:
        priority |= LOG_DEBUG;
        break;

    default:
        priority |= LOG_ERR;
        break;
    }

    syslog(
        priority, 
        "%s, %s:%u, last error: %u, %s", 
        file,
        Function,
        Line,
        Code,
        message);
};
