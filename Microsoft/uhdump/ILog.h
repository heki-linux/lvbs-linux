#pragma once

#include <Platform.h>

namespace CrashListener
{
namespace Logging
{

const LONG LevelLimit = 0xFFFF;

// Base

class ILog
{
public:
    ILog(_In_ LONG MaxLevel) : m_MaxLevel(MaxLevel)
    {
    }

    virtual ~ILog() = default;

#ifdef CL_WINDOWS
#pragma warning(push)
#pragma warning(disable : 4793)
// C4793: function compiled as native
#endif
    void Message(
        _In_ LONG Level,
        _In_ LONG Code,
        _In_z_ PCTSTR File,
        _In_z_ PCTSTR Function,
        _In_   ULONG Line,
        _In_z_ _Printf_format_string_ PCTSTR Format, ...) const noexcept
    {
        if (Level > m_MaxLevel)
        {
            return;
        }

        va_list argPtr;
        va_start(argPtr, Format);

        MessageV(Level, Code, File, Function, Line, Format, argPtr);

        va_end(argPtr);
    }        
#ifdef CL_WINDOWS
#pragma warning(pop)
#endif
    void SetMaxLevel(_In_ LONG MaxLevel)
    {
        m_MaxLevel = MaxLevel;
    }

    LONG GetMaxLevel() const
    {
        return m_MaxLevel;
    }

protected:

    virtual void MessageV(
        _In_ LONG Level,
        _In_ LONG Code,
        _In_z_ PCTSTR File,
        _In_z_ PCTSTR Function,
        _In_   ULONG Line,
        _In_z_ _Printf_format_string_ PCTSTR Format,
        _In_ va_list VaArg) const noexcept = 0;

private:
    LONG m_MaxLevel;
};

// Does nothing

class NullLog final : public ILog
{
public:
    NullLog() : ILog(0)
    {        
    }

protected:
#ifdef CL_WINDOWS
#pragma warning(push)
#pragma warning(disable : 4793)
// C4793: function compiled as native
#endif
    void MessageV(
        _In_ LONG Level,
        _In_ LONG Code,
        _In_z_ PCTSTR File,
        _In_z_ PCTSTR Function,
        _In_   ULONG Line,
        _In_z_ _Printf_format_string_ PCTSTR Format,
        _In_ va_list VaArg) const noexcept override
    {        
        UNREFERENCED_PARAMETER(Level);
        UNREFERENCED_PARAMETER(Code);
        UNREFERENCED_PARAMETER(File);
        UNREFERENCED_PARAMETER(Function);
        UNREFERENCED_PARAMETER(Line);
        UNREFERENCED_PARAMETER(Format);
        UNREFERENCED_PARAMETER(VaArg);
    }
#ifdef CL_WINDOWS
#pragma warning(pop)
#endif
};

}
}

#define CL_LOG(LogInstancePtr, Level, Code, ...) \
    if ((Level) <= (LogInstancePtr)->GetMaxLevel()) \
    { \
        /* Uncomment for the format parameter checking */ \
        /* 0 ? printf(__VA_ARGS__) : 0,*/ \
        (LogInstancePtr)->Message((Level), (Code), __TFILE__, __TFUNCTION__, __LINE__, __VA_ARGS__); \
    }; 

#define CL_LOG_ENTERED(LogInstancePtr) CL_LOG((LogInstancePtr), TRACE_LEVEL_VERBOSE, S_OK, TEXT("Entered"))
#define CL_INFO(LogInstancePtr, ...) CL_LOG((LogInstancePtr), TRACE_LEVEL_INFORMATION, S_OK, __VA_ARGS__)
