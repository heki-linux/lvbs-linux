# pragma once

#include <ILog.h>

namespace CrashListener
{
namespace Logging
{

class ConsoleLog final : public ILog
{
public:
    ConsoleLog(_In_ LONG MaxLevel = LevelLimit);
    ~ConsoleLog() override;

protected:

    void MessageV(
        _In_ LONG Level,
        _In_ LONG Code,
        _In_z_ PCTSTR File,
        _In_z_ PCTSTR Function,
        _In_   ULONG Line,
        _In_z_ _Printf_format_string_ PCTSTR Format,
        _In_ va_list VaArg) const noexcept override;
};

class SysLog final : public ILog
{
public:
    SysLog(_In_ LONG MaxLevel = LevelLimit);
    ~SysLog() override;

protected:

    void MessageV(
        _In_ LONG Level,
        _In_ LONG Code,
        _In_z_ PCTSTR File,
        _In_z_ PCTSTR Function,
        _In_   ULONG Line,
        _In_z_ _Printf_format_string_ PCTSTR Format,
        _In_ va_list VaArg) const noexcept override;
};

}
}
