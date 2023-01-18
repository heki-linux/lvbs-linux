#include <Platform.h>
#include <LinLog.h>
#include <LinProcessView.hpp>

using namespace CrashListener::Structures;
using namespace CrashListener::Connectivity;
using namespace CrashListener::Logging;

ConsoleLog g_Log {TRACE_LEVEL_INFORMATION};

void ShowUsageAndExit(const char* ProgramName);

void CreateCoreDump(int ProcessId, const tstring& PreferredPath, CoreDumpFiltering Filtering);
void PrintCallStacks(int ProcessId);

int main(int argc, char** argv)
{
    if (argc < 4)
    {
        ShowUsageAndExit(argv[0]);
    }

    try
    {
        if (strcmp(argv[1], "create") == 0)
        {
            tstring preferredPath;

            preferredPath = argv[3];

            CoreDumpFiltering filtering =
                CoreDumpFiltering::ExcludeShared |
                CoreDumpFiltering::ExcludeExecutable |
                CoreDumpFiltering::ExcludeNonElf |
                CoreDumpFiltering::ExcludeNonAccesible;

            for (auto i = 4; i < argc; ++i)
            {
                if (strcmp(argv[i], "--include-all") == 0)
                {
                    filtering = CoreDumpFiltering::ExcludeNone;
                }
                else if (strcmp(argv[i], "--include-non-elfs") == 0)
                {
                    filtering -= CoreDumpFiltering::ExcludeNonElf;
                }
                else if (strcmp(argv[i], "--include-code") == 0)
                {
                    filtering -= CoreDumpFiltering::ExcludeExecutable;
                }
                else if (strcmp(argv[i], "--include-na") == 0)
                {
                    filtering -= CoreDumpFiltering::ExcludeNonAccesible;
                }
                else if (strcmp(argv[i], "--verbose") == 0)
                {
                    g_Log.SetMaxLevel(TRACE_LEVEL_VERBOSE);
                }
                else
                {
                    ShowUsageAndExit(argv[0]);
                }
            }

            CreateCoreDump(atoi(argv[2]), preferredPath, filtering);
        }
        else if (strcmp(argv[1], "stacks") == 0)
        {
            PrintCallStacks(atoi(argv[2]));

            for (auto i = 3; i < argc; ++i)
            {
                if (strcmp(argv[i], "--verbose") == 0)
                {
                    g_Log.SetMaxLevel(TRACE_LEVEL_VERBOSE);
                }
                else
                {
                    ShowUsageAndExit(argv[0]);
                }
            }
        }
        else
        {
            ShowUsageAndExit(argv[0]);
        }
    }
    catch(const std::exception& e)
    {
        printf("Exception: %s\n", e.what());

        return -1;
    }

    return 0;
}

void ShowUsageAndExit(const char* ProgramName)
{
    printf(
        "If you need to:\n"
        "\tprint call stack information : %1$s stacks <PID>\n"
        "\tcreate core dump file        : %1$s create <PID> core-file-name [options]\n"
        "\t\tOptions for creating dump files:\n"
        "\t\t--include-all      Do include all memory in the process' VA mappings.\n"
        "\t\t                   The default is to exclude non-ELF mapped files, code pages mapped to a file,\n"
        "\t\t                   and virtual memory pages that cannot be accessed.\n"
        "\t\t--include-non-elfs Include non-ELF mapped files.\n"
        "\t\t--include-code     Include code pages (normally available in the binary).\n"
        "\t\t--include-na       Include non-available pages (guard pages, VA reservations).\n",
        ProgramName);

    exit(EXIT_FAILURE);
}

void CreateCoreDump(int ProcessId, const tstring& PreferredPath, CoreDumpFiltering Filtering)
{
    const mode_t accessRights = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
    tstring coreDumpPath;

    coreDumpPath = !PreferredPath.empty() ? PreferredPath :
                        std::string("core.aw.") + std::to_tstring(ProcessId);
    
    ProcessView processView(&g_Log);

    processView.Attach(ProcessId);
    processView.CreateCoreDump(coreDumpPath, accessRights, Filtering);
}

void PrintCallStacks(int ProcessId)
{
    ProcessView processView(&g_Log);

    processView.Attach(ProcessId);
    processView.PrintCallStacks();
}
