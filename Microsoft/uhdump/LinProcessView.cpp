#include <LinProcessView.hpp>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/signal.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <linux/elf.h>
#include <linux/auxvec.h>

struct Elf64_Auxv
{
    uint64_t a_type; // from auxvec.h
    union
    {
        uint64_t a_val;
    } a_un;
};

#pragma pack(push)

#pragma pack(1)

struct MappedFilesNoteIntro
{
    uint64_t m_FileCount;
    uint64_t m_PageSize;
};

struct MappedFilesNoteItem
{
    uint64_t m_StartAddr;
    uint64_t m_EndAddr;
    uint64_t m_PageCount;
};

#pragma pack(pop)

constexpr inline int Endianness() 
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return 0;
#elif __BYTE_ORDER == __BIG_ENDIAN
    return 1;
#else
    int probe = 1;

    return !*(char*)&probe; // Not constexpr, strictly speaking
#endif    
}

inline size_t RoundUp(size_t Value, size_t Alignment)
{
    if (Value == 0)
    {
        return 0;
    }

    return Value % Alignment != 0 ? (Value + Alignment)/Alignment*Alignment : Value;
}

// number of AT_* except AT_NULL, AT_IGNORE, AT_NOTELF

#define AT_VECTOR_SIZE_BASE 20

#ifndef AT_VECTOR_SIZE_ARCH
#define AT_VECTOR_SIZE_ARCH 0
#endif

#define AT_VECTOR_SIZE (2*(AT_VECTOR_SIZE_ARCH + AT_VECTOR_SIZE_BASE + 1))

using namespace CrashListener::Logging;
using namespace CrashListener::Structures;

ssize_t SureRead(int FileDesc, void* Buffer, size_t BufferSize)
{
    ssize_t totalBytesRead = 0;

    while ((size_t)totalBytesRead < BufferSize)
    {
        ssize_t bytesRead = 0;

        do
        {
            bytesRead = read(FileDesc, (char*)Buffer + totalBytesRead, BufferSize - totalBytesRead);
        }
        while (bytesRead < 0 && errno == EINTR);

        if (bytesRead < 0 && errno != EINTR)
        {
            totalBytesRead = bytesRead;
            
            break;
        }

        if (bytesRead == 0)
        {
            break;
        }

        totalBytesRead += bytesRead;
    }

    return totalBytesRead;
}

ssize_t SureWrite(int FileDesc, const void* Buffer, size_t BufferSize)
{
    ssize_t totalBytesWritten = 0;

    while ((size_t)totalBytesWritten < BufferSize)
    {
        ssize_t bytesWritten = 0;

        do
        {
            bytesWritten = write(FileDesc, (const char*)Buffer + totalBytesWritten, BufferSize - totalBytesWritten);
        }
        while (bytesWritten < 0 && errno == EINTR);

        if (bytesWritten < 0 && errno != EINTR)
        {
            totalBytesWritten = bytesWritten;
            
            break;
        }

        totalBytesWritten += bytesWritten;
    }

    return totalBytesWritten;
}

ssize_t AlignFilePosition(int FileDesc, size_t Alignment)
{
    const auto position = lseek(FileDesc, 0, SEEK_CUR);
    const auto paddedPosition = RoundUp(position, Alignment);

    int result = ftruncate(FileDesc, paddedPosition);

    if (result < 0)
    {
        return result;
    }

    result = lseek(FileDesc, paddedPosition, SEEK_SET);

    if (result < 0)
    {
        return result;
    }

    return paddedPosition - position;
}

ProcessView::ProcessView(const ILog* Logger) 
        : 
        m_Logger(Logger), 
        m_ProcessId(0), 
        m_Attached(false), 
        m_MemFileDesc(0), 
        m_AuxVectorSize(0),
        m_Vdso(0),
        m_NoteHeaderAndNameRoundUp(0),
        m_ProcessInfoNoteSize(0),
        m_ProcessStatusNoteSize(0),
        m_AuxVectorNoteSize(0),
        m_MappedFileNoteSize(0),
        m_TotalNoteSize(0),
        c_PageSize(sysconf(_SC_PAGESIZE)), 
        c_HeaderAlign(8), 
        c_NotePadding(8)
{        
}

void ProcessView::Attach(int ProcessId)
{
    if (m_Attached)
    {
        Detach();
    }

    m_ProcessId = ProcessId;

    const auto threadIds = GetThreadIds();

    for (const auto threadId : threadIds)
    {
        CL_LOG(
            m_Logger,
            TRACE_LEVEL_INFORMATION,
            S_OK,
            "Seizing thread %d...",
            threadId);

        int result = ptrace((__ptrace_request)PTRACE_SEIZE, threadId, NULL, NULL);
        if (result < 0)
        {
            throw std::system_error(errno, std::generic_category(), "Unable to attach to the pid specified");
        }

        CL_LOG(
            m_Logger,
            TRACE_LEVEL_INFORMATION,
            S_OK,
            "Interrupting thread %d...",
            threadId);

        result = ptrace((__ptrace_request)PTRACE_INTERRUPT, threadId, NULL, NULL);
        if (result < 0)
        {
            throw std::system_error(errno, std::generic_category(), "Unable to interrupt the pid specified");
        }

        if (waitpid(threadId, NULL, 0) != threadId)
        {
            throw std::system_error(errno, std::generic_category(), "Unable to wait for the pid specified");
        }        

        m_AttachedThreads[threadId] = BuildThreadView(threadId);
    }

    OpenMemFile();

    m_Attached = true;
}

void ProcessView::Detach()
{
    close(m_MemFileDesc);
    m_MemFileDesc = 0;

    m_AttachedThreads.clear();
    m_VaRegions.clear();
    m_MappedFiles.clear();

    const auto threadIds = GetThreadIds();

    for (const auto threadId : threadIds)
    {
        CL_LOG(
            m_Logger,
            TRACE_LEVEL_INFORMATION,
            S_OK,
            "Resuming thread %d...",
            threadId);

        int result = ptrace((__ptrace_request)PTRACE_DETACH, threadId, NULL, NULL);        
        if (result < 0)
        {
            throw std::system_error(errno, std::generic_category(), "Unable to detach from the process");
        }
    }

    m_AuxVectorSize = 0;

    m_NoteHeaderAndNameRoundUp = 0;
    m_ProcessInfoNoteSize = 0;
    m_ProcessStatusNoteSize = 0;
    m_AuxVectorNoteSize = 0;
    m_MappedFileNoteSize = 0;
    m_TotalNoteSize = 0;

    m_Vdso = 0;

    m_Attached = false;
}

void ProcessView::CreateCoreDump(const tstring& CoreDumpFileName, mode_t Permissions, CoreDumpFiltering Filtering)
{
    size_t totalWritten = 0;

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        TEXT("Creating core dump file %s for process %d"),
        CoreDumpFileName.c_str(),            
        m_ProcessId);

    if (!m_Attached)
    {
        throw std::logic_error("Need to attach to the process first");
    }

    if (m_MemFileDesc < 0)
    {
        throw std::runtime_error("The memory file for the process is not available");
    }

    GetAuxVectorSize();

    GetVaRegions(Filtering);

    GetNotesSize();

    int outputFile = STDOUT_FILENO;

    if (!CoreDumpFileName.empty() && CoreDumpFileName != "--")
    {
        outputFile = open(CoreDumpFileName.c_str(), O_CREAT | O_RDWR, Permissions);
        if (outputFile < 0)
        {
            throw std::system_error(errno, std::generic_category(), "Cannot open the core dump file");
        }
    }

    try
    {
        totalWritten += WriteElfHeader(outputFile);
        totalWritten += AlignFilePosition(outputFile, c_HeaderAlign);

        totalWritten += WriteProgramHeaders(outputFile);
        totalWritten += AlignFilePosition(outputFile, c_HeaderAlign);

        totalWritten += WriteNotes(outputFile);
        totalWritten += AlignFilePosition(outputFile, c_PageSize);

        totalWritten += WriteVaRegions(outputFile);        
    }
    catch(...)
    {
        close(outputFile);            

        throw;
    }        

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Wrote %lu bytes for ELF core dump %s",
        totalWritten,
        CoreDumpFileName.c_str());

    close(outputFile);
}

void ProcessView::PrintCallStacks()
{
    GetVaRegions(CoreDumpFiltering::ExcludeNonAccesible);

    for (const auto& [threadId, threadStatus] : m_AttachedThreads)
    {
        const auto r15 = threadStatus->m_Status.pr_reg[0];
        const auto r14 = threadStatus->m_Status.pr_reg[1];
        const auto r13 = threadStatus->m_Status.pr_reg[2];
        const auto r12 = threadStatus->m_Status.pr_reg[3];
        const auto rbp = threadStatus->m_Status.pr_reg[4];
        const auto rbx = threadStatus->m_Status.pr_reg[5];
        const auto r11 = threadStatus->m_Status.pr_reg[6];
        const auto r10 = threadStatus->m_Status.pr_reg[7];
        const auto r9 = threadStatus->m_Status.pr_reg[8];
        const auto r8 = threadStatus->m_Status.pr_reg[9];
        const auto rax = threadStatus->m_Status.pr_reg[10];
        const auto rcx = threadStatus->m_Status.pr_reg[11];
        const auto rdx = threadStatus->m_Status.pr_reg[12];
        const auto rsi = threadStatus->m_Status.pr_reg[13];
        const auto rdi = threadStatus->m_Status.pr_reg[14];
        // const auto orig_rax = threadStatus->m_Status.pr_reg[15];
        const auto rip = threadStatus->m_Status.pr_reg[16];
        // const auto cs = threadStatus->m_Status.pr_reg[17];
        const auto rflags = threadStatus->m_Status.pr_reg[18];
        const auto rsp = threadStatus->m_Status.pr_reg[19];
        // const auto ss = threadStatus->m_Status.pr_reg[20];
        // const auto fs_base = threadStatus->m_Status.pr_reg[0];
        // const auto gs_base = threadStatus->m_Status.pr_reg[0];
        // const auto ds = threadStatus->m_Status.pr_reg[0];
        // const auto es = threadStatus->m_Status.pr_reg[0];
        // const auto fs = threadStatus->m_Status.pr_reg[0];
        // const auto gs = threadStatus->m_Status.pr_reg[0];

        CL_LOG(
            m_Logger,
            TRACE_LEVEL_INFORMATION,
            S_OK,
            "Thread %ld:\n\tr15 %016llx r14 %016llx r13 %016llx r12 %016llx\n\trbp %016llx rbx %016llx r11 %016llx"
            " r10 %016llx\n\tr9  %016llx r8  %016llx rax %016llx rcx %016llx\n\trdx %016llx rsi %016llx rdi %016llx"
            " rip %016llx\n\trflags %016llx rsp %016llx",
            threadId, 
            r15, r14, r13, r12, rbp, rbx, r11,
            r10, r9, r8, rax, rcx, rdx, rsi, rdi,
            rip, rflags, rsp);

        // TODO romank: Bad O(n^2)
        for (const auto& region : m_VaRegions)
        {
            uint64_t rva;

            if (region.m_Start <= rip && rip <= region.m_End && !region.m_MappedFileName.empty())
            {
                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_INFORMATION,
                    S_OK,
                    "\t          rip: 0x%016llx rva: 0x%016llx file: %s",
                    rip,
                    rip - region.m_Start + region.m_Offset,
                    region.m_MappedFileName.c_str());

                break;
            }
        }

        // TODO romank: look for the VA region rsp belongs to to find the stack start
        uint64_t stack[256] = {};

        const auto bytesRead = pread64(m_MemFileDesc, &stack, sizeof(stack), rsp);

        for (auto stackFrame = 0; stackFrame < ARRAYSIZE(stack); ++stackFrame)
        {
            const auto maybeCodeAddr = stack[stackFrame];
            bool likelyCode = false;
            tstring moduleName;
            uint64_t rva = 0;

            // TODO romank: Bad O(n^2)
            for (const auto& region : m_VaRegions)
            {
                if (region.m_Start <= maybeCodeAddr && maybeCodeAddr <= region.m_End && !region.m_MappedFileName.empty())
                {
                    likelyCode = true;
                    rva = maybeCodeAddr - region.m_Start + region.m_Offset;
                    moduleName = region.m_MappedFileName;
                    break;
                }
            }

            if (likelyCode)
            {
                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_INFORMATION,
                    S_OK,
                    "\t[rsp + 0x%03llx]: 0x%016llx rva: 0x%016llx file: %s",
                    stackFrame*sizeof(stack[0]), maybeCodeAddr, rva, moduleName.c_str());
            }
        }
    }
}

ProcessView::~ProcessView()
{
    if (m_Attached)
    {
        Detach();
    }
}

void ProcessView::DumpElfHeaders(std::uint64_t MemDescOffset)
{
    Elf64_Ehdr elfHeader {};

    const char* elfTypeStr = "?";
    const char* elfMachineStr = "?";

    const auto bytesRead = pread64(m_MemFileDesc, &elfHeader, sizeof(elfHeader), MemDescOffset);
    const auto isMappedElfHeader = bytesRead == sizeof(elfHeader) &&
        elfHeader.e_ident[EI_MAG0] == ELFMAG0 &&
        elfHeader.e_ident[EI_MAG1] == ELFMAG1 &&
        elfHeader.e_ident[EI_MAG2] == ELFMAG2 &&
        elfHeader.e_ident[EI_MAG3] == ELFMAG3 &&
        elfHeader.e_ident[EI_VERSION] == EV_CURRENT &&
        elfHeader.e_ehsize == sizeof(elf64_hdr) &&
        (elfHeader.e_type == ET_EXEC || elfHeader.e_type == ET_DYN) &&
        elfHeader.e_phentsize == sizeof(elf64_phdr) &&
#ifdef __amd64
        elfHeader.e_machine == EM_X86_64;
#endif
#ifdef __aarch64__                    
        elfHeader.e_machine == EM_AARCH64;
#endif

    if (!isMappedElfHeader)
    {
        return;
    }

    switch (elfHeader.e_type)
    {
    case ET_NONE:
        elfTypeStr = "NONE";
        break;
    case ET_REL:
        elfTypeStr = "REL";
        break;
    case ET_EXEC:
        elfTypeStr = "EXEC";
        break;
    case ET_DYN:
        elfTypeStr = "DYN";
        break;
    case ET_CORE:
        elfTypeStr = "CORE";
        break;
    default:
        break;
    }

    switch (elfHeader.e_machine)
    {
    case EM_386:
        elfMachineStr = "x86";
        break;
    case EM_X86_64:
        elfMachineStr = "x86_64";
        break;
    case EM_AARCH64:
        elfMachineStr = "AArch64";
        break;
    default:
        break;
    }

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "ELF OS ABI %#x, type %s, machine %s",
        elfHeader.e_ident[EI_OSABI],
        elfTypeStr,
        elfMachineStr
    );

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "ELF Object file version: %#x\n\tentry point address: %#llx\n\t"
        "program header offset: %#llx\n\t"
        "section header offset: %#llx\n\t"
        "processor-specific flags: %#llx\n\t"
        "size of program header entry: %#llx\n\t"
        "number of program header entries (segments): %#llx\n\t"
        "size of section header entry: %#llx\n\t"
        "number of section header entries: %#llx\n\t"
        "index of the string table section: %#llx",
        elfHeader.e_version,
        elfHeader.e_entry,
        elfHeader.e_phoff,
        elfHeader.e_shoff,
        elfHeader.e_flags,
        elfHeader.e_phentsize,
        elfHeader.e_phnum,
        elfHeader.e_shentsize,
        elfHeader.e_shnum,
        elfHeader.e_shstrndx);

    if (elfHeader.e_shstrndx >= elfHeader.e_shnum)
    {
        throw std::runtime_error("Invalid index of the string table section");
    }

    if (elfHeader.e_phentsize != sizeof(Elf64_Phdr))
    {
        throw std::runtime_error("Invalid size of the program header's entry size");
    }

    if (elfHeader.e_shentsize != sizeof(Elf64_Shdr))
    {
        throw std::runtime_error("Invalid size of the program header's entry size");
    }

    for (uint32_t i = 0; i < elfHeader.e_phnum; ++i)
    {
        Elf64_Phdr segmentHeader {};
        
        const char* segmentTypeName = "?";
        char  segmentRwx[4] = {'-', '-', '-', '\x0'};

        const auto bytesRead = pread64(
            m_MemFileDesc, 
            &segmentHeader,
            sizeof(segmentHeader),
            MemDescOffset + elfHeader.e_phoff + i*sizeof(Elf64_Phdr));

        switch (segmentHeader.p_type)
        {
            case PT_NULL:
                segmentTypeName = "NULL";
                break;
            case PT_LOAD:
                segmentTypeName = "LOAD";
                break;
            case PT_DYNAMIC:
                segmentTypeName = "DYNAMIC";
                break;
            case PT_INTERP:
                segmentTypeName = "INTERP";
                break;
            case PT_NOTE:
                segmentTypeName = "NOTE";
                break;
            case PT_SHLIB:
                segmentTypeName = "SHLIB";
                break;
            case PT_PHDR:
                segmentTypeName = "PHDR";
                break;
            case PT_TLS:
                segmentTypeName = "TLS";
                break;
            case PT_GNU_EH_FRAME:
                segmentTypeName = "GNU_EH_FRAME";
                break;
            case PT_GNU_STACK:
                segmentTypeName = "GNU_STACK";
                break;

            default:
                break;        
        }

        if (segmentHeader.p_flags & PF_X)
        {
            segmentRwx[2] = 'X';
        }
        if (segmentHeader.p_flags & PF_R)
        {
            segmentRwx[0] = 'R';
        }
        if (segmentHeader.p_flags & PF_W)
        {
            segmentRwx[1] = 'W';
        }

        CL_LOG(
            m_Logger,
            TRACE_LEVEL_VERBOSE,
            S_OK,
            "Segment: %d\n\tsegment type: %s(%#x)\n\t"
            "segment flags: %s(%#x)\n\t"
            "offset in file: %#x\n\t"
            "virtual address in memory: %#x\n\t"
            "physical address: %#x\n\t"
            "size of segment in file: %#x\n\t"
            "size of segment in memory: %#x\n\t"
            "alignment of segment: %#x",
            i,
            segmentTypeName,
            segmentHeader.p_type,
            segmentRwx,
            segmentHeader.p_flags,
            segmentHeader.p_offset,
            segmentHeader.p_vaddr,
            segmentHeader.p_paddr,
            segmentHeader.p_filesz,
            segmentHeader.p_memsz,
            segmentHeader.p_align);
    }
}

void ProcessView::GetVaRegions(CoreDumpFiltering Filtering)
{
    char mapsFilename[PATH_MAX];
    sprintf(mapsFilename, "/proc/%d/maps", m_ProcessId);

    FILE* mapsFile = fopen(mapsFilename, "rt");
    if (mapsFile == nullptr)
    {
        throw std::system_error(errno, std::generic_category(), "Cannot open memory maps");
    }

    std::set<tstring> mappedNonElfFiles;
    std::set<tstring> mappedElfFiles;

    char line[256];
    while (fgets(line, sizeof(line), mapsFile) != nullptr)
    {
        line[strcspn(line, "\n")] = 0;

        uint64_t startAddress = 0;
        uint64_t endAddress = 0;
        uint64_t offset = 0;
        VaRegionProtection protection = VaRegionProtection::Unspecified;

        const auto endAddrEnd = strchr(line, ' ');
        const auto startAddrEnd = strchr(line, '-');
        const auto fileNameStart = strchr(line, '/');
        const bool isVdso = strstr(line, "[vdso]");       

        if (startAddrEnd == nullptr || endAddrEnd == nullptr)
        {
            continue;
        }

        startAddress = strtoul(line, nullptr, 16);
        endAddress   = strtoul(startAddrEnd+1, nullptr, 16);
        offset       = strtoul(endAddrEnd+6, nullptr, 16);

        // r w x s|p

        if (endAddrEnd[1] == 'r')
        {
            protection |= VaRegionProtection::Read;
        }
        if (endAddrEnd[2] == 'w')
        {
            protection |= VaRegionProtection::Write;
        }
        if (endAddrEnd[3] == 'x')
        {
            protection |= VaRegionProtection::Execute;
        }
        if (endAddrEnd[4] == 's')
        {
            protection |= VaRegionProtection::Shared;
        }
        if (endAddrEnd[4] == 'p')
        {
            protection |= VaRegionProtection::Private;
        }

        VaRegion region {startAddress, endAddress, offset, protection, fileNameStart ? fileNameStart : ""};

        if (region.m_MappedFileName.compare(0, 5, "/dev/") == 0)
        {
            CL_LOG(
                m_Logger,
                TRACE_LEVEL_INFORMATION,
                S_OK,
                "Skipping device VA region 0x%lx-0x%lx, offset 0x%lx, size: 0x%lx, protection: %s, mapped to %s", 
                region.m_Start, 
                region.m_End, 
                region.m_Offset,
                endAddress - startAddress,
                region.GetProtectionStr().c_str(),
                region.m_MappedFileName.c_str());

            continue;
        }

        if ((Filtering & CoreDumpFiltering::ExcludeNonAccesible) &&
            (region.m_Protection == VaRegionProtection::Private))
        {
            CL_LOG(
                m_Logger,
                TRACE_LEVEL_INFORMATION,
                S_OK,
                "Skipping non-accesible VA region 0x%lx-0x%lx, offset 0x%lx, size: 0x%lx, protection: %s", 
                region.m_Start, 
                region.m_End, 
                region.m_Offset,
                endAddress - startAddress,
                region.GetProtectionStr().c_str());

            continue;
        }

        auto inNonElfFragments = [&region = std::as_const(region), &mappedNonElfFiles = std::as_const(mappedNonElfFiles)]()
        {
            return !region.m_MappedFileName.empty() && mappedNonElfFiles.find(region.m_MappedFileName) != mappedNonElfFiles.end();
        };

        auto inElfFragments = [&region = std::as_const(region), &mappedElfFiles = std::as_const(mappedElfFiles)]()
        {
            return !region.m_MappedFileName.empty() && mappedElfFiles.find(region.m_MappedFileName) != mappedElfFiles.end();
        };
        
        auto isMappedElfHeader = false;
        if (!inNonElfFragments() && !inElfFragments())
        {
            // Have not seen that file before, check if that's an ELF

            Elf64_Ehdr elfHeader;

            const auto bytesRead = pread64(m_MemFileDesc, &elfHeader, sizeof(elfHeader), region.m_Start);

            isMappedElfHeader = bytesRead == sizeof(elfHeader) &&
                elfHeader.e_ident[EI_MAG0] == ELFMAG0 &&
                elfHeader.e_ident[EI_MAG1] == ELFMAG1 &&
                elfHeader.e_ident[EI_MAG2] == ELFMAG2 &&
                elfHeader.e_ident[EI_MAG3] == ELFMAG3 &&
                elfHeader.e_ident[EI_VERSION] == EV_CURRENT &&
                elfHeader.e_ehsize == sizeof(elf64_hdr) &&
                (elfHeader.e_type == ET_EXEC || elfHeader.e_type == ET_DYN) &&
                elfHeader.e_phentsize == sizeof(elf64_phdr) &&
#ifdef __amd64
                elfHeader.e_machine == EM_X86_64;
#endif
#ifdef __aarch64__                    
                elfHeader.e_machine == EM_AARCH64;
#endif
            if (isMappedElfHeader)
            {
                mappedElfFiles.insert(region.m_MappedFileName);

                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_VERBOSE,
                    S_OK,
                    "ELF header: VA region 0x%lx-0x%lx, offset 0x%lx, size: 0x%lx, protection: %s, mapped to %s", 
                    region.m_Start, 
                    region.m_End, 
                    region.m_Offset,
                    endAddress - startAddress,
                    region.GetProtectionStr().c_str(),
                    region.m_MappedFileName.c_str());
                
                //DumpElfHeaders(region.m_Start);
            }
            else
            {
                mappedNonElfFiles.insert(region.m_MappedFileName);
            }
        }

        if ((Filtering & CoreDumpFiltering::ExcludeNonElf) && inNonElfFragments()) 
        {
            CL_LOG(
                m_Logger,
                TRACE_LEVEL_INFORMATION,
                S_OK,
                "Skipping non-ELF mapped file: VA region 0x%lx-0x%lx, offset 0x%lx, size: 0x%lx, protection: %s, mapped to %s", 
                region.m_Start, 
                region.m_End, 
                region.m_Offset,
                endAddress - startAddress,
                region.GetProtectionStr().c_str(),
                region.m_MappedFileName.c_str());

            continue;
        }                

        if (!region.m_MappedFileName.empty() &&             // Do not exclude vDSO at least
            (Filtering & CoreDumpFiltering::ExcludeExecutable) && 
            (protection & VaRegionProtection::Execute))
        {
            CL_LOG(
                m_Logger,
                TRACE_LEVEL_INFORMATION,
                S_OK,
                "Skipping executable VA region 0x%lx-0x%lx, offset 0x%lx, size: 0x%lx, protection: %s, mapped to %s", 
                region.m_Start, 
                region.m_End, 
                region.m_Offset,
                endAddress - startAddress,
                region.GetProtectionStr().c_str(),
                region.m_MappedFileName.c_str());

            continue;
        }

        // For the future: better yet, go parse the ELF file, find .rodata sections, and exclude these

        if ((Filtering & CoreDumpFiltering::ExcludeReadOnly)                            && 
            (protection == (VaRegionProtection::Read | VaRegionProtection::Private) || 
             protection == (VaRegionProtection::Read | VaRegionProtection::Shared))     &&
            !region.m_MappedFileName.empty()                                            && 
            !isMappedElfHeader)
        {
            CL_LOG(
                m_Logger,
                TRACE_LEVEL_INFORMATION,
                S_OK,
                "Skipping read-only VA region 0x%lx-0x%lx, offset 0x%lx, size: 0x%lx, protection: %s, mapped to %s", 
                region.m_Start, 
                region.m_End, 
                region.m_Offset,
                endAddress - startAddress,
                region.GetProtectionStr().c_str(),
                region.m_MappedFileName.c_str());

            continue;
        }

        m_VaRegions.push_back(region);

        if (!region.m_MappedFileName.empty() && region.m_MappedFileName.front() == '/')
        {
            auto fileNameIter = m_MappedFiles.end();
            if ((fileNameIter = m_MappedFiles.find(region.m_MappedFileName)) != m_MappedFiles.end())
            {
                auto& regionList = fileNameIter->second;
                auto& lastAdded = regionList.back();

                if (lastAdded.m_End == region.m_Start)
                {
                    lastAdded.m_End = region.m_End;
                }
                else
                {
                    regionList.push_back(VaRange(region.m_Start, region.m_End, region.m_Offset));
                }
            }
            else
            {
                m_MappedFiles[region.m_MappedFileName] = { VaRange(region.m_Start, region.m_End, region.m_Offset) };
            }
        }

        CL_LOG(
            m_Logger,
            TRACE_LEVEL_VERBOSE,
            S_OK,
            "Adding VA region 0x%lx-0x%lx, offset 0x%lx, size: 0x%lx, protection: %s, mapped to %s", 
            region.m_Start, 
            region.m_End, 
            region.m_Offset,
            endAddress - startAddress,
            region.GetProtectionStr().c_str(),
            region.m_MappedFileName.c_str());

        if (isVdso)
        {
            m_Vdso = region.m_Start;

            CL_LOG(
                m_Logger,
                TRACE_LEVEL_INFORMATION,
                S_OK,
                "vDSO address from the memory maps: 0x%lx",
                m_Vdso);
        }
    }

    fclose(mapsFile);

    std::sort(
        m_VaRegions.begin(), 
        m_VaRegions.end(), 
        [](const VaRegion& lhs, const VaRegion& rhs) 
           {
               return lhs < rhs;
           }
        );
}

std::vector<pid_t> ProcessView::GetThreadIds() const
{
    std::vector<pid_t> threadIds;

    char taskDir[PATH_MAX];

    sprintf(taskDir, "/proc/%d/task", m_ProcessId);

    DIR *d = opendir(taskDir);

    if (d == nullptr)
    {
        throw std::system_error(errno, std::generic_category(), "Error when enumerating threads");
    }

    struct dirent* findData = readdir(d);

    do
    {
        if (findData->d_type == DT_DIR && 
            (_tcscmp(findData->d_name, ".") == 0 ||
             _tcscmp(findData->d_name, "..") == 0))
        {
            continue;
        }

        threadIds.push_back(atoi(findData->d_name));
    } 
    while ((findData = readdir(d)) != nullptr);

    closedir(d); 
    
    return threadIds;
}

// Threads in Linux are LWP aka Light-Weight Processes

std::shared_ptr<ThreadView> ProcessView::BuildThreadView(pid_t ThreadId) const
{
    std::shared_ptr<ThreadView> view = std::make_unique<ThreadView>();

    auto& info = view->m_Info;
    auto& status = view->m_Status;
    auto& signalInfo = view->m_SignalInfo;

    // Get process Information

    {
        const char* processStates = "RSDTZW";

        int pid;                        // %d
                                        // The process ID.
        char comm[256];                 // %s
                                        // The filename of the executable, in parentheses.
                                        // This is visible whether or not the executable is
                                        // swapped out.
        char state;                     // %c
                                        // One of the following characters, indicating process
                                        // state:
                                        //          R  Running
                                        //          S  Sleeping in an interruptible wait
                                        //          D  Waiting in uninterruptible disk sleep
                                        //          Z  Zombie
                                        //          T  Stopped (on a signal) or (before Linux 2.6.33)
                                        //             trace stopped
                                        //          t  Tracing stop (Linux 2.6.33 onward)
                                        //          W  Paging (only before Linux 2.6.0)
                                        //          X  Dead (from Linux 2.6.0 onward)
                                        //          x  Dead (Linux 2.6.33 to 3.13 only)
                                        //          K  Wakekill (Linux 2.6.33 to 3.13 only)
                                        //          W  Waking (Linux 2.6.33 to 3.13 only)
                                        //          P  Parked (Linux 3.9 to 3.13 only)
        int ppid;                       // %d
                                        // The PID of the parent of this process.
        int pgrp;                       // %d
                                        // The process group ID of the process.
        int session;                    // %d
                                        // The session ID of the process.
        int tty_nr;                     // %d
                                        // The controlling terminal of the process.  (The minor
                                        // device number is contained in the combination of
                                        // bits 31 to 20 and 7 to 0; the major device number is
                                        // in bits 15 to 8.)
        int tpgid;                      // %d 
                                        // The ID of the foreground process group of the con‐
                                        // trolling terminal of the process.
        unsigned int flags;             // %u
                                        // The kernel flags word of the process.  For bit mean‐
                                        // ings, see the PF_* defines in the Linux kernel
                                        // source file include/linux/sched.h.  Details depend
                                        // on the kernel version.
                                        // The format for this field was %lu before Linux 2.6.
        unsigned long minflt;           // %lu
                                        // The number of minor faults the process has made
                                        // which have not required loading a memory page from
                                        // disk.
        unsigned long cminflt;          // %lu
                                        // The number of minor faults that the process's
                                        // waited-for children have made.
        unsigned long majflt;           // %lu 
                                        // The number of major faults the process has made
                                        // which have required loading a memory page from disk.
        unsigned long cmajflt;          // %lu
                                        // The number of major faults that the process's
                                        // waited-for children have made.
        unsigned long utime;            // %lu 
                                        // Amount of time that this process has been scheduled
                                        // in user mode, measured in clock ticks (divide by
                                        // sysconf(_SC_CLK_TCK)).  This includes guest time,
                                        // guest_time (time spent running a virtual CPU, see
                                        // below), so that applications that are not aware of
                                        // the guest time field do not lose that time from
                                        // their calculations.
        unsigned long stime;            // %lu 
                                        // Amount of time that this process has been scheduled
                                        // in kernel mode, measured in clock ticks (divide by
                                        // sysconf(_SC_CLK_TCK)).
        unsigned long cutime;           // %ld 
                                        // Amount of time that this process's waited-for chil‐
                                        // dren have been scheduled in user mode, measured in
                                        // clock ticks (divide by sysconf(_SC_CLK_TCK)).  (See
                                        // also times(2).)  This includes guest time,
                                        // cguest_time (time spent running a virtual CPU, see
                                        // below).
        unsigned long cstime;           // %ld
                                        // Amount of time that this process's waited-for chil‐
                                        // dren have been scheduled in kernel mode, measured in
                                        // clock ticks (divide by sysconf(_SC_CLK_TCK)).
        unsigned long priority;         // %ld 
                                        // (Explanation for Linux 2.6) For processes running a
                                        // real-time scheduling policy (policy below; see
                                        // sched_setscheduler(2)), this is the negated schedul‐
                                        // ing priority, minus one; that is, a number in the
                                        // range -2 to -100, corresponding to real-time priori‐
                                        // ties 1 to 99.  For processes running under a non-
                                        // real-time scheduling policy, this is the raw nice
                                        // value (setpriority(2)) as represented in the kernel.
                                        // The kernel stores nice values as numbers in the
                                        // range 0 (high) to 39 (low), corresponding to the
                                        // user-visible nice range of -20 to 19.
                                        // Before Linux 2.6, this was a scaled value based on
                                        // the scheduler weighting given to this process.
        unsigned long nice;             // %ld
                                        // The nice value (see setpriority(2)), a value in the
                                        // range 19 (low priority) to -20 (high priority).
        unsigned long num_threads;      // %ld
                                        // Number of threads in this process (since Linux 2.6).
                                        // Before kernel 2.6, this field was hard coded to 0 as
                                        // a placeholder for an earlier removed field.
        unsigned long itrealvalue;      // %ld
                                        // The time in jiffies before the next SIGALRM is sent
                                        // to the process due to an interval timer.  Since ker‐
                                        // nel 2.6.17, this field is no longer maintained, and
                                        // is hard coded as 0.
        unsigned long long starttime;   // %llu
                                        // The time the process started after system boot.  In
                                        // kernels before Linux 2.6, this value was expressed
                                        // in jiffies.  Since Linux 2.6, the value is expressed
                                        // in clock ticks (divide by sysconf(_SC_CLK_TCK)).
                                        // The format for this field was %lu before Linux 2.6.
        unsigned long vsize;            // %lu
                                        // Virtual memory size in bytes.
        unsigned long rss;              // %ld
                                        // Resident Set Size: number of pages the process has
                                        // in real memory.  This is just the pages which count
                                        // toward text, data, or stack space.  This does not
                                        // include pages which have not been demand-loaded in,
                                        // or which are swapped out.
        unsigned long rsslim;           // %lu
                                        // Current soft limit in bytes on the rss of the
                                        // process; see the description of RLIMIT_RSS in
                                        // getrlimit(2).
        unsigned long startcode;        // %lu  [PT]
                                        // The address above which program text can run.
        unsigned long endcode;          // %lu  [PT]
                                        // The address below which program text can run.
        unsigned long startstack;       // %lu  [PT]
                                        // The address of the start (i.e., bottom) of the
                                        // stack.
        unsigned long kstkesp;          // %lu  [PT]
                                        // The current value of ESP (stack pointer), as found
                                        // in the kernel stack page for the process.
        unsigned long kstkeip;          // %lu  [PT]
                                        // The current EIP (instruction pointer).

        char statStr[1024];

        {
            char statFilename[256];
            sprintf(statFilename, "/proc/%d/task/%d/stat", m_ProcessId, ThreadId);

            int statFileFd = open(statFilename, O_RDONLY);

            if (statFileFd <= 0)
            {
                throw std::system_error(errno, std::generic_category(), "Cannot open the process' stat file");
            }

            memset(statStr, 0, sizeof(statStr));
            SureRead(statFileFd, statStr, sizeof(statStr) - 1);

            close(statFileFd);
        }

        // Extract PID

        pid = atoi(statStr);

        // Extract command line

        const char* commStart = strchr(statStr, '(');
        const char* commEnd = strrchr(statStr, ')');

        if (commStart != nullptr && commEnd != nullptr && commEnd > commStart)
        {
            memset(comm, 0, sizeof(comm));
            strncpy(comm, commStart + 1, MIN(sizeof(comm)-1, (size_t)(commEnd - commStart - 1)));
        }
        else
        {
            throw std::system_error(errno, std::generic_category(), "Cannot parse the process' stat file");
        }

        // Extract the rest

        const auto result = sscanf(
            commEnd + 2,                        // Skip ") "
            "%c %d %d %d %d %d "
            "%u %lu %lu %lu %lu %lu %lu %ld "
            "%ld %ld %ld %ld %ld %llu %lu %ld "
            "%lu %lu %lu %lu %lu %lu",
            &state, &ppid, &pgrp, &session, &tty_nr, &tpgid,
            &flags, &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime, &cutime,
            &cstime, &priority, &nice, &num_threads, &itrealvalue, &starttime, &vsize, &rss,
            &rsslim, &startcode, &endcode, &startstack, &kstkesp, &kstkeip);

        if (result != 28) // how many items were parsed out
        {
            throw std::system_error(errno, std::generic_category(), "Error when parsing the process' stat file");
        }

        CL_LOG(
            m_Logger,
            TRACE_LEVEL_VERBOSE,
            S_OK,
            "Thread %d info (man 5 proc): pid %d, comm %s, state %c, ppid %d, pgrp %d, session %d, tty_nr %d, tpgid %d, "
            "flags 0x%x, minflt %lu, cminflt %lu, majflt %lu, cmajflt %lu, utime %lu, stime %lu, cutime %ld, "
            "cstime %ld, priority %ld, nice %ld, num_therads %ld, itrealvalue %ld, starttime %llu, vsize %lu, rss %ld, "
            "rsslim %lu, startcode %p, endcode %p, startstack %p, kstkesp %p, ksteip %p",
            ThreadId,
            pid, comm, state, ppid, pgrp, session, tty_nr, tpgid,
            flags, minflt, cminflt, majflt, cmajflt, utime, stime, cutime,
            cstime, priority, nice, num_threads, itrealvalue, starttime, vsize, rss,
            rsslim, (void*)startcode, (void*)endcode, (void*)startstack, (void*)kstkesp, (void*)kstkeip);

        for (auto i = 0ULL; i < strlen(processStates); ++i)
        {
            if ((processStates[i] == state) || (processStates[i] == state - ('a'-'A')))
            {
                info.pr_state = i;
                break;
            }
        }

        info.pr_sname = state;
        info.pr_zomb = state == 'Z';
        info.pr_nice = nice;
        info.pr_flag = flags;
        info.pr_pid = pid;
        info.pr_ppid = ppid; 
        info.pr_pgrp = pgrp;
        info.pr_sid = session;    

        // Also fiil out few fields in status

        status.pr_pid = info.pr_pid;
        status.pr_ppid = info.pr_ppid;
        status.pr_pgrp = info.pr_pgrp;
        status.pr_sid = info.pr_sid;

        status.pr_utime.tv_sec = utime/1000;
        status.pr_utime.tv_usec = (utime%1000)*1000;
        status.pr_stime.tv_sec = stime/1000;
        status.pr_stime.tv_usec = (stime%1000)*1000;
        status.pr_cutime.tv_sec = cutime/1000;
        status.pr_cutime.tv_usec = (cutime%1000)*1000;
        status.pr_cstime.tv_sec = cstime/1000;
        status.pr_cstime.tv_usec = (cstime%1000)*1000;
    }

    {
        char    exeLink[256];
        char    exePath[1024];
        char*   exeName = nullptr;

        memset(exePath, 0, sizeof(exePath));
        sprintf(exeLink, "/proc/%d/task/%d/exe", m_ProcessId, ThreadId);

        const auto result = readlink(exeLink, exePath, sizeof(exePath) - 1); // Best effort
        exeName = strrchr(exePath, '/');

        (void)result;

        if (exeName != nullptr)
        {
            CL_LOG(
                m_Logger,
                TRACE_LEVEL_VERBOSE,
                S_OK,
                "Thread %d started from %s",
                ThreadId,
                exePath);

            strncpy(info.pr_fname, exeName + 1, sizeof(info.pr_fname) - 1);
        }        
    }

    {
        char cmdlinePath[256];

        sprintf(cmdlinePath, "/proc/%d/task/%d/cmdline", m_ProcessId, ThreadId);

        int cmdlineFd = open(cmdlinePath, O_RDONLY);

        if (cmdlineFd > 0) // Best effort
        {
            SureRead(cmdlineFd, &info.pr_psargs[0], sizeof(info.pr_psargs) - 1);
            close(cmdlineFd);
        }
    }

    {
        char statusPath[256];

        sprintf(statusPath, "/proc/%d/task/%d/status", m_ProcessId, ThreadId);

        FILE* statusFile = fopen(statusPath, "rt");

        if (statusFile != nullptr)
        {
            char line[MAX_PATH];

            while (fgets(line, sizeof(line) - 1, statusFile) != nullptr)
            {
                if (strncmp(line, "Uid:\t", 5) == 0)
                {
                    info.pr_uid = atoi(line + 5);
                }
                else if (strncmp(line, "Gid:\t", 5) == 0)
                {
                    info.pr_gid = atoi(line + 5);
                }
                else if (strncmp(line, "SigQ:\t", 6) == 0)
                {
                    status.pr_cursig = atoi(line + 6);
                    signalInfo.si_signo = status.pr_cursig;
                }
                else if (strncmp(line, "SigBlk:\t", 8) == 0)
                {
                    status.pr_sighold = atol(line + 8);
                }
                else if (strncmp(line, "SigPnd:\t", 8) == 0)
                {
                    status.pr_sigpend = atol(line + 8);
                }
            }

            fclose(statusFile);
        }
    }

    // Get the process status

    {
        status.pr_fpvalid = 1;

        {
            struct iovec ioVec;

            ioVec.iov_base = &status.pr_reg;
            ioVec.iov_len = sizeof(status.pr_reg);

            if (ptrace((__ptrace_request)PTRACE_GETREGSET, ThreadId, NT_PRSTATUS, &ioVec) < 0)
            {
                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_ERROR,
                    errno,
                    "Error when getting general purpose registers for thread %d",
                    ThreadId);
            }
        }

        {
            struct iovec ioVec;

            ioVec.iov_base = &view->m_FpState;
            ioVec.iov_len = sizeof(view->m_FpState);

            if (ptrace((__ptrace_request)PTRACE_GETREGSET, ThreadId, NT_PRFPREG, &ioVec) < 0)
            {
                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_ERROR,
                    errno,
                    "Error when getting floating point registers for thread %d",
                    ThreadId);
            }

            view->m_FpStateSize = ioVec.iov_len;
        }

#ifdef __amd64
        {
            struct iovec ioVec;

            ioVec.iov_base = &view->m_XState;
            ioVec.iov_len = sizeof(view->m_XState);

            if (ptrace((__ptrace_request)PTRACE_GETREGSET, ThreadId, NT_X86_XSTATE, &ioVec) < 0)
            {
                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_ERROR,
                    errno,
                    "Error when getting XSAVE state for thread %d",
                    ThreadId);
            }

            view->m_XStateSize = ioVec.iov_len;
        }
#endif 
#ifdef __aarch64__
        {
            struct iovec ioVec;

            ioVec.iov_base = &view->m_HwBreak;
            ioVec.iov_len = sizeof(view->m_HwBreak);

            if (ptrace((__ptrace_request)PTRACE_GETREGSET, ThreadId, NT_ARM_HW_BREAK, &ioVec) < 0)
            {
                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_ERROR,
                    errno,
                    "Error when getting ARM HW breakpoints state for thread %d",
                    ThreadId);
            }

            view->m_HwBreakSize = ioVec.iov_len;            
        }

        {
            struct iovec ioVec;

            ioVec.iov_base = &view->m_HwWatch;
            ioVec.iov_len = sizeof(view->m_HwWatch);

            if (ptrace((__ptrace_request)PTRACE_GETREGSET, ThreadId, NT_ARM_HW_WATCH, &ioVec) < 0)
            {
                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_ERROR,
                    errno,
                    "Error when getting ARM HW watch state for thread %d",
                    ThreadId);
            }

            view->m_HwWatchSize = ioVec.iov_len;       
        }

        {
            struct iovec ioVec;

            ioVec.iov_base = &view->m_Tls;
            ioVec.iov_len = sizeof(view->m_Tls);

            if (ptrace((__ptrace_request)PTRACE_GETREGSET, ThreadId, NT_ARM_TLS, &ioVec) < 0)
            {
                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_ERROR,
                    errno,
                    "Error when getting ARM TLS state for thread %d",
                    ThreadId);
            }
        }

        {
            struct iovec ioVec;

            ioVec.iov_base = &view->m_SysCall;
            ioVec.iov_len = sizeof(view->m_SysCall);

            if (ptrace((__ptrace_request)PTRACE_GETREGSET, ThreadId, NT_ARM_SYSTEM_CALL, &ioVec) < 0)
            {
                CL_LOG(
                    m_Logger,
                    TRACE_LEVEL_ERROR,
                    errno,
                    "Error when getting ARM syscall state for thread %d",
                    ThreadId);
            }
        }
#endif 
    }

    return view;
}

size_t ProcessView::SaveVaRegion(const VaRegion& Region, int OutFileDesc) const
{
    std::unique_ptr<char[]> page = std::make_unique<char[]>(c_PageSize);

    size_t dumped = 0;

    for (uint64_t address = Region.m_Start; address < Region.m_End; address += c_PageSize)
    {
        memset(page.get(), 0xCC, c_PageSize);

        const auto bytesRead = pread64(m_MemFileDesc, page.get(), c_PageSize, address);
        const auto bytesWritten = SureWrite(OutFileDesc, page.get(), c_PageSize);

        (void)bytesRead;

        if (bytesWritten < 0)
        {
            throw std::system_error(errno, std::generic_category(), "Failed write to the core file");
        }

        dumped += bytesWritten;                
    }

    return dumped;
}

void ProcessView::OpenMemFile()
{
    char memFilename[PATH_MAX];
    sprintf(memFilename, "/proc/%d/mem", m_ProcessId);

    m_MemFileDesc = open(memFilename, O_RDONLY);
    if (m_MemFileDesc < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Cannot open the process' memory file");
    }
}

size_t ProcessView::WriteElfHeader(int OutputFileDesc) const
{
    Elf64_Ehdr elfHeader;

    memset(&elfHeader, 0, sizeof(elfHeader));

    elfHeader.e_ident[EI_MAG0] = ELFMAG0;
    elfHeader.e_ident[EI_MAG1] = ELFMAG1;
    elfHeader.e_ident[EI_MAG2] = ELFMAG2;
    elfHeader.e_ident[EI_MAG3] = ELFMAG3;
    elfHeader.e_ident[EI_CLASS] = ELFCLASS64;
    elfHeader.e_ident[EI_DATA] = Endianness() ? ELFDATA2MSB : ELFDATA2LSB;
    elfHeader.e_ident[EI_VERSION] = EV_CURRENT;
    elfHeader.e_ident[EI_OSABI] = ELFOSABI_NONE;
    elfHeader.e_type = ET_CORE;
#ifdef __amd64
    elfHeader.e_machine = EM_X86_64;
#elif __aarch64__
    elfHeader.e_machine = EM_AARCH64;
#else
#   error Unsupported CPU
#endif
    elfHeader.e_version = EV_CURRENT;
    (void)elfHeader.e_entry;
    elfHeader.e_phoff = sizeof(Elf64_Ehdr);
    (void)elfHeader.e_shoff;
    (void)elfHeader.e_flags;
    elfHeader.e_ehsize = sizeof(Elf64_Ehdr);
    elfHeader.e_phentsize = sizeof(Elf64_Phdr);
    elfHeader.e_phnum = 1 + m_VaRegions.size(); // PT_NOTE and m_VaRegions.size() of PT_LOAD
    elfHeader.e_shentsize = sizeof(Elf64_Shdr);
    (void)elfHeader.e_shnum;
    (void)elfHeader.e_shstrndx;

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Writing ELF core header at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    const auto written = SureWrite(OutputFileDesc, &elfHeader, sizeof(elfHeader));

    if (written < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Writing core dump header failed");
    }

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Wrote %lu bytes for ELF core header",
        written);

    return written;
}

size_t ProcessView::WriteProgramHeaders(int OutputFileDesc) const
{
    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Writing program headers at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    // There will a header for PT_NOTE, and
    // as many PT_LOAD as there are VA regions

    const size_t programHeadersSize = sizeof(Elf64_Phdr) * (m_VaRegions.size() + 1);
    const size_t elfHeaderHeaderSize = sizeof(Elf64_Ehdr);

    const size_t dataOffset = RoundUp(elfHeaderHeaderSize, c_HeaderAlign) + 
                              RoundUp(programHeadersSize, c_HeaderAlign); // Notes are situated right after the headers

    // Fill out headers

    std::vector<Elf64_Phdr> programHeadersData;

    {
        Elf64_Phdr noteHeader;

        memset(&noteHeader, 0, sizeof(noteHeader));

        noteHeader.p_type = PT_NOTE;
        noteHeader.p_flags = 0;
        noteHeader.p_vaddr = 0;
        noteHeader.p_paddr = 0;
        noteHeader.p_filesz = m_TotalNoteSize;
        noteHeader.p_memsz = m_TotalNoteSize;
        noteHeader.p_align = 1;

        noteHeader.p_offset = dataOffset; // Notes are written after the headers

        programHeadersData.push_back(noteHeader);
    }

    {
        Elf64_Phdr segmentHeader;

        size_t currentOffset = RoundUp(dataOffset + m_TotalNoteSize, c_PageSize);

        for (const auto& region : m_VaRegions)
        {
            memset(&segmentHeader, 0, sizeof(segmentHeader));

            segmentHeader.p_type = PT_LOAD;
            segmentHeader.p_flags = region.ToElfProtection();
            segmentHeader.p_offset = currentOffset;
            segmentHeader.p_vaddr = region.m_Start;
            segmentHeader.p_paddr = 0;
            segmentHeader.p_filesz = region.m_End - region.m_Start;
            segmentHeader.p_memsz = segmentHeader.p_filesz;
            segmentHeader.p_align = c_PageSize;

            currentOffset += segmentHeader.p_filesz;

            programHeadersData.push_back(segmentHeader);
        }
    }

    // Write

    const auto written = SureWrite(OutputFileDesc, &programHeadersData[0], programHeadersSize);

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Wrote %lu bytes",
        written);

    return written;
}

void ProcessView::GetNotesSize()
{
    m_NoteHeaderAndNameRoundUp  = sizeof(Elf64_Nhdr) + 8;

    m_ProcessInfoNoteSize   = m_NoteHeaderAndNameRoundUp + sizeof(prpsinfo_t);
    m_ProcessStatusNoteSize = (m_NoteHeaderAndNameRoundUp + sizeof(prstatus_t) +
                               m_NoteHeaderAndNameRoundUp + sizeof(siginfo_t) +
                               m_NoteHeaderAndNameRoundUp + m_AttachedThreads[m_ProcessId]->m_FpStateSize +
#ifdef __amd64
                               m_NoteHeaderAndNameRoundUp + m_AttachedThreads[m_ProcessId]->m_XStateSize
#endif 
#ifdef __aarch64__
                               m_NoteHeaderAndNameRoundUp + sizeof(ThreadView::m_Tls) +
                               m_NoteHeaderAndNameRoundUp + m_AttachedThreads[m_ProcessId]->m_HwBreakSize +
                               m_NoteHeaderAndNameRoundUp + m_AttachedThreads[m_ProcessId]->m_HwWatchSize +
                               m_NoteHeaderAndNameRoundUp + sizeof(ThreadView::m_SysCall)
#endif
                               )*m_AttachedThreads.size();
    m_AuxVectorNoteSize     = m_NoteHeaderAndNameRoundUp + m_AuxVectorSize;

    m_MappedFileNoteSize = [this]()
    {
        size_t addrLayoutSize = 0;
        size_t stringSize = 0;

        for (const auto& [fileName, regionList] : m_MappedFiles)
        {
            stringSize += ((fileName.size() + 1)*regionList.size());
            addrLayoutSize += (sizeof(MappedFilesNoteItem)*regionList.size());
        }

        const auto introSize = sizeof(MappedFilesNoteIntro);

        return m_NoteHeaderAndNameRoundUp + RoundUp(introSize + addrLayoutSize + stringSize, c_NotePadding);
    }();

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "Projected process info note size: %lu",
        m_ProcessInfoNoteSize);

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "Projected process status note size: %lu",
        m_ProcessStatusNoteSize);

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "Projected aux vector note size: %lu",
        m_AuxVectorNoteSize);

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "Projected mapped files note size: %lu",
        m_MappedFileNoteSize);

    m_TotalNoteSize = m_ProcessInfoNoteSize + m_ProcessStatusNoteSize + m_AuxVectorNoteSize + m_MappedFileNoteSize;

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "Projected total note size: %lu",
        m_TotalNoteSize);
}

void ProcessView::GetAuxVectorSize()
{
    char auxvFilename[PATH_MAX];
    sprintf(auxvFilename, "/proc/%d/auxv", m_ProcessId);

    int auxFd = open(auxvFilename, O_RDONLY);

    if (auxFd < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Opening aux vector data failed");
    }

    Elf64_Auxv aux;
    m_AuxVectorSize = 0;

    while (SureRead(auxFd, &aux, sizeof(aux)) > 0)
    {
        m_AuxVectorSize += sizeof(aux);

        if (aux.a_type == AT_SYSINFO_EHDR)
        {
            CL_LOG(
                m_Logger,
                TRACE_LEVEL_INFORMATION,
                S_OK,
                "vDSO address from the auxiliary vector: 0x%lx",
                aux.a_un.a_val);
        }
    }

    close(auxFd);
}

size_t ProcessView::WriteNote(int OutputFileDesc, int NoteKind, const char* Name, const void* Data, size_t DataSize) const
{
    size_t totalWritten = 0;

    Elf64_Nhdr noteHeader;
    char noteName[8];

    memset(&noteHeader, 0, sizeof(noteHeader));
    memset(&noteName, 0, sizeof(noteName));

    noteHeader.n_type = NoteKind;
    noteHeader.n_namesz = MIN(strlen(Name), 7);
    noteHeader.n_descsz = DataSize;

    strncpy(&noteName[0], Name, noteHeader.n_namesz);

    // Account for the terminating zero. 
    // ELF-64 Object File Format, Version 1.5 claims that is not required
    // but readelf and gdb refuse to read it otherwise

    ++noteHeader.n_namesz; 

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "Writing note header at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    ssize_t written = SureWrite(OutputFileDesc, &noteHeader, sizeof(noteHeader));

    if (written < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Writing note header failed");
    }

    totalWritten += written;

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "Writing note name at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    written = SureWrite(OutputFileDesc, noteName, sizeof(noteName));

    if (written < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Writing note name failed");
    }

    totalWritten += written;

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_VERBOSE,
        S_OK,
        "Writing note payload %lu bytes at offset 0x%lx...",
        DataSize,
        lseek(OutputFileDesc, 0, SEEK_CUR));

    if (DataSize % 4 != 0)
    {
        throw std::logic_error("Note's payload is not properly padded");
    }

    written = SureWrite(OutputFileDesc, Data, DataSize);

    if (written < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Writing note payload failed");
    }

    totalWritten += written;

    return totalWritten;
}

size_t ProcessView::WriteNotes(int OutputFileDesc) const
{
    size_t totalWritten = 0;
    size_t written = 0;

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Writing notes at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    if (m_ProcessInfoNoteSize != 0)
    {
        written = WriteProcessInfoNote(OutputFileDesc);
        if (written != m_ProcessInfoNoteSize)
        {
            throw std::logic_error("Mismatched process info note size");
        }
        totalWritten += written;
    }

    if (m_ProcessStatusNoteSize != 0)
    {
        written = WriteThreadStatusNotes(OutputFileDesc);
        if (written != m_ProcessStatusNoteSize)
        {
            throw std::logic_error("Mismatched process status note size");
        }
        totalWritten += written;
    }

    if (m_AuxVectorNoteSize != 0)
    {
        written = WriteAuxVectorNote(OutputFileDesc);
        if (written != m_AuxVectorNoteSize)
        {
            throw std::logic_error("Mismatched aux vector note size");
        }
        totalWritten += written;
    }

    if (m_MappedFileNoteSize != 0)
    {
        written = WriteMappedFilesNote(OutputFileDesc);
        if (written != m_MappedFileNoteSize)
        {
            throw std::logic_error("Mismatched mapped files note size");
        }
        totalWritten += written;
    }

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Wrote %lu bytes for notes",
        totalWritten);

    return totalWritten;
}

size_t ProcessView::WriteThreadStatusNotes(int OutputFileDesc) const
{
    size_t totalWritten = 0;

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Writing thread status notes at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    for (const auto& [threadId, threadStatus] : m_AttachedThreads)
    {
        size_t written = WriteNote(OutputFileDesc, NT_PRSTATUS, "CORE", &threadStatus->m_Status, sizeof(threadStatus->m_Status));
        totalWritten += written;

        written = WriteNote(OutputFileDesc, NT_PRFPREG, "CORE", &threadStatus->m_FpState, threadStatus->m_FpStateSize);
        totalWritten += written;

#ifdef __amd64
        written = WriteNote(OutputFileDesc, NT_X86_XSTATE, "LINUX", &threadStatus->m_XState, threadStatus->m_XStateSize);
        totalWritten += written;
#endif 
#ifdef __aarch64__
        written = WriteNote(OutputFileDesc, NT_ARM_TLS, "LINUX", &threadStatus->m_Tls, sizeof(threadStatus->m_Tls));
        totalWritten += written;

        written = WriteNote(OutputFileDesc, NT_ARM_HW_BREAK, "LINUX", &threadStatus->m_HwBreak, threadStatus->m_HwBreakSize);
        totalWritten += written;

        written = WriteNote(OutputFileDesc, NT_ARM_HW_WATCH, "LINUX", &threadStatus->m_HwWatch, threadStatus->m_HwWatchSize);
        totalWritten += written;

        written = WriteNote(OutputFileDesc, NT_ARM_SYSTEM_CALL, "LINUX", &threadStatus->m_SysCall, sizeof(threadStatus->m_SysCall));
        totalWritten += written;
#endif 

        written = WriteNote(OutputFileDesc, NT_SIGINFO, "CORE", &threadStatus->m_SignalInfo, sizeof(threadStatus->m_SignalInfo));
        totalWritten += written;
    }

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Wrote %lu bytes for the thread status notes, %lu notes",
        totalWritten,
        m_AttachedThreads.size());

    return totalWritten;
}

size_t ProcessView::WriteVaRegions(int OutputFileDesc) const
{
    size_t written = 0;

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Writing memory content at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    for (const auto& region : m_VaRegions)
    {        
        const auto dumped = SaveVaRegion(region, OutputFileDesc);

        written += dumped;

        CL_LOG(
            m_Logger,
            TRACE_LEVEL_VERBOSE,
            S_OK,
            "Saved %lu bytes from region 0x%lx..0x%lx of size %lu, current file offset 0x%lx...",
            dumped,
            region.m_Start,
            region.m_End,
            region.m_End - region.m_Start,
            lseek(OutputFileDesc, 0, SEEK_CUR));
    }

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Wrote %lu bytes for VA regions",
        written);

    return written;
}

size_t ProcessView::WriteProcessInfoNote(int OutputFileDesc) const
{
    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Writing process info note at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    // Threads and processes in Linux are LWP (Light-weight processes)

    const auto&& processInfo = m_AttachedThreads.find(m_ProcessId);
    
    const auto written = WriteNote(OutputFileDesc, NT_PRPSINFO, "CORE", &processInfo->second->m_Info, sizeof(processInfo->second->m_Info));

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Wrote %lu bytes for the process info note",
        written);

    return written;
}

size_t ProcessView::WriteAuxVectorNote(int OutputFileDesc) const
{    
    char auxvFilename[PATH_MAX];
    sprintf(auxvFilename, "/proc/%d/auxv", m_ProcessId);

    int auxFd = open(auxvFilename, O_RDONLY);

    if (auxFd < 0)
    {
        throw std::system_error(errno, std::generic_category(), "Opening aux vector data failed");
    }

    std::unique_ptr<char[]> auxv = std::make_unique<char[]>(m_AuxVectorSize);

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Writing auxiliary vector at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    if (SureRead(auxFd, auxv.get(), m_AuxVectorSize) < 0)
    {
        close(auxFd);

        throw std::system_error(errno, std::generic_category(), "Reading auxiliary vector note failed");
    }

    close(auxFd);

    const auto written = WriteNote(OutputFileDesc, NT_AUXV, "CORE", auxv.get(), m_AuxVectorSize);

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Wrote %lu bytes for the auxiliary vector",
        written);

    return written;
}

size_t ProcessView::WriteMappedFilesNote(int OutputFileDesc) const
{
    std::unique_ptr<char[]> data = std::make_unique<char[]>(m_MappedFileNoteSize);

    size_t position = 0;

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Writing mapped files note at offset 0x%lx...",
        lseek(OutputFileDesc, 0, SEEK_CUR));

    MappedFilesNoteIntro intro;

    intro.m_PageSize = 1;
    intro.m_FileCount = 0;
    
    for (const auto& [mappedFile, regionList] : m_MappedFiles)
    {
        intro.m_FileCount += regionList.size();
    }    

    memcpy(data.get() + position, &intro, sizeof(intro));

    position += sizeof(intro);

    // Sort by virtual address

    std::vector<std::tuple<tstring, VaRange>> rangeStartAddrSortedList;

    for (const auto& [mappedFile, regionList] : m_MappedFiles)
    {
        rangeStartAddrSortedList.push_back({mappedFile, regionList.front()});
    }

    std::sort(
        rangeStartAddrSortedList.begin(),
        rangeStartAddrSortedList.end(),
        [](const std::tuple<tstring, VaRange>& lhs, const std::tuple<tstring, VaRange>& rhs)
        {
            return std::get<1>(lhs) < std::get<1>(rhs);
        }
    );

    // and iterate the mapped files map using the sorted vector

    for (const auto& [mappedFile, startRange] : rangeStartAddrSortedList)
    {
        const auto& regionList = m_MappedFiles.find(mappedFile);

        for (const auto& region : regionList->second)
        {
            MappedFilesNoteItem item;

            item.m_StartAddr = region.m_Start;
            item.m_EndAddr = region.m_End;
            item.m_PageCount = region.m_Offset;

            memcpy(data.get() + position, &item, sizeof(item));

            position += sizeof(item);
        }
    }

    for (const auto& [mappedFile, startRange] : rangeStartAddrSortedList)
    {
        const auto& regionList = m_MappedFiles.find(mappedFile);

        for (auto i = 0U; i < regionList->second.size(); ++i)
        {
            memcpy(data.get() + position, mappedFile.c_str(), mappedFile.size() + 1);

            position += (mappedFile.size() + 1);
        }
    }

    const auto paddedPosition = RoundUp(position, c_NotePadding);

    for (auto i = position; i < paddedPosition; ++i)
    {
        data[i] = 0;
    }

    position = paddedPosition;

    const auto written = WriteNote(OutputFileDesc, NT_FILE, "CORE", data.get(), position);

    CL_LOG(
        m_Logger,
        TRACE_LEVEL_INFORMATION,
        S_OK,
        "Wrote %lu bytes for mapped files note",
        written);

    return written;
}
