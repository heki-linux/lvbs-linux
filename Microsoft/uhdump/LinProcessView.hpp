#pragma once

#include <Platform.h>

#include <ILog.h>
#include <Enums.h>

#include <sys/procfs.h>
#include <linux/elf.h>

struct VaRange
{
    uint64_t m_Start;
    uint64_t m_End;
    uint64_t m_Offset;

    VaRange() : m_Start(0), m_End(0), m_Offset(0)
    {
    }

    VaRange(uint64_t Start, uint64_t End, uint64_t Offset) : m_Start(Start), m_End(End), m_Offset(Offset)
    {
    }

    bool operator <(const VaRange& Other) const
    {
        return m_Start < Other.m_Start;
    }
};

struct VaRegion : VaRange
{
    CrashListener::Structures::VaRegionProtection  m_Protection;

    tstring             m_MappedFileName;

    VaRegion() 
        : m_Protection(CrashListener::Structures::VaRegionProtection::Unspecified)
    {        
    }

    VaRegion(uint64_t Start, uint64_t End, uint64_t Offset, CrashListener::Structures::VaRegionProtection Protection, const tstring& MappedFileName) 
        : VaRange(Start, End, Offset), m_Protection(Protection), m_MappedFileName(MappedFileName)
    {        
    }

    tstring GetProtectionStr()
    {
        tstring protection("    ");

        protection[0] = m_Protection & CrashListener::Structures::VaRegionProtection::Read ?       'r' : '-';
        protection[1] = m_Protection & CrashListener::Structures::VaRegionProtection::Write ?      'w' : '-';
        protection[2] = m_Protection & CrashListener::Structures::VaRegionProtection::Execute ?    'x' : '-';

        if (m_Protection & CrashListener::Structures::VaRegionProtection::Private)
        {
            protection[3] = 'p';
        } 
        else if (m_Protection & CrashListener::Structures::VaRegionProtection::Shared)
        {
            protection[3] = 's';
        }
        else
        {
            protection[3] = '-';
        }

        return protection;
    }

    Elf64_Word ToElfProtection() const
    {
        Elf64_Word elfProtection = 0;

        elfProtection |= m_Protection & CrashListener::Structures::VaRegionProtection::Read ?    PF_R : 0;
        elfProtection |= m_Protection & CrashListener::Structures::VaRegionProtection::Write ?   PF_W : 0;
        elfProtection |= m_Protection & CrashListener::Structures::VaRegionProtection::Execute ? PF_X : 0;

        return elfProtection;
    }
};


struct ThreadView
{
    prstatus_t  m_Status;
    siginfo_t   m_SignalInfo;
    prpsinfo_t  m_Info;
    char        m_FpState[0xb00]; // Contains SSE registers on amd64, NEON on arm64
    size_t      m_FpStateSize;
#if defined(__amd64) 
    char        m_XState[0xb00];  // XSAVE state on amd64
    size_t      m_XStateSize;
#elif defined(__aarch64__)
    uint64_t    m_Tls;
    char        m_HwBreak[0xb00];
    size_t      m_HwBreakSize; 
    char        m_HwWatch[0xb00];
    size_t      m_HwWatchSize; 
    uint32_t    m_SysCall;
#else
#error Unsupported CPU
#endif

    ThreadView() : 
        m_FpStateSize(0),
#ifdef __amd64
        m_XStateSize(0)
#endif 
#ifdef __aarch64__
        m_Tls(0xffffffffffffffff),
        m_HwBreakSize(0), 
        m_HwWatchSize(0),
        m_SysCall(0xffff)        
#endif 
    {
        memset(&m_Status, 0, sizeof(m_Status));
        memset(&m_SignalInfo, 0, sizeof(m_SignalInfo));
        memset(&m_Info, 0, sizeof(m_Info));
#ifdef __amd64
        memset(m_FpState, 0, sizeof(m_FpState));
        memset(m_XState, 0, sizeof(m_XState));
#endif 
#ifdef __aarch64__
        memset(m_FpState, 0, sizeof(m_FpState)); 
        memset(m_HwBreak, 0, sizeof(m_HwBreak));
        memset(m_HwWatch, 0, sizeof(m_HwWatch));
#endif
    }
};

class ProcessView
{
public:
    ProcessView(const CrashListener::Logging::ILog* Logger);
    ~ProcessView();

    ProcessView(const ProcessView&) = delete;
    ProcessView(const ProcessView&&) = delete;
    ProcessView& operator=(const ProcessView&) = delete;
    ProcessView& operator=(const ProcessView&&) = delete;

    void Attach(int ProcessId);
    void Detach();
    void CreateCoreDump(
        const tstring& CoreDumpFileName, 
        mode_t Permissions,
        CrashListener::Structures::CoreDumpFiltering Filtering);

    void PrintCallStacks();

private:

    void DumpElfHeaders(std::uint64_t MemDescOffset);

    void OpenMemFile();
    void GetVaRegions(CrashListener::Structures::CoreDumpFiltering Filtering);

    std::vector<pid_t> GetThreadIds() const;

    void GetNotesSize();
    void GetAuxVectorSize();

    std::shared_ptr<ThreadView> BuildThreadView(pid_t ThreadId) const;

    size_t SaveVaRegion(const VaRegion& Region, int OutFileDesc) const;

    size_t WriteElfHeader(int OutputFileDesc) const;
    size_t WriteProgramHeaders(int OutputFileDesc) const;
    size_t WriteNotes(int OutputFileDesc) const;
    size_t WriteNote(int OutputFileDesc, int NoteKind, const char* name, const void* Data, size_t DataSize) const;
    size_t WriteThreadStatusNotes(int OutputFileDesc) const;
    size_t WriteProcessStatusNote(int OutputFileDesc) const;
    size_t WriteProcessInfoNote(int OutputFileDesc) const;
    size_t WriteAuxVectorNote(int OutputFileDesc) const;
    size_t WriteMappedFilesNote(int OutputFileDesc) const;
    size_t WriteVaRegions(int OutputFileDesc) const;

private:
    const CrashListener::Logging::ILog* m_Logger;

    int         m_ProcessId;    
    bool        m_Attached;
    int         m_MemFileDesc;    
    size_t      m_AuxVectorSize;
    uint64_t    m_Vdso;

    std::map<pid_t, std::shared_ptr<ThreadView>>    m_AttachedThreads;
    std::vector<VaRegion>                           m_VaRegions;
    std::map<tstring, std::list<VaRange>>           m_MappedFiles;

    size_t m_NoteHeaderAndNameRoundUp;
    size_t m_ProcessInfoNoteSize;
    size_t m_ProcessStatusNoteSize;
    size_t m_AuxVectorNoteSize;
    size_t m_MappedFileNoteSize;
    size_t m_TotalNoteSize;

    const size_t c_PageSize;
    const size_t c_HeaderAlign;
    const size_t c_NotePadding;    
};
