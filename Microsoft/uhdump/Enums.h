#pragma once

template<typename T>
struct BitMaskEnum
{
    static const bool enable = false;
};

template<typename T>
typename std::enable_if<BitMaskEnum<T>::enable, T>::type
operator |=(T& Lhs, T Rhs)
{
    using underlying_type = typename std::underlying_type<T>::type;

    Lhs = static_cast<T>(static_cast<underlying_type>(Lhs) | static_cast<underlying_type>(Rhs));

    return Lhs;
}

template<typename T>
typename std::enable_if<BitMaskEnum<T>::enable, T>::type
operator |(T Lhs, T Rhs)
{
    using underlying_type = typename std::underlying_type<T>::type;

    return static_cast<T>(static_cast<underlying_type>(Lhs) | static_cast<underlying_type>(Rhs));
}

template<typename T>
typename std::enable_if<BitMaskEnum<T>::enable, T>::type
operator -=(T& Lhs, T Rhs)
{
    using underlying_type = typename std::underlying_type<T>::type;

    Lhs = static_cast<T>(static_cast<underlying_type>(Lhs) & ~static_cast<underlying_type>(Rhs));

    return Lhs;
}

template<typename T>
typename std::enable_if<BitMaskEnum<T>::enable, T>::type
operator -(T Lhs, T Rhs)
{
    using underlying_type = typename std::underlying_type<T>::type;

    return static_cast<T>(static_cast<underlying_type>(Lhs) & ~static_cast<underlying_type>(Rhs));
}

template<typename T, typename std::enable_if<BitMaskEnum<T>::enable, int>::type = 0>
bool operator &(T Lhs, T Rhs)
{
    using underlying_type = typename std::underlying_type<T>::type;

    return static_cast<underlying_type>(Lhs) & static_cast<underlying_type>(Rhs);
}

namespace CrashListener::Structures
{

enum class CrashDumpType
{
    Mini = 0,
    Heap = 1,
    Full = 2,
};

enum class FilePathType
{
    Absolute = 0,
    Relative = 1
};

enum class SortType
{
    Ascending = 0,
    Descending = 1
};

enum class VaRegionProtection : uint32_t
{
    Unspecified = 0,
    Read = 1,
    Write = 2,
    Execute = 4,
    Shared = 8,
    Private = 16
};

enum class CoreDumpFiltering : uint32_t
{
    ExcludeNone = 0,
    ExcludeShared = 1,
    ExcludeExecutable = 2,
    ExcludeReadOnly = 4,
    ExcludeNonElf = 8,
    ExcludeNonAccesible = 16
};

}

template <>
struct BitMaskEnum<CrashListener::Structures::CoreDumpFiltering>
{
    static const bool enable = true;
};

template <>
struct BitMaskEnum<CrashListener::Structures::VaRegionProtection>
{
    static const bool enable = true;
};

namespace CrashListener::Connectivity
{

enum class EndpointType
{
    Unknown = 0,
    Public = 1,
    Mooncake = 2,
    Fairfax = 3,
    Blackforest = 4
};

enum class BlobType
{
    Block,
    Page,
    Append
};

}
