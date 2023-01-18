#ifndef __HCL_TESTS__
#define __HCL_TESTS__

typedef unsigned char   u8;
typedef unsigned short  u16;
typedef unsigned int    u32;
typedef unsigned long   u64;

typedef signed char   s8;
typedef signed short  s16;
typedef signed int    s32;
typedef signed long   s64;

#include <generated/autoconf.h>

#define __packed __attribute__((packed))

#define __EXPORTED_HEADERS__

#include <linux/const.h>
#include <linux/bits.h>
#include <linux/syslog.h>

#define UL(x)		(_UL(x))
#define ULL(x)		(_ULL(x))

#define HV_PAGE_SIZE 0x1000
#define BITS_PER_LONG_LONG 64

#include <asm/hyperv-tlfs.h>
#include <asm/hv_hcl.h>

#endif
