/* From ioctl.h: 
 * "ioctl command encoding: 32 bits total, command in lower 16 bits,
 * size of the parameter structure in the lower 14 bits of the
 * upper 16 bits.
 * Encoding the size of the parameter structure in the ioctl request
 * is useful for catching programs compiled with old versions
 * and to avoid overwriting user space outside the user buffer area.
 * The highest 2 bits are reserved for indicating the ``access mode''.
 * NOTE: This limits the max parameter size to 16kB -1 !""
 */

// For huge pages, need
// 1) CONFIG_HUGETLB_PAGE=y, CONFIG_TRANSPARENT_HUGEPAGE=y
// 2) write echo $number > /proc/sys/vm/nr_hugepages

#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sched.h>
#include <fcntl.h>

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/klog.h>
#include <sys/mount.h>
#include <sys/syscall.h>

#include "hcl-init.h"

long kmsg_fd;

#define UNDERHILL_PATH "/bin/underhill"

#define UNDERHILL_ARGS \
    UNDERHILL_PATH, \
    NULL

static char* underhill_args[] = {
    UNDERHILL_ARGS    
};

static char* underhill_envp[] = {
    "PATH=/bin",
    "PWD=/",
#ifdef CONFIG_RUST_FULL_BACKTRACE
    "RUST_BACKTRACE=full",
#else
    "RUST_BACKTRACE=1",
#endif
    NULL
};

void init(void);
void run_init_if_present(void);
void run_debug_server_if_present(void);

void infinite_pause(void);
void run_underhill(void);

void dump(const char* path);
void save(const char* path, const char* value);

void main()
{
    init();
    run_init_if_present();
    run_debug_server_if_present();
    run_underhill();
    infinite_pause();
}

struct mount_t 
{
    const char* fs;
    const char* mount_point;
    const char* dev;
};

void init(void)
{
    int i;
    long err;

    struct mount_t mount_tab[] = 
    {
        {.fs = "devtmpfs", .mount_point = "devtmpfs", .dev = "/dev"},
        {.fs = "devpts", .mount_point = "devpts", .dev = "/dev/pts"},
        {.fs = "proc", .mount_point = "proc", .dev = "/proc"},
        {.fs = "sysfs", .mount_point = "sysfs", .dev = "/sys"},
    };

    // Configure the logger 

    klogctl(SYSLOG_ACTION_CONSOLE_ON, NULL, 0);
    klogctl(SYSLOG_ACTION_CONSOLE_LEVEL, NULL, 7); // DEBUG

    kmsg_fd = open("/dev/kmsg", O_WRONLY);
    //kmsg_fd = STDIO;

    dup2(kmsg_fd, STDOUT_FILENO);
    dup2(kmsg_fd, STDERR_FILENO);
    
    puts("Inside hcl-init");

    for (i = 0; i < sizeof mount_tab/sizeof mount_tab[0]; ++i)
    {
        printf("Mounting %s, %s -> %s\n", mount_tab[i].fs, mount_tab[i].dev, mount_tab[i].mount_point);
        err = mount(mount_tab[i].fs, mount_tab[i].dev, mount_tab[i].mount_point, 0, 0);

        if (err < 0)
        {
            printf("Failed to mount (%ld)\n", err);
        }
    }

    dump("/proc/uptime");
    dump("/proc/timer_list");
    dump("/proc/interrupts");    
    dump("/proc/meminfo");
    dump("/proc/iomem");
    dump("/proc/ioports");
    dump("/proc/sys/kernel/pid_max");
    dump("/proc/sys/kernel/threads-max");
    dump("/proc/sys/vm/max_map_count");

    // Set maximum number of the threads
    save("/proc/sys/kernel/threads-max", "32768");
    // Do not anonimize the kernel pointers
    save("/proc/sys/kernel/kptr_restrict", "0");
}

void run_init_if_present()
{
    puts("Running /bin/busybox if present...");
    execl("/bin/busybox", "init", NULL);
    puts("...not found");
}

void run_debug_server_if_present()
{
    puts("Running /bin/gdbserver if present...");
    execl("/bin/gdbserver",
          " --disable-randomization", "--no-startup-with-shell",
          "/dev/tty_vsock9",
          UNDERHILL_ARGS);
    puts("...not found");
}

void run_underhill(void)
{
    int id;

    id = fork();
    if (id == 0) {
        setsid();
        setpgid(0, 0);

        kmsg_fd = open("/dev/kmsg", O_WRONLY);

        dup2(kmsg_fd, STDOUT_FILENO);
        dup2(kmsg_fd, STDERR_FILENO);

        id = execvpe(underhill_args[0], underhill_args, underhill_envp);
        if (id < 0) {
            printf("underhill could not start, error %d\n", errno);
        }
    } else if (id > 0){
        printf("forked for underhill, pid %d\n", id);
    } else if (id < 0){
        printf("Error %d when forking\n", id);
    }
}

void infinite_pause(void)
{
    puts("Sleeping...");

    for(;;) {
        pause();
        puts("Caught a signal");
    }
}

void dump(const char* path)
{
    char read_buff[512];
    long bytes_read;
    long fd;

    printf("Dumping %s\n", path);

    fd = open(path, O_RDONLY);

    if (fd < 0)
    {
        printf("Failed to open the file (%ld)\n", fd);

        return;
    }

    while ((bytes_read = read(fd, &read_buff[0], sizeof read_buff)))
    {
        write(kmsg_fd, &read_buff[0], bytes_read);
    }
    
    puts("\n");

    close(fd);
}

void save(const char* path, const char* value)
{
    long bytes_written;
    long bytes_to_write;
    long fd;

    printf("Writing '%s' to %s\n", value, path);

    fd = open(path, O_WRONLY);

    if (fd < 0) {
        printf("Failed to open the file (%ld)\n", fd);

        return;
    }

    bytes_to_write = strlen(value);
    bytes_written = write(fd, &value[0], bytes_to_write);
    if (bytes_written < 0 || bytes_written != bytes_to_write) {
        printf("Failed to write (%d)\n", errno);
    }

    close(fd);
}
