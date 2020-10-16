#define _GNU_SOURCE

#include <arpa/inet.h>
#include <asm/ldt.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/ethtool.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/if_bonding.h>
#include <linux/ipc.h>
#include <linux/mqueue.h>
#include <linux/msg.h>
#include <linux/net.h>
#include <linux/netfilter/x_tables.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/sockios.h>
#include <linux/stat.h>
#include <linux/sysctl.h>
#include <linux/usbdevice_fs.h>
#include <linux/videodev2.h>
#include <linux/wireless.h>
#include <poll.h>
#include <scsi/sg.h>
#include <signal.h>
#include <sound/asound.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <termios.h>

/// DIFF NOTE: This is not present in rr
#include <sched.h>

/// Need to manually define these
const unsigned int _SNDRV_CTL_IOCTL_PVERSION = SNDRV_CTL_IOCTL_PVERSION;
const unsigned int _SNDRV_CTL_IOCTL_CARD_INFO = SNDRV_CTL_IOCTL_CARD_INFO;
