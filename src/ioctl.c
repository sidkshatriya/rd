#define _GNU_SOURCE

#include <linux/ioctl.h>

unsigned int ioctl_type(unsigned int nr)  { return _IOC_TYPE(nr); }

unsigned int ioctl_dir(unsigned int nr)  { return _IOC_DIR(nr); }

unsigned int ioctl_nr(unsigned int nr)  { return _IOC_NR(nr); }

unsigned int ioctl_size(unsigned int nr)  { return _IOC_SIZE(nr); }

