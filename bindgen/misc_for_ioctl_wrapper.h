#define _GNU_SOURCE

#include <sys/ioctl.h>
#include <linux/input.h>
#include <linux/fs.h>
#include <linux/joystick.h>
#include <linux/msdos_fs.h>

const unsigned int _VFAT_IOCTL_READDIR_BOTH = VFAT_IOCTL_READDIR_BOTH;;
const unsigned int _FS_IOC_GETVERSION = FS_IOC_GETVERSION;
const unsigned int _FS_IOC_GETFLAGS = FS_IOC_GETFLAGS;
const unsigned int _EVIOCGVERSION = EVIOCGVERSION;
const unsigned int _EVIOCGID = EVIOCGID;
const unsigned int _EVIOCGREP = EVIOCGREP;
const unsigned int _EVIOCGKEYCODE = EVIOCGKEYCODE;
const unsigned int _EVIOCGNAME_0 = EVIOCGNAME(0);
const unsigned int _EVIOCGPHYS_0 = EVIOCGPHYS(0);
const unsigned int _EVIOCGUNIQ_0 = EVIOCGUNIQ(0);
const unsigned int _EVIOCGPROP_0 = EVIOCGPROP(0);
const unsigned int _EVIOCGMTSLOTS_0 = EVIOCGMTSLOTS(0);
const unsigned int _EVIOCGKEY_0 = EVIOCGKEY(0);
const unsigned int _EVIOCGLED_0 = EVIOCGLED(0);
const unsigned int _EVIOCGSND_0 = EVIOCGSND(0);
const unsigned int _EVIOCGSW_0 = EVIOCGSW(0);
const unsigned int _EVIOCGEFFECTS = EVIOCGEFFECTS;
const unsigned int _EVIOCGMASK = EVIOCGMASK;
const unsigned int _JSIOCGVERSION = JSIOCGVERSION;
const unsigned int _JSIOCGAXES = JSIOCGAXES;
const unsigned int _JSIOCGBUTTONS = JSIOCGBUTTONS;
const unsigned int _JSIOCGAXMAP = JSIOCGAXMAP;
const unsigned int _JSIOCGBTNMAP = JSIOCGBTNMAP;
const unsigned int _JSIOCGNAME_0 = JSIOCGNAME(0);
