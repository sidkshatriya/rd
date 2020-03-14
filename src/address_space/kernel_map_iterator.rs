use crate::address_space::kernel_mapping::KernelMapping;
use crate::address_space::thread_group_in_exec;
use crate::remote_ptr::{RemotePtr, Void};
use crate::task::Task;
use libc::{ino_t, pid_t};
use nix::sys::mman::MapFlags;
use nix::sys::mman::ProtFlags;
use nix::sys::stat::makedev;
use nix::unistd::getpid;
use std::fs::File;
use std::io::{BufRead, BufReader};

pub struct KernelMapIterator {
    tid: pid_t,
    buf_reader: BufReader<File>,
}

impl Iterator for KernelMapIterator {
    type Item = KernelMapping;

    fn next(&mut self) -> Option<KernelMapping> {
        let mut raw_line: String = String::new();
        if let Ok(read_bytes) = self.buf_reader.read_line(&mut raw_line) {
            if read_bytes == 0 {
                return None;
            }

            Some(Self::parse_rawline(&raw_line))
        } else {
            fatal!("Error in reading /proc/{}/maps", self.tid);
            unreachable!()
        }
    }
}

impl KernelMapIterator {
    pub fn new(task: &dyn Task) -> KernelMapIterator {
        // See https://lkml.org/lkml/2016/9/21/423
        ed_assert!(
            task,
            !thread_group_in_exec(task),
            "Task-group in execve, so reading\n\
         /proc/.../maps may trigger kernel\n\
         deadlock!"
        );
        let tid = task.tid;
        KernelMapIterator {
            tid,
            buf_reader: Self::init(tid),
        }
    }

    pub fn new_from_tid(tid: pid_t) -> KernelMapIterator {
        KernelMapIterator {
            tid,
            buf_reader: Self::init(tid),
        }
    }

    fn init(tid: pid_t) -> BufReader<File> {
        let maps_path = format!("/proc/{}/maps", tid);
        let result = File::open(&maps_path);
        match result {
            Err(_) => {
                fatal!("Failed to open {}", maps_path);
                unreachable!()
            }
            Ok(file) => BufReader::new(file),
        }
    }

    fn parse_rawline(raw_line: &str) -> KernelMapping {
        let mut iter = raw_line.splitn(6, ' ');
        let addr_range = iter.next().unwrap();
        let perms_s = iter.next().unwrap();
        let offset_s = iter.next().unwrap();
        let device = iter.next().unwrap();
        let inode_s = iter.next().unwrap();
        // @TODO do we need to worry about right to left language filenames in /proc/{}/maps?
        // Strip leading ascii spaces and trailing newlines also
        let filename_unescaped = iter
            .next()
            .unwrap()
            .trim_start_matches(' ')
            .trim_end_matches('\n');

        let mut addr_iter = addr_range.split('-');
        let addr_low_s = addr_iter.next().unwrap();
        let addr_high_s = addr_iter.next().unwrap();

        let mut dev_iter = device.split(':');
        let dev_major_s = dev_iter.next().unwrap();
        let dev_minor_s = dev_iter.next().unwrap();

        let addr_low: RemotePtr<Void> = usize::from_str_radix(addr_low_s, 16).unwrap().into();
        let addr_high: RemotePtr<Void> = usize::from_str_radix(addr_high_s, 16).unwrap().into();
        let offset: u64 = u64::from_str_radix(offset_s, 16).unwrap();
        let dev_major: u32 = u32::from_str_radix(dev_major_s, 16).unwrap();
        let dev_minor: u32 = u32::from_str_radix(dev_minor_s, 16).unwrap();
        let inode: ino_t = inode_s.parse::<ino_t>().unwrap();

        let mut filename = String::new();
        let mut iter = filename_unescaped.chars();
        while let Some(c) = iter.next() {
            if c == '\\' {
                let c1: Option<char> = iter.next();
                let c2: Option<char> = iter.next();
                let c3: Option<char> = iter.next();

                if c1.is_some()
                    && c1.unwrap() == '0'
                    && c2.is_some()
                    && c2.unwrap() == '1'
                    && c3.is_some()
                    && c3.unwrap() == '2'
                {
                    filename.push('\n');
                } else {
                    filename.push(c);
                    c1.map_or((), |c| filename.push(c));
                    c2.map_or((), |c| filename.push(c));
                    c3.map_or((), |c| filename.push(c));
                }
            } else {
                filename.push(c);
            }
        }

        let prot: ProtFlags = Self::get_prot(perms_s);
        let map_flags: MapFlags = Self::get_map_flags(perms_s);
        KernelMapping::new_with_opts(
            addr_low,
            addr_high,
            &filename,
            makedev(dev_major as u64, dev_minor as u64),
            inode,
            prot,
            map_flags,
            offset,
        )
    }

    fn get_prot(perms_s: &str) -> ProtFlags {
        let mut prot = ProtFlags::empty();
        perms_s
            .find('r')
            .map_or((), |_| prot = prot | ProtFlags::PROT_READ);
        perms_s
            .find('w')
            .map_or((), |_| prot = prot | ProtFlags::PROT_WRITE);
        perms_s
            .find('x')
            .map_or((), |_| prot = prot | ProtFlags::PROT_EXEC);
        prot
    }

    fn get_map_flags(perms_s: &str) -> MapFlags {
        let mut map_flags = MapFlags::empty();
        perms_s
            .find('p')
            .map_or((), |_| map_flags = map_flags | MapFlags::MAP_PRIVATE);
        perms_s
            .find('s')
            .map_or((), |_| map_flags = map_flags | MapFlags::MAP_SHARED);
        map_flags
    }

    pub fn test_output() {
        let it = Self::new_from_tid(getpid().as_raw());
        for m in it {
            println!("{:?}\n", m);
        }
    }
}
