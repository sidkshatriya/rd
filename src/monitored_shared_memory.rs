use std::cell::RefCell;
use std::rc::Rc;

pub struct MonitoredSharedMemory {}

pub type MonitoredSharedMemorySharedPtr = Rc<RefCell<MonitoredSharedMemory>>;
