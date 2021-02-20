// enum from rr-debugger/rr ( https://github.com/rr-debugger/rr ) src/GdbConnection.h
// enum as of rr-debugger/rr git revision abd344288878c9b4046e0b8664927992947a46eb
// Also DREQ_RR_CMD -> DREQ_RD_CMD
enum GdbRequestType {
  DREQ_NONE = 0,

  /* None of these requests have parameters. */
  DREQ_GET_CURRENT_THREAD,
  DREQ_GET_OFFSETS,
  DREQ_GET_REGS,
  DREQ_GET_STOP_REASON,
  DREQ_GET_THREAD_LIST,
  DREQ_INTERRUPT,
  DREQ_DETACH,

  /* These use params.target. */
  DREQ_GET_AUXV,
  DREQ_GET_EXEC_FILE,
  DREQ_GET_IS_THREAD_ALIVE,
  DREQ_GET_THREAD_EXTRA_INFO,
  DREQ_SET_CONTINUE_THREAD,
  DREQ_SET_QUERY_THREAD,
  // TLS lookup, uses params.target and params.tls.
  DREQ_TLS,
  // gdb wants to write back siginfo_t to a tracee.  More
  // importantly, this packet arrives before an experiment
  // session for a |call foo()| is about to be torn down.
  //
  // TODO: actual interface NYI.
  DREQ_WRITE_SIGINFO,

  /* These use params.mem. */
  DREQ_GET_MEM,
  DREQ_SET_MEM,
  // gdb wants to read the current siginfo_t for a stopped
  // tracee.  More importantly, this packet arrives at the very
  // beginning of a |call foo()| experiment.
  //
  // Uses .mem for offset/len.
  DREQ_READ_SIGINFO,
  DREQ_SEARCH_MEM,
  DREQ_MEM_FIRST = DREQ_GET_MEM,
  DREQ_MEM_LAST = DREQ_SEARCH_MEM,

  DREQ_REMOVE_SW_BREAK,
  DREQ_REMOVE_HW_BREAK,
  DREQ_REMOVE_WR_WATCH,
  DREQ_REMOVE_RD_WATCH,
  DREQ_REMOVE_RDWR_WATCH,
  DREQ_SET_SW_BREAK,
  DREQ_SET_HW_BREAK,
  DREQ_SET_WR_WATCH,
  DREQ_SET_RD_WATCH,
  DREQ_SET_RDWR_WATCH,
  DREQ_WATCH_FIRST = DREQ_REMOVE_SW_BREAK,
  DREQ_WATCH_LAST = DREQ_SET_RDWR_WATCH,

  /* Use params.reg. */
  DREQ_GET_REG,
  DREQ_SET_REG,
  DREQ_REG_FIRST = DREQ_GET_REG,
  DREQ_REG_LAST = DREQ_SET_REG,

  /* Use params.cont. */
  DREQ_CONT,

  /* gdb host detaching from stub.  No parameters. */

  /* Uses params.restart. */
  DREQ_RESTART,

  /* Uses params.text. */
  DREQ_RD_CMD,

  // qSymbol packet, uses params.sym.
  DREQ_QSYMBOL,

  // vFile:setfs packet, uses params.file_setfs.
  DREQ_FILE_SETFS,
  // vFile:open packet, uses params.file_open.
  DREQ_FILE_OPEN,
  // vFile:pread packet, uses params.file_pread.
  DREQ_FILE_PREAD,
  // vFile:close packet, uses params.file_close.
  DREQ_FILE_CLOSE,
};

