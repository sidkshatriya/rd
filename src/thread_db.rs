/// This provides an interface to libthread_db.so to help with TLS
/// lookup. In principle there could be one instance per process, but we only
/// support one instance for the GdbServer's target process.
///
/// The overall approach is that a libthread_db.so is loaded into rr
/// when this class is initialized (see |load_library|).  This provides
/// the GdbServer with a list of symbols whose addresses might be
/// needed in order to resolve TLS accesses.
///
/// Then, when the address of a TLS variable is requested by the
/// debugger, GdbServer calls |get_tls_address|.  This uses the
/// libthread_db "new" function ("td_ta_new"); if this succeeds then
/// ThreadDb proceeds to use other APIs to find the desired address.
///
/// ThreadDb works on a callback model, using symbols provided by the
/// hosting application.  These are all defined in ThreadDb.cc.
#[derive(Default)]
pub struct ThreadDb;
