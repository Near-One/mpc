/// Maximum length of a single network message. This is a security measure
/// to prevent a malicious node from sending a huge message that would
/// cause OOM errors.
pub const MAX_MESSAGE_LEN: u32 = 100 * 1024 * 1024;
