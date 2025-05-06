/// This must be incremented every time we introduce an incompatible protocol
/// change.
///
/// A change is an incompatible protocol change UNLESS a binary compiled with
/// the code before the change is compatible with a binary compiled after the
/// change.
///
/// A binary A is compatible with binary B if a cluster of nodes where some are
/// running A and some are running B can still function normally, even if
/// neither group have threshold number of nodes.
///
/// The effect of this protocol version is that nodes with different protocol
/// versions will refuse to connect to each other. That way, when we introduce
/// an incompatible protocol change, we are effectively creating a new network
/// that is separate from the old network, thus requiring only threshold number
/// of nodes to upgrade.
pub const MPC_PROTOCOL_VERSION: u32 = 5;
