use std::collections::BTreeSet;

use near_sdk::{
    near,
    store::{key::Identity, IterableMap, LookupMap},
    BlockHeight,
};

use crate::primitives::YieldIndex;

use super::signature::SignatureRequest;
type SignatureId = u64;
// in V1, there is a risk that one might not be able to submit a signature request, because a
// previous resquest is still in the store (but is timed out).
// one would have to wait for that request to get cleared.
// This makes it difficult to reason about the code, hence below should be an improvement on V1.
#[near(serializers=[borsh])]
pub struct SignatureStore {
    next_id: SignatureId,
    metadata: LookupMap<SignatureId, (SignatureRequest, BlockHeight, YieldIndex)>,
    pending_requests: LookupMap<SignatureRequest, SignatureId>, //
    request_by_block_height: IterableMap<BlockHeight, BTreeSet<SignatureId>, Identity>,
}
//enum RequestStatus {
//    Inserted(SignatureId),
//    Waiting(SignatureId),
//}
impl SignatureStore {
    //pub fn add_request(
    //    &mut self,
    //    request: &SignatureRequest,
    //    yield_index: YieldIndex,
    //    timeout_in_blocks: u64,
    //) -> RequestStatus {
    //    // check if a request exists:
    //    let current_block = env::block_height();
    //    match self.pending_requests.insert(request.clone(), self.next_id) {
    //        None => {
    //            self.request_by_block_height
    //                .entry(current_block)
    //                .or_insert(BTreeSet::new())
    //                .and_modify(|sigs| {
    //                    sigs.insert(self.next_id);
    //                });
    //        }
    //        Some(existing) => {}
    //    }
    //    //match &self.pending_requests.entry(request).or {
    //    //    Occupied(current) => { },
    //    //    VacantEntry()=> {},
    //    //}
    //    //if request_id
    //}
}
