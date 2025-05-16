use near_sdk::{near, BlockHeight};

use super::code_hash::CodeHash;
use super::quote::TeeQuote;

// Maximum time after which TEE MPC nodes must be upgraded to the latest version
const TEE_UPGRADE_PERIOD: BlockHeight = 604800; // ~7 days

/// Proposal for a new TEE code hash to be added to the whitelist, along with the TEE quote that
/// includes the RTMR3 measurement among others.
#[near(serializers=[borsh, json])]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
pub struct TeeProposal {
    pub code_hash: CodeHash,
    pub tee_quote: TeeQuote,
}

/// A proposal for a new TEE code hash to be added to the whitelist, along with the time it was
/// added.
#[near(serializers=[borsh])]
#[derive(Debug, Clone)]
pub struct AllowedTeeProposal {
    pub proposal: TeeProposal,
    pub added: BlockHeight,
}
/// Collection of whitelisted Docker code hashes that are the only ones MPC nodes are allowed to
/// run.
#[near(serializers=[borsh])]
#[derive(Debug, Default)]
pub struct AllowedTeeProposals {
    /// Whitelisted code hashes, sorted by when they were added (oldest first). Expired entries are
    /// lazily cleaned up during insertions and lookups.
    allowed_tee_proposals: Vec<AllowedTeeProposal>,
}

impl AllowedTeeProposals {
    /// Removes all expired code hashes and returns the number of removed entries.
    fn clean(&mut self, current_block_height: BlockHeight) -> usize {
        // Find the first non-expired entry
        let expired_count = self
            .allowed_tee_proposals
            .iter()
            .position(|entry| entry.added + TEE_UPGRADE_PERIOD >= current_block_height)
            .unwrap_or(self.allowed_tee_proposals.len());

        // Remove all expired entries
        self.allowed_tee_proposals.drain(0..expired_count);

        // Return the number of removed entries
        expired_count
    }

    /// Inserts a new code hash into the list after cleaning expired entries. Maintains the sorted
    /// order by `added` (ascending). Returns `true` if the insertion was successful, `false` if the
    /// code hash already exists.
    pub fn insert(
        &mut self,
        code_hash: CodeHash,
        tee_quote: TeeQuote,
        current_block_height: u64,
    ) -> bool {
        // Clean expired entries
        self.clean(current_block_height);

        // Check if the code hash already exists
        if self
            .allowed_tee_proposals
            .iter()
            .any(|entry| entry.proposal.code_hash == code_hash)
        {
            return false;
        }

        // Create the new entry
        let new_entry = AllowedTeeProposal {
            proposal: TeeProposal {
                code_hash: code_hash.clone(),
                tee_quote,
            },
            added: current_block_height,
        };

        // Find the correct position to maintain sorted order by `added`
        let insert_index = self
            .allowed_tee_proposals
            .iter()
            .position(|entry| new_entry.added <= entry.added)
            .unwrap_or(self.allowed_tee_proposals.len());

        // Insert at the correct position
        self.allowed_tee_proposals.insert(insert_index, new_entry);
        true
    }

    pub fn get(&mut self, current_block_height: BlockHeight) -> Vec<AllowedTeeProposal> {
        self.clean(current_block_height);
        self.allowed_tee_proposals.clone()
    }
}
