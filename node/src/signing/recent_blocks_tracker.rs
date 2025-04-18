use near_indexer_primitives::types::BlockHeight;
use near_indexer_primitives::CryptoHash;
use std::collections::HashMap;
use std::fmt::Debug;
use std::ops::Add;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Tracks the topology of the recent blocks, using the blocks given by the indexer.
///
/// This class provides two important functionalities:
///  - For any given block, it classifies it into one of the categories in `CheckBlockResult`.
///    See the documentation of that enum for the classifications.
///  - Converts a stream of optimistic blocks from the indexer into a stream of finalized
///    blocks. The content of each block in the finalized stream is specified via the `T`
///    type parameter.
///
/// We have certain expectations of the order of blocks that come from the indexer.
/// First, let's define a partial order for blocks. For any two blocks A and B:
///  - If A is a strict ancestor of B then A < B;
///  - If B is a strict ancestor of A then B < A;
///  - If A is the same block as B then A = B;
///  - Otherwise, A and B are not ordered.
///
/// We expect that the blocks given by the indexer:
///  - Respects partial order. That is, if A is given before B, it must not happen that A > B.
///  - Furthermore, if A < B and B < C, and both A and C are given, then B must also be given.
///    In other words there should not be any gaps.
///
/// That being said, the following is fair game:
///  - The indexer gives blocks of different forks in any order, i.e. it can give a block of
///    height 12 and then another block of height 10 that belongs to a different fork.
///  - The indexer, upon startup, may start giving blocks from any position in the blockchain,
///    including giving blocks from multiple forks without giving us any common parents.
///
/// Given these expectations, we provide the aforementioned functionalities by tracking the
/// following:
///  - We keep a fixed-sized window of recent blocks, i.e. all blocks with height >= H - W + 1,
///    where H is the height of the latest block we have *heard of*, and W is the window size.
///    - "Heard of" means the maximum of what we have seen, as well as what others have told us.
///  - We keep track of the canonical chain as well as the final chain.
///
/// Despite the assumptions we make on the indexer's behavior, this class guarantees not to panic
/// even if the indexer violates these assumptions in arbitrary ways.
///
/// Note: The use of Arc is a little unfortunate. Logically we only need Rc, but this code needs
/// to work in futures, and Rc is not Send. So we use Arc instead.
pub struct RecentBlocksTracker<T: Clone + 'static> {
    window_size: u64,
    /// By "root", we mean the blocks whose parents we don't know or are older than the window.
    /// The children of the root are the earliest blocks we are keeping who do not have any order
    /// with each other.
    root_children: Vec<Arc<BlockNode>>,
    /// The head of the canonical chain. This is the chain of the highest-height block we've seen.
    /// This may be None if we have no block at all.
    canonical_head: Option<Arc<BlockNode>>,
    /// The head of the final chain. This is determined by recovering information from the
    /// last_final_block fields of the block headers given to us. This may be None if we have not
    /// seen any final blocks yet.
    final_head: Option<Arc<BlockNode>>,
    /// The maximum height available to us. This is the maximum height of the blocks we have seen,
    /// or have heard of.
    maximum_height_available: BlockHeight,
    /// Maps block hashes to their nodes in the tree.
    hash_to_node: HashMap<CryptoHash, Arc<BlockNode>>,
    /// Maps block hashes to their content; this is to provide the stream of finalized blocks.
    /// Technically, instead of a hashmap we could put this in the node, but that would clutter
    /// the code by requiring the T type parameter everywhere.
    node_to_content: HashMap<CryptoHash, T>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckBlockResult {
    /// The block is older than the recent window of blocks we keep.
    OlderThanRecentWindow,
    /// The block is within the recent window, and also finalized by the blockchain
    /// (it is an ancestor (including self) of the latest final block).
    RecentAndFinal,
    /// The block is recent enough, but belongs to a different fork so has no chance
    /// of being included in any canonical chain from this point on.
    NotIncluded,
    /// The block is optimistically included in the chain, and it is on the canonical chain,
    /// but it is not yet part of the final chain. It is also recent enough.
    OptimisticAndCanonical,
    /// The block is optimistically included in the chain, but it is not on the canonical chain.
    /// It is also recent enough.
    OptimisticButNotCanonical,
    /// We have not seen the block yet, but it appears recent, judging from the height.
    Unknown,
}

pub struct AddBlockResult<T> {
    /// The list of newly finalized blocks, in ascending height order. Each entry is a tuple of
    /// the block height and the data passed to us when adding the block.
    /// It is guaranteed that the new final blocks returned from multiple calls to add_block are
    /// contiguous, thus forming the stream of finalized blocks.
    pub new_final_blocks: Vec<(u64, T)>,
}

/// Represents a block in the recent blockchain.
///
/// Note: We're not using the thread-safe functionality of Mutex here because we only access
/// it from at most one thread. But these need to work in futures, and RefCell is not Send,
/// so we use Mutex instead. Same story with AtomicBool vs Cell<bool>.
struct BlockNode {
    hash: CryptoHash,
    height: u64,
    /// Whether this block is currently on the canonical chain.
    canonical: AtomicBool,
    /// Whether this block is on the final chain. This only ever goes from false to true.
    is_final: AtomicBool,
    /// The parent block, if we're aware of it. This may be None if we either have never
    /// heard of the parent or the parent has been pruned (too old).
    parent: Mutex<Option<Arc<BlockNode>>>,
    /// The children blocks; there can be multiple if there are forks. The children are
    /// kept in no specific order.
    children: Mutex<Vec<Arc<BlockNode>>>,
}

impl BlockNode {
    /// Find the closest descendants of this node (including itself), whose height is at least
    /// `height`. These descendants are appended to `descendants_output`. The nodes from the
    /// subtree that are lower than the height are appended to `old_nodes`.
    fn closest_descendants_with_height_at_least(
        self: &Arc<BlockNode>,
        height: u64,
        descendants_output: &mut Vec<Arc<BlockNode>>,
        old_nodes: &mut Vec<Arc<BlockNode>>,
    ) {
        if self.height >= height {
            descendants_output.push(self.clone());
        } else {
            old_nodes.push(self.clone());
            let children = self.children.lock().unwrap();
            for child in children.iter() {
                child.closest_descendants_with_height_at_least(
                    height,
                    descendants_output,
                    old_nodes,
                );
            }
        }
    }

    fn debug_print(
        &self,
        f: &mut std::fmt::Formatter<'_>,
        indents: &mut Vec<u8>,
        final_head: Option<CryptoHash>,
        canonical_head: Option<CryptoHash>,
        content_printer: &impl Fn(&CryptoHash, &mut std::fmt::Formatter<'_>) -> std::fmt::Result,
    ) -> std::fmt::Result {
        if Some(self.hash) == final_head {
            write!(f, "FH ")?;
        } else if Some(self.hash) == canonical_head {
            write!(f, "CH ")?;
        } else {
            write!(f, "   ")?;
        }
        for indent in indents.iter() {
            match *indent {
                0 => write!(f, "  ")?,
                1 => write!(f, "│ ")?,
                2 => write!(f, "└─")?,
                3 => write!(f, "├─")?,
                _ => unreachable!(),
            }
        }
        if indents.last().is_some_and(|indent| *indent >= 2) {
            *indents.last_mut().unwrap() -= 2;
        }
        write!(
            f,
            "[{}] {} {} {:<44} ",
            self.height,
            if self.canonical.load(Ordering::Relaxed) {
                "C"
            } else {
                " "
            },
            if self.is_final.load(Ordering::Relaxed) {
                "F"
            } else {
                " "
            },
            format!("{:?}", self.hash),
        )?;
        content_printer(&self.hash, f)?;
        writeln!(f)?;
        let children = self.children.lock().unwrap();
        for (i, child) in children.iter().enumerate() {
            if children.len() == 1 {
                child.debug_print(f, indents, final_head, canonical_head, content_printer)?;
            } else {
                let indent = if i + 1 == children.len() { 2 } else { 3 };
                indents.push(indent);
                child.debug_print(f, indents, final_head, canonical_head, content_printer)?;
                indents.pop();
            }
        }
        Ok(())
    }
}

/// A view of a block that is sufficient for the RecentBlocksTracker.
#[derive(Clone)]
pub struct BlockViewLite {
    pub hash: CryptoHash,
    pub height: u64,
    pub prev_hash: CryptoHash,
    pub last_final_block: CryptoHash,
}

impl<T: Clone> RecentBlocksTracker<T> {
    pub fn new(window_size: u64) -> Self {
        Self {
            window_size,
            root_children: Vec::new(),
            canonical_head: None,
            final_head: None,
            maximum_height_available: 0,
            hash_to_node: HashMap::new(),
            node_to_content: HashMap::new(),
        }
    }

    /// Adds a block to the tracker. This is expected to be called for EVERY block given by the
    /// indexer (whether or not it is interesting). The content is whatever content that we want
    /// to buffer for the stream of final blocks.
    pub fn add_block(
        &mut self,
        block: &BlockViewLite,
        content: T,
    ) -> anyhow::Result<AddBlockResult<T>> {
        if self.hash_to_node.contains_key(&block.hash) {
            anyhow::bail!("Block already exists in the tracker");
        }
        let parent = self.hash_to_node.get(&block.prev_hash).cloned();
        let node = Arc::new(BlockNode {
            hash: block.hash,
            height: block.height,
            canonical: AtomicBool::new(false),
            is_final: AtomicBool::new(false),
            parent: Mutex::new(parent.clone()),
            children: Mutex::new(Vec::new()),
        });
        self.hash_to_node.insert(block.hash, node.clone());
        self.node_to_content.insert(block.hash, content);
        if let Some(parent) = parent {
            parent.children.lock().unwrap().push(node.clone());
        } else {
            self.root_children.push(node.clone());
        }

        let new_final_blocks = self.maybe_update_final_head(block.last_final_block);
        // We must do this lookup before calling prune_old_blocks or else we may no longer have
        // some of the blocks. Note: filter_map should not really filter anything out, but we're
        // doing this defensively to not crash just in case we have a bug.
        let new_final_blocks = new_final_blocks
            .into_iter()
            .filter_map(|node| Some((node.height, self.node_to_content.get(&node.hash)?.clone())))
            .collect();
        match self.canonical_head.as_ref() {
            None => {
                self.update_canonical_head(&node);
            }
            Some(canonical_head) => {
                if block.height > canonical_head.height {
                    self.update_canonical_head(&node);
                }
            }
        }
        if block.height > self.maximum_height_available {
            self.maximum_height_available = block.height;
        }
        self.prune_old_blocks();
        Ok(AddBlockResult { new_final_blocks })
    }

    /// Notifies the tracker that we have heard of the given height being available.
    /// This may move the window forward and cause older blocks to return
    /// `CheckBlockResult::OlderThanRecentWindow`.
    pub fn notify_maximum_height_available(&mut self, height: u64) {
        if height > self.maximum_height_available {
            self.maximum_height_available = height;
            self.prune_old_blocks();
        }
    }

    /// Update the final head if the new final head received from a block is newer.
    /// Returns the list of newly finalized blocks in increasing height order.
    fn maybe_update_final_head(&mut self, potential_final_head: CryptoHash) -> Vec<Arc<BlockNode>> {
        let final_head_node = self.hash_to_node.get(&potential_final_head);
        let mut new_final_blocks = Vec::new();
        if let Some(final_head_node) = final_head_node {
            let mut node = final_head_node.clone();
            loop {
                if node.is_final.load(Ordering::Relaxed) {
                    break;
                }
                node.is_final.store(true, Ordering::Relaxed);
                new_final_blocks.push(node.clone());
                let Some(parent) = node.parent.lock().unwrap().clone() else {
                    break;
                };
                node = parent;
            }
            if self
                .final_head
                .as_ref()
                .is_none_or(|prev_final_head| prev_final_head.height < final_head_node.height)
            {
                self.final_head = Some(final_head_node.clone());
            }
        }
        new_final_blocks.reverse();
        new_final_blocks
    }

    /// Updates the canonical chain to the chain of the given block.
    /// Nodes on the existing canonical chain that are not in the new canonical chain
    /// will be marked as no longer canonical.
    fn update_canonical_head(&mut self, new_canonical_head: &Arc<BlockNode>) {
        let mut node = Some(new_canonical_head.clone());

        while let Some(current_node) = node {
            if current_node.canonical.load(Ordering::Relaxed) {
                node = Some(current_node);
                break;
            }
            current_node.canonical.store(true, Ordering::Relaxed);
            node = current_node.parent.lock().unwrap().clone();
        }
        let common_ancestor = node;

        let mut old_node = self.canonical_head.clone();
        while let Some(current_node) = old_node {
            if let Some(common_ancestor) = &common_ancestor {
                if Arc::ptr_eq(&current_node, common_ancestor) {
                    break;
                }
            }
            current_node.canonical.store(false, Ordering::Relaxed);
            old_node = current_node.parent.lock().unwrap().clone();
        }
        self.canonical_head = Some(new_canonical_head.clone());
    }

    /// Calculates the minimum height of blocks that we need to keep.
    /// This is typically canonical_head.height - window_size + 1, but in case of delayed finality,
    /// we ensure that the final head is not pruned. Otherwise, not only would the logic be very
    /// messy, but also we would not be able to provide a contiguous stream of finalized blocks.
    fn minimum_height_to_keep(&self) -> Option<u64> {
        let Some(final_head) = &self.final_head else {
            return None;
        };
        Some(
            self.maximum_height_available
                .saturating_sub(self.window_size)
                .add(1)
                .min(final_head.height),
        )
    }

    /// Remove old blocks that are neither needed for the `classify_block` query or for providing
    /// the stream of finalized blocks.
    fn prune_old_blocks(&mut self) {
        let Some(minimum_height_to_keep) = self.minimum_height_to_keep() else {
            return;
        };
        // Note: unwrap_or cannot fail because if we have a minimum height then we have at least one
        // block. Still, we'll program defensively.
        if self
            .root_children
            .iter()
            .map(|child| child.height)
            .min()
            .unwrap_or(0)
            >= minimum_height_to_keep
        {
            return;
        }

        let mut new_root_children = Vec::new();
        let mut old_nodes = Vec::new();
        for child in &self.root_children {
            child.closest_descendants_with_height_at_least(
                minimum_height_to_keep,
                &mut new_root_children,
                &mut old_nodes,
            );
        }
        for child in &new_root_children {
            *child.parent.lock().unwrap() = None;
        }
        self.root_children = new_root_children;
        for old_node in old_nodes {
            self.hash_to_node.remove(&old_node.hash);
            self.node_to_content.remove(&old_node.hash);
        }
    }

    /// Classifies a block into one of the categories in `CheckBlockResult`.
    pub fn classify_block(&self, block_hash: CryptoHash, block_height: u64) -> CheckBlockResult {
        if self
            .maximum_height_available
            .saturating_sub(self.window_size)
            .add(1)
            > block_height
        {
            return CheckBlockResult::OlderThanRecentWindow;
        }
        match self.hash_to_node.get(&block_hash) {
            Some(node) => {
                if node.is_final.load(Ordering::Relaxed) {
                    return CheckBlockResult::RecentAndFinal;
                }
                if let Some(final_head) = &self.final_head {
                    if block_height <= final_head.height {
                        return CheckBlockResult::NotIncluded;
                    }
                }
                if node.canonical.load(Ordering::Relaxed) {
                    return CheckBlockResult::OptimisticAndCanonical;
                }
                CheckBlockResult::OptimisticButNotCanonical
            }
            None => {
                // At this point, the block is recent enough but we have not seen it yet.
                // We could do a few more checks to narrow down the case, but it's not really
                // worth the complexity. So just return Unknown.
                CheckBlockResult::Unknown
            }
        }
    }
}

impl<T: Clone + Debug> Debug for RecentBlocksTracker<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "   Recent blocks: (Window = {} to {}, GC limit {})",
            self.maximum_height_available
                .saturating_sub(self.window_size)
                .add(1),
            self.maximum_height_available,
            self.minimum_height_to_keep().unwrap_or(0)
        )?;
        let final_head = self.final_head.as_ref().map(|n| n.hash);
        let canonical_head = self.canonical_head.as_ref().map(|n| n.hash);

        for (i, child) in self.root_children.iter().enumerate() {
            child.debug_print(
                f,
                &mut vec![if i + 1 == self.root_children.len() {
                    2
                } else {
                    3
                }],
                final_head,
                canonical_head,
                &|hash, f| {
                    if let Some(content) = self.node_to_content.get(hash) {
                        write!(f, "{:?}", content)
                    } else {
                        write!(f, "")
                    }
                },
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    use super::{BlockViewLite, RecentBlocksTracker};
    use crate::signing::recent_blocks_tracker::CheckBlockResult;
    use near_indexer::near_primitives::hash::hash;
    use near_indexer_primitives::CryptoHash;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    pub struct TestBlock {
        hash: CryptoHash,
        height: u64,
        parent: Option<Arc<TestBlock>>,

        tester: Arc<TestBlockMaker>,
        next_fork_seed: AtomicU64,
    }

    pub struct TestBlockMaker {
        root_blocks: Mutex<Vec<Arc<TestBlock>>>,
        final_head: Mutex<Option<Arc<TestBlock>>>,
    }

    impl TestBlock {
        pub fn height(&self) -> u64 {
            self.height
        }

        pub fn last_final_block(self: &TestBlock) -> Option<Arc<TestBlock>> {
            let parent = self.parent.as_ref()?;
            let grandparent = parent.parent.as_ref()?;
            if grandparent.height + 1 == parent.height && parent.height + 1 == self.height {
                return Some(grandparent.clone());
            }
            parent.last_final_block()
        }

        pub fn to_block_view(&self) -> BlockViewLite {
            let parent_hash = match self.parent.clone() {
                Some(parent) => parent.hash,
                None => {
                    // Invent some parent hash
                    let bytes = self
                        .hash
                        .0
                        .iter()
                        .chain(b"parent")
                        .copied()
                        .collect::<Vec<_>>();
                    hash(&bytes)
                }
            };

            let last_final_block_hash = match self.last_final_block() {
                Some(block) => block.hash,
                None => {
                    // Invent some last final block hash
                    let bytes = self
                        .hash
                        .0
                        .iter()
                        .chain(b"last_final_block")
                        .copied()
                        .collect::<Vec<_>>();
                    hash(&bytes)
                }
            };

            BlockViewLite {
                hash: self.hash,
                height: self.height,
                prev_hash: parent_hash,
                last_final_block: last_final_block_hash,
            }
        }

        pub fn child(self: &Arc<TestBlock>, height: u64) -> Arc<TestBlock> {
            assert!(
                height > self.height,
                "Height must be greater than the parent height"
            );

            let next_fork_seed = self.next_fork_seed.load(Ordering::Relaxed);
            self.next_fork_seed
                .store(next_fork_seed + 1, Ordering::Relaxed);

            let hash_seed = self
                .hash
                .0
                .iter()
                .chain(next_fork_seed.to_be_bytes().iter())
                .copied()
                .collect::<Vec<_>>();
            let block = Arc::new(TestBlock {
                hash: hash(&hash_seed),
                height,
                parent: Some(self.clone()),
                tester: self.tester.clone(),
                next_fork_seed: AtomicU64::new(0),
            });
            *self.tester.final_head.lock().unwrap() = block.last_final_block();
            block
        }
    }

    impl TestBlockMaker {
        pub fn new() -> Arc<Self> {
            Self {
                root_blocks: Mutex::new(Vec::new()),
                final_head: Mutex::new(None),
            }
            .into()
        }

        pub fn block(self: &Arc<Self>, height: u64) -> Arc<TestBlock> {
            let hash_seed: Vec<u8> = b"root"
                .iter()
                .chain(self.root_blocks.lock().unwrap().len().to_be_bytes().iter())
                .copied()
                .collect();
            let block = Arc::new(TestBlock {
                hash: hash(&hash_seed),
                height,
                parent: None,
                tester: self.clone(),
                next_fork_seed: AtomicU64::new(0),
            });
            self.root_blocks.lock().unwrap().push(block.clone());
            block
        }
    }

    pub struct Tester {
        maker: Arc<TestBlockMaker>,
        tracker: RecentBlocksTracker<String>,
        parents_of_added_blocks: HashSet<CryptoHash>,
    }

    impl Tester {
        pub fn new(heights_to_keep: u64) -> Self {
            let maker = TestBlockMaker::new();
            let tracker = RecentBlocksTracker::new(heights_to_keep);
            Self {
                maker,
                tracker,
                parents_of_added_blocks: HashSet::new(),
            }
        }

        pub fn block(&self, height: u64) -> Arc<TestBlock> {
            self.maker.block(height)
        }

        pub fn check(&self, block: &Arc<TestBlock>) -> CheckBlockResult {
            self.tracker.classify_block(block.hash, block.height)
        }

        pub fn add(&mut self, block: &Arc<TestBlock>, name: &str) -> String {
            assert!(
                !self.parents_of_added_blocks.contains(&block.hash),
                "Cannot retroactively add the parent of an already added block"
            );
            let result = self
                .tracker
                .add_block(&block.to_block_view(), name.to_string())
                .unwrap();
            if let Some(parent) = block.parent.clone() {
                self.parents_of_added_blocks.insert(parent.hash);
            }
            result
                .new_final_blocks
                .iter()
                .map(|(_, name)| name.clone())
                .collect::<Vec<_>>()
                .join(",")
        }

        pub fn avail(&mut self, height: u64) -> &mut Self {
            self.tracker.notify_maximum_height_available(height);
            self
        }

        pub fn print(&self) {
            println!("{:?}", self.tracker);
        }
    }

    #[test]
    fn test_no_forks() {
        let mut tester = Tester::new(4);
        let b10 = tester.block(10);
        let b11 = b10.child(11);
        let b12 = b11.child(12);
        let b13 = b12.child(13);
        let b14 = b13.child(14);
        let b15 = b14.child(15);
        let b16 = b15.child(16);

        assert_eq!(&tester.add(&b11, "11"), "");
        assert_eq!(&tester.add(&b12, "12"), "");
        assert_eq!(&tester.add(&b13, "13"), "11");
        assert_eq!(&tester.add(&b14, "14"), "12");
        assert_eq!(&tester.add(&b15, "15"), "13");
        //    Recent blocks: (Window = 12 to 15, GC limit 12)
        //    └─[12] C F 7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "12"
        // FH   [13] C F DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "13"
        //      [14] C   4q6agzf1AcZWcVbNnULR8969K8MhmPCEJ7pKapjmEGmA "14"
        // CH   [15] C   7inNzFR4mz4TRu9CSajNQnWxwhKDcYzTYubtM6zFri7Y "15"
        tester.print();

        // At this point, the tracker should keep blocks 12, 13, 14, 15.
        assert_eq!(tester.check(&b10), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(tester.check(&b11), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(tester.check(&b12), CheckBlockResult::RecentAndFinal);
        assert_eq!(tester.check(&b13), CheckBlockResult::RecentAndFinal);
        assert_eq!(tester.check(&b14), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(tester.check(&b15), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(tester.check(&b16), CheckBlockResult::Unknown);

        // We received announcement that block 17 is already available.
        tester.avail(17);
        //    Recent blocks: (Window = 14 to 17, GC limit 13)
        // FH └─[13] C F DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "13"
        //      [14] C   4q6agzf1AcZWcVbNnULR8969K8MhmPCEJ7pKapjmEGmA "14"
        // CH   [15] C   7inNzFR4mz4TRu9CSajNQnWxwhKDcYzTYubtM6zFri7Y "15"
        tester.print();
        assert_eq!(tester.check(&b10), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(tester.check(&b11), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(tester.check(&b12), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(tester.check(&b13), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(tester.check(&b14), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(tester.check(&b15), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(tester.check(&b16), CheckBlockResult::Unknown);
    }

    #[test]
    fn test_simple_forks() {
        let mut t = Tester::new(5);
        let b10 = t.block(10);
        let b11 = b10.child(11);
        let b12 = b11.child(12);
        let b13 = b12.child(13);
        // Start forks (last final block is 11)
        let b14 = b12.child(14);
        let b15 = b13.child(15);
        let b16 = b12.child(16);
        let b17 = b13.child(17);

        assert_eq!(&t.add(&b11, "11"), "");
        assert_eq!(&t.add(&b12, "12"), "");
        assert_eq!(&t.add(&b13, "13"), "11");
        assert_eq!(&t.add(&b14, "14"), "");
        assert_eq!(&t.add(&b16, "16"), "");
        assert_eq!(&t.add(&b15, "15"), "");

        //    Recent blocks: (Window = 12 to 16, GC limit 11)
        // FH └─[11] C F F1BKWCCxzv7PtiVZxLMx3HQuuxDGcrtPRT2FaGgRggpA "11"
        //      [12] C   7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "12"
        //      ├─[13]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "13"
        //      │ [15]     4q6agzf1AcZWcVbNnULR8969K8MhmPCEJ7pKapjmEGmA "15"
        //      ├─[14]     DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "14"
        // CH   └─[16] C   81v6keTjdkVp8RgTdWQE2vx7E7nof7NxtZNaYFh3oVpG "16"
        t.print();

        assert_eq!(t.check(&b10), CheckBlockResult::OlderThanRecentWindow);
        // The tracker kept the block internally as it is the last final block, but it is still
        // outside of the window.
        assert_eq!(t.check(&b11), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b12), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b13), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b14), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b15), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b16), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b17), CheckBlockResult::Unknown);

        let b18 = b14.child(18);
        assert_eq!(&t.add(&b18, "18"), "");
        //    Recent blocks: (Window = 14 to 18, GC limit 11)
        // FH └─[11] C F F1BKWCCxzv7PtiVZxLMx3HQuuxDGcrtPRT2FaGgRggpA "11"
        //      [12] C   7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "12"
        //      ├─[13]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "13"
        //      │ [15]     4q6agzf1AcZWcVbNnULR8969K8MhmPCEJ7pKapjmEGmA "15"
        //      ├─[14] C   DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "14"
        // CH   │ [18] C   GHjy91467tR3nyE2ycq9JM4MH22ZoBZCrkXSEFnT7Vhp "18"
        //      └─[16]     81v6keTjdkVp8RgTdWQE2vx7E7nof7NxtZNaYFh3oVpG "16"
        t.print();

        assert_eq!(t.check(&b13), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b14), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b16), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b18), CheckBlockResult::OptimisticAndCanonical);

        let b19 = b18.child(19);
        let b20 = b19.child(20);
        assert_eq!(&t.add(&b19, "19"), "");
        assert_eq!(&t.add(&b20, "20"), "12,14,18");

        //    Recent blocks: (Window = 16 to 20, GC limit 16)
        // FH ├─[18] C F GHjy91467tR3nyE2ycq9JM4MH22ZoBZCrkXSEFnT7Vhp "18"
        //    │ [19] C   DtoqtibWnNxpvqwgXUXDMrawHNQPP2AC8p3fjdiZvtKg "19"
        // CH │ [20] C   24aEbuUrHRACVS8Ty27pbWnBygML7QBttQo44trWLen7 "20"
        //    └─[16]     81v6keTjdkVp8RgTdWQE2vx7E7nof7NxtZNaYFh3oVpG "16"
        t.print();

        assert_eq!(t.check(&b14), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b15), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b16), CheckBlockResult::NotIncluded);
        assert_eq!(t.check(&b17), CheckBlockResult::Unknown);
        assert_eq!(t.check(&b18), CheckBlockResult::RecentAndFinal);
        assert_eq!(t.check(&b19), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b20), CheckBlockResult::OptimisticAndCanonical);

        // We receive announcement that block 21 is already available.
        t.avail(21);
        t.print();
        assert_eq!(t.check(&b16), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b17), CheckBlockResult::Unknown);
        assert_eq!(t.check(&b18), CheckBlockResult::RecentAndFinal);
        assert_eq!(t.check(&b19), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b20), CheckBlockResult::OptimisticAndCanonical);
    }

    #[test]
    fn test_complex_forks() {
        let mut t = Tester::new(5);
        let b = t.block(2);
        let b0 = b.child(4);
        let b00 = b0.child(6);
        let b000 = b00.child(8);
        let b001 = b00.child(9);
        let b01 = b0.child(7);
        let b010 = b01.child(9);
        let b011 = b01.child(10);
        let b1 = b.child(5);
        let b10 = b1.child(6);
        let b100 = b10.child(8);
        let b101 = b10.child(8);
        let b11 = b1.child(7);
        let b110 = b11.child(9);
        let b111 = b11.child(10);

        assert_eq!(&t.add(&b0, "b0"), "");
        assert_eq!(&t.add(&b00, "b00"), "");
        assert_eq!(&t.add(&b000, "b000"), "");
        assert_eq!(&t.add(&b001, "b001"), "");
        assert_eq!(&t.add(&b01, "b01"), "");
        assert_eq!(&t.add(&b010, "b010"), "");
        assert_eq!(&t.add(&b011, "b011"), "");
        assert_eq!(&t.add(&b1, "b1"), "");
        assert_eq!(&t.add(&b10, "b10"), "");
        assert_eq!(&t.add(&b100, "b100"), "");
        assert_eq!(&t.add(&b101, "b101"), "");
        assert_eq!(&t.add(&b11, "b11"), "");
        assert_eq!(&t.add(&b110, "b110"), "");
        assert_eq!(&t.add(&b111, "b111"), "");

        //    Recent blocks: (Window = 6 to 10, GC limit 0)
        //    ├─[4] C   F1BKWCCxzv7PtiVZxLMx3HQuuxDGcrtPRT2FaGgRggpA "b0"
        //    │ ├─[6]     7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "b00"
        //    │ │ ├─[8]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "b000"
        //    │ │ └─[9]     DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "b001"
        //    │ └─[7] C   8FoDbEfMuYmtr7SXRPiscHR4mQ6m5nCyuca43eAopktY "b01"
        //    │   ├─[9]     8jRJjsyqjoAbyWbjLXTjFNiKTwT8s4xspouvRaZGfh6R "b010"
        // CH │   └─[10] C   CnbxNBi2SVDZo9z8V8kwrmE3pUkozpDvpCCg9Tq25rY3 "b011"
        //    └─[5]     FsmQgeGtsztQh7aaRtaj59JToK91VqiRyRqXXRN85ZAA "b1"
        //      ├─[6]     6s7VNQLN9b4SpwUdEq8LqKwBjf8SqUuutACcMtHwULu8 "b10"
        //      │ ├─[8]     GounuZUfMmxdVequL65iUm7D94sKYg67Q34Z5cjRjZ71 "b100"
        //      │ └─[8]     7aXqE7cPZt6FnVcpytqW3oy5y2E17X9Gpgs6C7praap5 "b101"
        //      └─[7]     2xhND7PwiNZckwCnXFa25wMG1G8JWfKN2Sinmbz3W6xK "b11"
        //        ├─[9]     6E2vqjZLbuUY2y6VK571Ai3pk43EUHXuNxibJuBGh44T "b110"
        //        └─[10]     Cq9uMZqNZr6zuF7nT6yfGms1ptaVVu5dAdiRJ6pqCTN8 "b111"
        t.print();
        assert_eq!(t.check(&b0), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b00), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b000), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b01), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b010), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b011), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b1), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b10), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b100), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b11), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b110), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b111), CheckBlockResult::OptimisticButNotCanonical);

        // Now, we test some pathological cases where the data being given is not consistent
        // with Near blockchain's behavior. Still, we want reasonable behavior and no crashes.
        let b102 = b10.child(7);
        let b1020 = b102.child(8);
        assert_eq!(t.add(&b102, "b102"), "b1");
        assert_eq!(t.add(&b1020, "b1020"), "b10");
        //    Recent blocks: (Window = 6 to 10, GC limit 6)
        //    ├─[6]     7wk1ewkZKmCNLRRhCrjFuoYy1K94dis9qAUv7JUKzCkG "b00"
        //    │ ├─[8]     DTYziqMhQ9i2wbruEfoNiWZNp34dzVYto6FLy3FUZKwt "b000"
        //    │ └─[9]     DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "b001"
        //    ├─[7] C   8FoDbEfMuYmtr7SXRPiscHR4mQ6m5nCyuca43eAopktY "b01"
        //    │ ├─[9]     8jRJjsyqjoAbyWbjLXTjFNiKTwT8s4xspouvRaZGfh6R "b010"
        // CH │ └─[10] C   CnbxNBi2SVDZo9z8V8kwrmE3pUkozpDvpCCg9Tq25rY3 "b011"
        // FH ├─[6]   F 6s7VNQLN9b4SpwUdEq8LqKwBjf8SqUuutACcMtHwULu8 "b10"
        //    │ ├─[8]     GounuZUfMmxdVequL65iUm7D94sKYg67Q34Z5cjRjZ71 "b100"
        //    │ ├─[8]     7aXqE7cPZt6FnVcpytqW3oy5y2E17X9Gpgs6C7praap5 "b101"
        //    │ └─[7]     FK5PX18pxwwtaB6AvYjNkWZ4Jvnn2HeNx4tknkM5g7VP "b102"
        //    │   [8]     AQif6GckVVDt4L4rUeAN43PNComjsa7fPYAF5NHW7oX8 "b1020"
        //    └─[7]     2xhND7PwiNZckwCnXFa25wMG1G8JWfKN2Sinmbz3W6xK "b11"
        //      ├─[9]     6E2vqjZLbuUY2y6VK571Ai3pk43EUHXuNxibJuBGh44T "b110"
        //      └─[10]     Cq9uMZqNZr6zuF7nT6yfGms1ptaVVu5dAdiRJ6pqCTN8 "b111"
        //
        // Note above: the canonical head is not a descendant of final head. This can't happen in
        // the real blockchain, but here we fed in a pathological scenario.
        t.print();
        assert_eq!(t.check(&b0), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b00), CheckBlockResult::NotIncluded);
        // Note: b000 has no chance of being included in the canonical chain due to b10 being final.
        // However, checking that case is not worth the complexity. In practice, the check we use of
        // checking the height against the final head's height is likely good enough.
        assert_eq!(t.check(&b000), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b01), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b010), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b011), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b1), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b10), CheckBlockResult::RecentAndFinal);
        assert_eq!(t.check(&b100), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b11), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b110), CheckBlockResult::OptimisticButNotCanonical);
        assert_eq!(t.check(&b111), CheckBlockResult::OptimisticButNotCanonical);

        let b10200 = b1020.child(11);
        let b102000 = b10200.child(12);
        let b1020000 = b102000.child(13);
        assert_eq!(&t.add(&b10200, "b10200"), "");
        assert_eq!(&t.add(&b102000, "b102000"), "");
        assert_eq!(&t.add(&b1020000, "b1020000"), "b102,b1020,b10200");

        //    Recent blocks: (Window = 9 to 13, GC limit 9)
        //    ├─[9]     DC88XsXQdWZXipUU4vRHQqYo22nwtGVnp3rHptw44mJz "b001"
        //    ├─[9]     8jRJjsyqjoAbyWbjLXTjFNiKTwT8s4xspouvRaZGfh6R "b010"
        //    ├─[10]     CnbxNBi2SVDZo9z8V8kwrmE3pUkozpDvpCCg9Tq25rY3 "b011"
        // FH ├─[11] C F NW4CWxr6ptWa9tsV2gMhGPdE7ecNWfCrnJDfJwx9yv9 "b10200"
        //    │ [12] C   4Vwtcagaq6fi5j82suG4j8HiaU3SMbqotrZzT3bjqwcP "b102000"
        // CH │ [13] C   GktyudcCf3dBkWCdjq9dFssY7KZRRZQJ1TZH3ZMw8LWk "b1020000"
        //    ├─[9]     6E2vqjZLbuUY2y6VK571Ai3pk43EUHXuNxibJuBGh44T "b110"
        //    └─[10]     Cq9uMZqNZr6zuF7nT6yfGms1ptaVVu5dAdiRJ6pqCTN8 "b111"
        t.print();
        assert_eq!(t.check(&b001), CheckBlockResult::NotIncluded);
        assert_eq!(t.check(&b010), CheckBlockResult::NotIncluded);
        assert_eq!(t.check(&b011), CheckBlockResult::NotIncluded);
        assert_eq!(t.check(&b10200), CheckBlockResult::RecentAndFinal);
        assert_eq!(t.check(&b102000), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b1020000), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b110), CheckBlockResult::NotIncluded);
        assert_eq!(t.check(&b111), CheckBlockResult::NotIncluded);

        // We receive announcement that block 15 is already available.
        t.avail(15);
        //    Recent blocks: (Window = 11 to 15, GC limit 11)
        // FH └─[11] C F NW4CWxr6ptWa9tsV2gMhGPdE7ecNWfCrnJDfJwx9yv9 "b10200"
        //      [12] C   4Vwtcagaq6fi5j82suG4j8HiaU3SMbqotrZzT3bjqwcP "b102000"
        // CH   [13] C   GktyudcCf3dBkWCdjq9dFssY7KZRRZQJ1TZH3ZMw8LWk "b1020000"
        t.print();
        assert_eq!(t.check(&b001), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b010), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b011), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b10200), CheckBlockResult::RecentAndFinal);
        assert_eq!(t.check(&b102000), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b1020000), CheckBlockResult::OptimisticAndCanonical);
        assert_eq!(t.check(&b110), CheckBlockResult::OlderThanRecentWindow);
        assert_eq!(t.check(&b111), CheckBlockResult::OlderThanRecentWindow);
    }
}
