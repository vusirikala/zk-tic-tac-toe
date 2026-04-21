//! Hand-rolled depth-4 Sparse Merkle Tree over a 3×3 Tic-Tac-Toe board.
//!
//! ## Layout
//!
//! ```text
//! Depth 4  →  16 leaves, indexed 0..=15
//! Board mapping: index = y * 3 + x   (indices 0..=8 used, 9..=15 always Empty)
//!
//! Root (depth 0)
//!  ├── [0..7]   (depth 1, left)
//!  │    ├── [0..3]  (depth 2)
//!  │    │    ├── [0,1]  (depth 3)
//!  │    │    │    ├── leaf 0 = (0,0)
//!  │    │    │    └── leaf 1 = (1,0)
//!  │    │    └── [2,3]  (depth 3)
//!  │    │         ├── leaf 2 = (2,0)
//!  │    │         └── leaf 3 = (0,1)
//!  │    └── [4..7]  (depth 2)
//!  │         ├── [4,5]  (depth 3)
//!  │         │    ├── leaf 4 = (1,1)
//!  │         │    └── leaf 5 = (2,1)
//!  │         └── [6,7]  (depth 3)
//!  │              ├── leaf 6 = (0,2)
//!  │              └── leaf 7 = (1,2)
//!  └── [8..15] (depth 1, right)
//!       ├── [8..11] (depth 2)
//!       │    ├── [8,9]   (depth 3) → leaf 8 = (2,2), leaf 9 = unused
//!       │    └── [10,11] (depth 3) → unused
//!       └── [12..15] (depth 2) → all unused
//! ```
//!
//! ## Proof format
//!
//! `siblings[0]` = sibling at leaf level (closest to leaf)
//! `siblings[DEPTH-1]` = sibling closest to root
//!
//! Verification: walk from leaf to root, at bit `k` of the index,
//! bit=0 means we are the left child (sibling is right):
//!   `current = SHA256(current || siblings[k])`
//! bit=1 means we are the right child (sibling is left):
//!   `current = SHA256(siblings[k] || current)`

use sha2::{Digest, Sha256};

use crate::types::{Cell, Hash, TREE_DEPTH};

// ---------------------------------------------------------------------------
// Low-level hash helpers
// ---------------------------------------------------------------------------

pub fn leaf_hash(cell: Cell) -> Hash {
    let byte: u8 = match cell {
        Cell::Empty => 0,
        Cell::X => 1,
        Cell::O => 2,
    };
    Sha256::digest([byte]).into()
}

pub fn merge(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Precomputed empty-subtree hashes
// ---------------------------------------------------------------------------

/// Returns `[h0, h1, h2, h3, h4]` where:
/// - `h0` = hash of an empty leaf
/// - `h_k` = hash of an all-empty subtree of height k
pub fn empty_hashes() -> [Hash; TREE_DEPTH + 1] {
    let mut h = [[0u8; 32]; TREE_DEPTH + 1];
    h[0] = leaf_hash(Cell::Empty);
    for k in 1..=TREE_DEPTH {
        h[k] = merge(&h[k - 1], &h[k - 1]);
    }
    h
}

/// Root of a fully-empty board (all 16 leaves = Empty).
pub fn empty_board_root() -> Hash {
    empty_hashes()[TREE_DEPTH]
}

// ---------------------------------------------------------------------------
// Key / index helpers
// ---------------------------------------------------------------------------

/// Map board coordinate to SMT leaf index.
pub fn cell_index(x: u8, y: u8) -> u8 {
    y * 3 + x
}

// ---------------------------------------------------------------------------
// Proof verification
// ---------------------------------------------------------------------------

/// Recompute the root from `(index, cell, siblings)` and check it equals `root`.
pub fn verify_proof(root: &Hash, x: u8, y: u8, cell: Cell, siblings: &[Hash; TREE_DEPTH]) -> bool {
    &recompute_root(cell_index(x, y), cell, siblings) == root
}

/// Walk from leaf to root using the sibling path, returning the computed root.
pub fn recompute_root(index: u8, cell: Cell, siblings: &[Hash; TREE_DEPTH]) -> Hash {
    let mut cur = leaf_hash(cell);
    for k in 0..TREE_DEPTH {
        let bit = (index >> k) & 1;
        cur = if bit == 0 {
            merge(&cur, &siblings[k])
        } else {
            merge(&siblings[k], &cur)
        };
    }
    cur
}

/// Compute the new root after replacing the cell at `index` with `new_cell`,
/// reusing the same `siblings` (they are all off the updated path).
pub fn updated_root(index: u8, new_cell: Cell, siblings: &[Hash; TREE_DEPTH]) -> Hash {
    recompute_root(index, new_cell, siblings)
}

// ---------------------------------------------------------------------------
// Full-tree builder (used by the server to generate proofs)
// ---------------------------------------------------------------------------

/// In-memory representation of the full depth-4 SMT for a given board state.
/// The server keeps a `[[Cell; 3]; 3]` board and rebuilds this whenever it needs proofs.
pub struct MerkleTree {
    /// `nodes[level]` has `16 >> level` entries.
    /// `nodes[0]` = 16 leaf hashes; `nodes[4]` = 1 root hash.
    nodes: [Vec<Hash>; TREE_DEPTH + 1],
}

impl MerkleTree {
    /// Build the tree from the current board state.
    pub fn from_board(board: &[[Cell; 3]; 3]) -> Self {
        let eh = empty_hashes();
        let mut leaves = vec![eh[0]; 16];

        for y in 0..3usize {
            for x in 0..3usize {
                leaves[y * 3 + x] = leaf_hash(board[y][x]);
            }
        }

        let mut nodes: [Vec<Hash>; TREE_DEPTH + 1] = Default::default();
        nodes[0] = leaves;

        for level in 1..=TREE_DEPTH {
            let prev = &nodes[level - 1];
            let n = prev.len() / 2;
            nodes[level] = (0..n).map(|i| merge(&prev[2 * i], &prev[2 * i + 1])).collect();
        }

        MerkleTree { nodes }
    }

    /// Root hash of this tree.
    pub fn root(&self) -> Hash {
        self.nodes[TREE_DEPTH][0]
    }

    /// Sibling path for the leaf at the given index.
    /// `siblings[0]` is the sibling at leaf level.
    pub fn proof(&self, index: u8) -> [Hash; TREE_DEPTH] {
        let mut siblings = [[0u8; 32]; TREE_DEPTH];
        let mut idx = index as usize;
        for level in 0..TREE_DEPTH {
            let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            siblings[level] = self.nodes[level][sibling];
            idx /= 2;
        }
        siblings
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_board_round_trip() {
        let board = [[Cell::Empty; 3]; 3];
        let tree = MerkleTree::from_board(&board);
        assert_eq!(tree.root(), empty_board_root());
    }

    #[test]
    fn proof_verify_and_update() {
        let mut board = [[Cell::Empty; 3]; 3];
        board[1][1] = Cell::X; // (x=1, y=1) → index 4

        let tree = MerkleTree::from_board(&board);
        let root = tree.root();

        let idx = cell_index(1, 1);
        let siblings = tree.proof(idx);

        // Verify existing value
        assert!(verify_proof(&root, 1, 1, Cell::X, &siblings));
        assert!(!verify_proof(&root, 1, 1, Cell::Empty, &siblings));

        // Compute new root after placing O at (1,1)
        let new_root = updated_root(idx, Cell::O, &siblings);

        // Build a fresh tree with the update applied and compare roots
        board[1][1] = Cell::O;
        let tree2 = MerkleTree::from_board(&board);
        assert_eq!(new_root, tree2.root());
    }

    #[test]
    fn proof_every_cell() {
        let mut board = [[Cell::Empty; 3]; 3];
        for y in 0..3usize {
            for x in 0..3usize {
                board[y][x] = if (x + y) % 2 == 0 { Cell::X } else { Cell::O };
            }
        }
        let tree = MerkleTree::from_board(&board);
        let root = tree.root();
        for y in 0..3u8 {
            for x in 0..3u8 {
                let idx = cell_index(x, y);
                let siblings = tree.proof(idx);
                let cell = board[y as usize][x as usize];
                assert!(verify_proof(&root, x, y, cell, &siblings), "failed at ({x},{y})");
            }
        }
    }
}
