use serde::{Deserialize, Serialize};

pub type Hash = [u8; 32];
pub type PublicKey = [u8; 32];
pub type Signature = [u8; 64];
/// Unique, randomly-generated identifier for one game instance.
pub type GameId = [u8; 32];

/// Depth of the Sparse Merkle Tree. Depth 4 → 16 leaves (indices 0–15).
/// Board cells use indices 0–8 (y*3+x); indices 9–15 are permanently Empty.
pub const TREE_DEPTH: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Cell {
    Empty,
    X,
    O,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Player {
    X,
    O,
}

impl Player {
    pub fn to_cell(self) -> Cell {
        match self {
            Player::X => Cell::X,
            Player::O => Cell::O,
        }
    }

    pub fn other(self) -> Player {
        match self {
            Player::X => Player::O,
            Player::O => Player::X,
        }
    }
}

/// All mutable game metadata committed alongside the board root.
///
/// Fixed 99-byte serialization (no length ambiguity in the hash preimage):
///   [0..32]  game_id      — isolates state roots across games, preventing cross-game replay
///   [32..64] pubkey_x
///   [64..96] pubkey_y
///   [96]     move_count
///   [97]     next_player  (0 = X, 1 = O)
///   [98]     game_over    (0 = active, 1 = finished)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GameMeta {
    pub game_id: GameId,
    pub pubkey_x: PublicKey,
    pub pubkey_y: PublicKey,
    pub move_count: u8,
    pub next_player: Player,
    pub game_over: bool,
}

impl GameMeta {
    /// Deterministic 99-byte encoding used in state-root preimage.
    pub fn to_bytes(&self) -> [u8; 99] {
        let mut b = [0u8; 99];
        b[0..32].copy_from_slice(&self.game_id);
        b[32..64].copy_from_slice(&self.pubkey_x);
        b[64..96].copy_from_slice(&self.pubkey_y);
        b[96] = self.move_count;
        b[97] = match self.next_player {
            Player::X => 0,
            Player::O => 1,
        };
        b[98] = self.game_over as u8;
        b
    }
}

/// Externally supplied move from a player.
// No serde: the server constructs this directly; [u8; 64] arrays aren't serde-able by default.
#[derive(Debug, Clone)]
pub enum PlayerMove {
    /// One-time initialisation: registers the two players for a specific game.
    /// The server generates `game_id` randomly; the STF binds it into the state root.
    CreateGame {
        game_id: GameId,
        pubkey_x: PublicKey,
        pubkey_y: PublicKey,
    },
    /// Place a mark at (x, y). The signature covers `prior_state_root || [x, y]`.
    /// `prior_state_root` already encodes `game_id` (via GameMeta), so no explicit
    /// game_id is needed here — cross-game replay is impossible.
    Play {
        pubkey: PublicKey,
        signature: Signature,
        x: u8,
        y: u8,
    },
}

/// Merkle inclusion proof for one board cell.
#[derive(Debug, Clone)]
pub struct CellProof {
    pub x: u8,
    pub y: u8,
    /// Authenticated value of this cell in the committed board.
    pub cell: Cell,
    /// Sibling hashes from leaf level (index 0) up toward the root (index TREE_DEPTH-1).
    pub siblings: [Hash; TREE_DEPTH],
}

/// Everything the STF needs beyond the move itself.
/// For CreateGame the witness is empty; for Play it carries the full state
/// decommitment plus the minimal set of cell proofs.
#[derive(Debug, Clone)]
pub enum Witness {
    CreateGame,
    Play {
        game_meta: GameMeta,
        board_root: Hash,
        /// Proofs for every cell on any win-check line through the played cell.
        cell_proofs: Vec<CellProof>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Winner {
    X,
    O,
    Draw,
}
