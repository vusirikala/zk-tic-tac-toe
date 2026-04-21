//! State Transition Function (STF) — the pure core of the zkVM program.
//!
//! `stf` has no I/O and no side effects. It accepts the prior committed state,
//! a player move, and the minimal witness needed to validate that move, and
//! returns the new committed state root together with an optional game result.

use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::{
    merkle::{cell_index, empty_board_root, updated_root, verify_proof},
    types::*,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum StfError {
    #[error("witness type does not match move type")]
    WitnessMismatch,
    #[error("game already exists (prior root is not zero)")]
    GameAlreadyExists,
    #[error("game is over")]
    GameOver,
    #[error("state commitment mismatch: witness is inconsistent with prior root")]
    StateCommitmentMismatch,
    #[error("coordinate out of range: ({0},{1})")]
    InvalidCoords(u8, u8),
    #[error("not this player's turn")]
    NotYourTurn,
    #[error("invalid public key bytes")]
    InvalidPublicKey,
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("invalid Merkle proof for cell ({0},{1})")]
    InvalidMerkleProof(u8, u8),
    #[error("cell ({0},{1}) is already occupied")]
    CellOccupied(u8, u8),
    #[error("missing required cell proof for ({0},{1})")]
    MissingCellProof(u8, u8),
}

// ---------------------------------------------------------------------------
// State-root construction
// ---------------------------------------------------------------------------

/// `state_root = SHA-256( game_meta.to_bytes() || board_root )`
fn state_root(meta: &GameMeta, board_root: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update(meta.to_bytes());
    h.update(board_root);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Signature message construction
// ---------------------------------------------------------------------------

/// The message a player signs when they want to play at (x, y) from a given state.
/// Binds the move to the exact prior state, preventing replay.
pub fn play_message(prior_state_root: &Hash, x: u8, y: u8) -> [u8; 34] {
    let mut msg = [0u8; 34];
    msg[..32].copy_from_slice(prior_state_root);
    msg[32] = x;
    msg[33] = y;
    msg
}

// ---------------------------------------------------------------------------
// Win-check helpers
// ---------------------------------------------------------------------------

/// Returns the deduplicated set of board cells whose Merkle proofs are required
/// to verify all win-check lines through the cell at `(x, y)`.
///
/// Only lines that pass through the played cell can be completed by this move,
/// so we only include those lines — and nothing else.
pub fn required_cells(x: u8, y: u8) -> Vec<(u8, u8)> {
    let mut set = std::collections::BTreeSet::new();

    // Row y
    for xi in 0u8..3 {
        set.insert((xi, y));
    }
    // Column x
    for yi in 0u8..3 {
        set.insert((x, yi));
    }
    // Main diagonal (top-left → bottom-right)
    if x == y {
        for i in 0u8..3 {
            set.insert((i, i));
        }
    }
    // Anti-diagonal (top-right → bottom-left)
    if x + y == 2 {
        set.insert((0, 2));
        set.insert((1, 1));
        set.insert((2, 0));
    }

    set.into_iter().collect()
}

fn find_cell<'a>(proofs: &'a [CellProof], x: u8, y: u8) -> Option<&'a CellProof> {
    proofs.iter().find(|p| p.x == x && p.y == y)
}

/// Check whether `mark` has won on any line through `(px, py)`.
/// `get` returns the cell value at a coordinate (using the post-move board).
fn has_won(px: u8, py: u8, mark: Cell, get: impl Fn(u8, u8) -> Cell) -> bool {
    let all = |coords: &[(u8, u8)]| coords.iter().all(|&(x, y)| get(x, y) == mark);

    // Row
    if all(&[(0, py), (1, py), (2, py)]) {
        return true;
    }
    // Column
    if all(&[(px, 0), (px, 1), (px, 2)]) {
        return true;
    }
    // Main diagonal
    if px == py && all(&[(0, 0), (1, 1), (2, 2)]) {
        return true;
    }
    // Anti-diagonal
    if px + py == 2 && all(&[(0, 2), (1, 1), (2, 0)]) {
        return true;
    }

    false
}

// ---------------------------------------------------------------------------
// STF
// ---------------------------------------------------------------------------

/// Pure state-transition function.
///
/// # Arguments
/// * `prior_state_root` — commitment to the previous game state; `[0u8;32]` means no game yet
/// * `mv`              — the player's move
/// * `witness`         — auxiliary data needed to validate `mv` against `prior_state_root`
///
/// # Returns
/// `(new_state_root, Option<Winner>)` on success, or an `StfError` if the move is invalid.
pub fn stf(
    prior_state_root: Hash,
    mv: PlayerMove,
    witness: Witness,
) -> Result<(Hash, Option<Winner>), StfError> {
    match (mv, witness) {
        // ------------------------------------------------------------------
        // CreateGame — one-time initialisation
        // ------------------------------------------------------------------
        (PlayerMove::CreateGame { game_id, pubkey_x, pubkey_y }, Witness::CreateGame) => {
            if prior_state_root != [0u8; 32] {
                return Err(StfError::GameAlreadyExists);
            }

            let meta = GameMeta {
                game_id,
                pubkey_x,
                pubkey_y,
                move_count: 0,
                next_player: Player::X,
                game_over: false,
            };
            let board_root = empty_board_root();
            Ok((state_root(&meta, &board_root), None))
        }

        // ------------------------------------------------------------------
        // Play — place a mark on the board
        // ------------------------------------------------------------------
        (
            PlayerMove::Play { pubkey, signature, x, y },
            Witness::Play { game_meta, board_root, cell_proofs },
        ) => {
            // 1. Re-derive state root from witness and compare with prior root
            if state_root(&game_meta, &board_root) != prior_state_root {
                return Err(StfError::StateCommitmentMismatch);
            }

            // 2. Game must still be active
            if game_meta.game_over {
                return Err(StfError::GameOver);
            }

            // 3. Coordinate bounds
            if x > 2 || y > 2 {
                return Err(StfError::InvalidCoords(x, y));
            }

            // 4. Correct player's turn
            let expected_pubkey = match game_meta.next_player {
                Player::X => game_meta.pubkey_x,
                Player::O => game_meta.pubkey_y,
            };
            if pubkey != expected_pubkey {
                return Err(StfError::NotYourTurn);
            }

            // 5. Signature: player signs (prior_state_root || x || y)
            let vk = VerifyingKey::from_bytes(&pubkey)
                .map_err(|_| StfError::InvalidPublicKey)?;
            let sig = Ed25519Sig::from_bytes(&signature);
            let msg = play_message(&prior_state_root, x, y);
            vk.verify(&msg, &sig).map_err(|_| StfError::InvalidSignature)?;

            // 6. Verify Merkle proofs for every cell on a win-check line through (x,y)
            for &(cx, cy) in &required_cells(x, y) {
                let proof = find_cell(&cell_proofs, cx, cy)
                    .ok_or(StfError::MissingCellProof(cx, cy))?;
                if !verify_proof(&board_root, cx, cy, proof.cell, &proof.siblings) {
                    return Err(StfError::InvalidMerkleProof(cx, cy));
                }
            }

            // 7. Played cell must be empty
            let played_proof = find_cell(&cell_proofs, x, y)
                .ok_or(StfError::MissingCellProof(x, y))?;
            if played_proof.cell != Cell::Empty {
                return Err(StfError::CellOccupied(x, y));
            }

            // 8. Compute new board root (siblings are unchanged — only the path to (x,y) changes)
            let new_mark = game_meta.next_player.to_cell();
            let new_board_root = updated_root(cell_index(x, y), new_mark, &played_proof.siblings);

            // 9. Win check using post-move cell values:
            //    • (x,y)   → new_mark  (freshly placed)
            //    • others  → value from their proof (authenticated against prior board_root)
            let get_cell = |cx: u8, cy: u8| -> Cell {
                if cx == x && cy == y {
                    new_mark
                } else {
                    find_cell(&cell_proofs, cx, cy)
                        .map(|p| p.cell)
                        .unwrap_or(Cell::Empty)
                }
            };

            let new_move_count = game_meta.move_count + 1;
            let won = has_won(x, y, new_mark, get_cell);
            let draw = !won && new_move_count == 9;

            let winner = if won {
                Some(match game_meta.next_player {
                    Player::X => Winner::X,
                    Player::O => Winner::O,
                })
            } else if draw {
                Some(Winner::Draw)
            } else {
                None
            };

            let new_meta = GameMeta {
                game_id: game_meta.game_id,
                pubkey_x: game_meta.pubkey_x,
                pubkey_y: game_meta.pubkey_y,
                move_count: new_move_count,
                next_player: game_meta.next_player.other(),
                game_over: winner.is_some(),
            };

            Ok((state_root(&new_meta, &new_board_root), winner))
        }

        _ => Err(StfError::WitnessMismatch),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;
    use ed25519_dalek::SigningKey;

    const GAME_A: GameId = [0xAA; 32];
    const GAME_B: GameId = [0xBB; 32];

    struct TestKeys {
        sk_x: SigningKey,
        sk_o: SigningKey,
        pk_x: PublicKey,
        pk_o: PublicKey,
    }

    fn test_keys() -> TestKeys {
        let sk_x = SigningKey::from_bytes(&[1u8; 32]);
        let sk_o = SigningKey::from_bytes(&[2u8; 32]);
        let pk_x = sk_x.verifying_key().to_bytes();
        let pk_o = sk_o.verifying_key().to_bytes();
        TestKeys { sk_x, sk_o, pk_x, pk_o }
    }

    fn create_game(game_id: GameId, pk_x: PublicKey, pk_o: PublicKey) -> (Hash, GameMeta) {
        let (root, winner) = stf(
            [0u8; 32],
            PlayerMove::CreateGame { game_id, pubkey_x: pk_x, pubkey_y: pk_o },
            Witness::CreateGame,
        )
        .unwrap();
        assert_eq!(winner, None);
        let meta = GameMeta {
            game_id,
            pubkey_x: pk_x,
            pubkey_y: pk_o,
            move_count: 0,
            next_player: Player::X,
            game_over: false,
        };
        (root, meta)
    }

    fn build_witness(meta: &GameMeta, board: &[[Cell; 3]; 3], x: u8, y: u8) -> Witness {
        let tree = MerkleTree::from_board(board);
        let board_root = tree.root();
        let proofs = required_cells(x, y)
            .into_iter()
            .map(|(cx, cy)| CellProof {
                x: cx,
                y: cy,
                cell: board[cy as usize][cx as usize],
                siblings: tree.proof(cell_index(cx, cy)),
            })
            .collect();
        Witness::Play { game_meta: meta.clone(), board_root, cell_proofs: proofs }
    }

    fn sign(sk: &SigningKey, state_root: &Hash, x: u8, y: u8) -> Signature {
        use ed25519_dalek::Signer;
        sk.sign(&play_message(state_root, x, y)).to_bytes()
    }

    #[test]
    fn create_game_once() {
        let k = test_keys();
        let (root, _) = create_game(GAME_A, k.pk_x, k.pk_o);
        let err = stf(
            root,
            PlayerMove::CreateGame { game_id: GAME_A, pubkey_x: k.pk_x, pubkey_y: k.pk_o },
            Witness::CreateGame,
        );
        assert!(matches!(err, Err(StfError::GameAlreadyExists)));
    }

    #[test]
    fn full_game_x_wins() {
        let k = test_keys();
        let (mut state, mut meta) = create_game(GAME_A, k.pk_x, k.pk_o);
        let mut board = [[Cell::Empty; 3]; 3];

        // X wins via top row: (0,0), (1,0), (2,0)
        let moves: &[(u8, u8, Player)] = &[
            (0, 0, Player::X),
            (0, 1, Player::O),
            (1, 0, Player::X),
            (1, 1, Player::O),
            (2, 0, Player::X),
        ];

        for &(x, y, player) in moves {
            let sk = if player == Player::X { &k.sk_x } else { &k.sk_o };
            let pk = if player == Player::X { k.pk_x } else { k.pk_o };
            let sig = sign(sk, &state, x, y);
            let witness = build_witness(&meta, &board, x, y);
            let (new_state, winner) = stf(
                state,
                PlayerMove::Play { pubkey: pk, signature: sig, x, y },
                witness,
            )
            .unwrap();
            board[y as usize][x as usize] = player.to_cell();
            meta.move_count += 1;
            meta.next_player = meta.next_player.other();
            if winner.is_some() { meta.game_over = true; }
            state = new_state;
            if let Some(w) = winner {
                assert_eq!(w, Winner::X);
                return;
            }
        }
        panic!("expected X to win");
    }

    #[test]
    fn occupied_cell_rejected() {
        let k = test_keys();
        let (mut state, mut meta) = create_game(GAME_A, k.pk_x, k.pk_o);
        let mut board = [[Cell::Empty; 3]; 3];

        // X plays (1,1)
        let sig = sign(&k.sk_x, &state, 1, 1);
        let (new_state, _) = stf(
            state,
            PlayerMove::Play { pubkey: k.pk_x, signature: sig, x: 1, y: 1 },
            build_witness(&meta, &board, 1, 1),
        )
        .unwrap();
        board[1][1] = Cell::X;
        state = new_state;
        meta.move_count += 1;
        meta.next_player = Player::O;

        // O tries to play (1,1) — occupied
        let sig = sign(&k.sk_o, &state, 1, 1);
        let err = stf(
            state,
            PlayerMove::Play { pubkey: k.pk_o, signature: sig, x: 1, y: 1 },
            build_witness(&meta, &board, 1, 1),
        );
        assert!(matches!(err, Err(StfError::CellOccupied(1, 1))));
    }

    /// Two concurrent games with the same players produce different state roots
    /// immediately after CreateGame, so a signature from game A cannot be replayed in game B.
    #[test]
    fn cross_game_replay_impossible() {
        let k = test_keys();

        // Create two independent games with the same players
        let (state_a, _meta_a) = create_game(GAME_A, k.pk_x, k.pk_o);
        let (state_b, _meta_b) = create_game(GAME_B, k.pk_x, k.pk_o);

        // Different game_ids → different initial state roots
        assert_ne!(state_a, state_b, "state roots must differ across games");

        // X signs a move for game A at (0,0)
        let sig_for_a = sign(&k.sk_x, &state_a, 0, 0);

        // Attempting to use that signature against game B's state root must fail
        // because the signed message embeds state_a ≠ state_b
        let err = stf(
            state_b,
            PlayerMove::Play { pubkey: k.pk_x, signature: sig_for_a, x: 0, y: 0 },
            build_witness(&_meta_b, &[[Cell::Empty; 3]; 3], 0, 0),
        );
        assert!(matches!(err, Err(StfError::InvalidSignature)));
    }
}
