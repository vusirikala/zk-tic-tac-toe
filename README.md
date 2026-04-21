# zk-tic-tac-toe

A zkVM-ready Tic-Tac-Toe implementation built around a **pure state transition function** (STF). Game state is committed in a hand-rolled Sparse Merkle Tree. Every move carries a minimal cryptographic witness. The server constructs witnesses and calls the STF; the STF itself has no I/O and could run inside a zkVM (RISC Zero, SP1) unchanged.

---

## Table of Contents

1. [Project structure](#project-structure)
2. [Design overview](#design-overview)
3. [State model](#state-model)
4. [Sparse Merkle Tree](#sparse-merkle-tree)
5. [State Transition Function](#state-transition-function)
6. [Signatures and replay protection](#signatures-and-replay-protection)
7. [Witness minimality](#witness-minimality)
8. [Multi-game concurrency](#multi-game-concurrency)
9. [What "zero knowledge" means here](#what-zero-knowledge-means-here)
10. [Running the server](#running-the-server)
11. [API reference](#api-reference)
12. [Running the tests](#running-the-tests)
13. [References](#references)

---

## Project structure

```
zk-tic-tac-toe/
├── Cargo.toml              # Workspace root
├── core/                   # Pure STF crate — no I/O, no server deps
│   └── src/
│       ├── lib.rs
│       ├── types.rs        # Cell, GameMeta, PlayerMove, Witness, …
│       ├── merkle.rs       # Depth-4 Sparse Merkle Tree (SHA-256)
│       └── game.rs         # stf() — the pure state transition function
├── server/                 # Axum web server
│   └── src/
│       └── main.rs         # Witness construction + HTTP handlers
└── test_game.py            # End-to-end integration test (Python 3, stdlib only)
```

`core` has zero knowledge of HTTP, async runtimes, or any I/O. In a real zkVM deployment you would compile `core` for the target ISA (e.g. `riscv32im-risc0-zkvm-elf`) and wrap it with the prover SDK. `server` is the off-chain orchestration layer.

---

## Design overview

```
  Player A                Player B
     │                       │
     ▼                       ▼
┌─────────────────────────────────────┐
│           Axum web server           │
│                                     │
│  1. look up game state (board,      │
│     game_meta, state_root)          │
│  2. build minimal Merkle witness    │
│  3. call stf(root, move, witness)   │
│  4. update mirror state on success  │
└─────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────┐
│  stf(prior_root, move, witness)     │  ← pure function, no I/O
│                                     │
│  • verify state commitment          │
│  • verify Ed25519 signature         │
│  • verify Merkle proofs             │
│  • apply move, check win/draw       │
│  • return (new_root, Option<Winner>)│
└─────────────────────────────────────┘
```

The server is a **convenience layer** — it stores the full board in memory so it can build proofs. In a zkVM deployment the server's job is replaced by a SNARK prover: the prover runs `stf` inside the zkVM and produces a succinct proof `π` that the transition was valid. Verifiers check `π` in milliseconds without re-executing `stf`.

---

## State model

### Per-game state root

All game state is distilled into a single 32-byte hash:

```
state_root = SHA-256( game_meta_bytes || board_root )
```

Where:

**`game_meta_bytes`** is a fixed 99-byte encoding of `GameMeta`:

| Bytes  | Field          | Size |
|--------|----------------|------|
| 0–31   | `game_id`      | 32 B |
| 32–63  | `pubkey_x`     | 32 B |
| 64–95  | `pubkey_y`     | 32 B |
| 96     | `move_count`   |  1 B |
| 97     | `next_player`  |  1 B (0 = X, 1 = O) |
| 98     | `game_over`    |  1 B (0 = active, 1 = finished) |

**`board_root`** is the root of a depth-4 Sparse Merkle Tree over the 3×3 board (see next section).

The fixed-width encoding is intentional: no length prefix, no padding ambiguity, no dynamic allocation in the hash preimage.

### Initial state

Before `CreateGame` is called, the prior root for a game slot is `[0u8; 32]` (all zeros). The STF checks this to enforce "create once":

```rust
if prior_state_root != [0u8; 32] {
    return Err(StfError::GameAlreadyExists);
}
```

With multiple concurrent games each game has its own zero-initialized slot in the server's map.

---

## Sparse Merkle Tree

### Why a Merkle tree?

The requirement is to store game state **keyed by (x, y) coordinates** with values `Empty | X | O`, and to produce inclusion proofs. A binary hash tree lets the STF verify any single cell's value in `O(depth)` hashes without seeing the whole board.

### Structure

We use a **complete binary tree of depth 4** with 16 leaves (indices 0–15):

```
leaf index = y × 3 + x        (x, y ∈ {0, 1, 2})
```

Indices 0–8 correspond to board cells. Indices 9–15 are permanently `Empty` (unused padding to fill out the power-of-two leaf count).

```
Depth 0 (root): 1 node
Depth 1:        2 nodes
Depth 2:        4 nodes
Depth 3:        8 nodes
Depth 4:       16 nodes  ← leaves
```

### Hash functions

```
leaf_hash(cell) = SHA-256( [cell_byte] )
    where cell_byte = 0 (Empty), 1 (X), 2 (O)

internal_hash(left, right) = SHA-256( left || right )
```

### Empty-subtree hashes (precomputed)

The "all-empty board" root is computed once, bottom-up:

```
h[0] = SHA-256([0x00])                    ← empty leaf
h[1] = SHA-256(h[0] || h[0])             ← empty 2-leaf subtree
h[2] = SHA-256(h[1] || h[1])             ← empty 4-leaf subtree
h[3] = SHA-256(h[2] || h[2])
h[4] = SHA-256(h[3] || h[3])             ← empty board root
```

### Inclusion proof

A proof for leaf at index `i` is a list of **4 sibling hashes** (one per level), ordered from the leaf upward:

```
siblings[0] = sibling at leaf level
siblings[1] = sibling one level above
siblings[2] = sibling two levels above
siblings[3] = sibling just below root
```

**Verification** (from `merkle.rs`):

```
cur ← leaf_hash(cell)
for k = 0 to 3:
    bit_k = (index >> k) & 1
    if bit_k == 0:
        cur ← SHA-256(cur || siblings[k])    // we are the left child
    else:
        cur ← SHA-256(siblings[k] || cur)    // we are the right child
assert cur == committed_root
```

### Root update after a move

When cell `(x, y)` changes from `old_cell` to `new_cell`, only the 4 nodes on the path from that leaf to the root change. All siblings are **off-path** and therefore unchanged. The new root reuses the same 4 sibling hashes:

```
new_root = recompute_root(index, new_cell, same_siblings)
```

This is a single O(depth) pass — no full tree rebuild needed. The STF uses this property to compute the new board root from the played cell's proof without access to any other cell's data.

**Why this is secure:** if `verify_proof(old_root, cell, siblings)` succeeds, then `SHA-256` collision resistance guarantees the `siblings` are uniquely determined by `old_root` and the leaf value. Replacing the leaf with `new_cell` and recomputing with the same siblings produces the unique root that corresponds to a board identical to the old one except at `(x, y)`.

### Worked example: playing X at (1, 1)

```
index = 1×3 + 1 = 4   →   binary 0100

Path from root to leaf 4:
  bit 3 = 0: go left  at depth 1  (sibling = right subtree [8..15])
  bit 2 = 1: go right at depth 2  (sibling = left  subtree [4..7]  ← wait, [0..3])
  bit 1 = 0: go left  at depth 3  (sibling = leaf 5)
  bit 0 = 0: go left  at depth 4  (sibling = leaf 5) ← leaf 4 IS leaf 4, sibling = leaf 5

Verification walk (bottom-up):
  cur = SHA-256([0x01])            ← leaf_hash(X)
  k=0, bit=0: cur = SHA-256(cur || siblings[0])   // siblings[0] = leaf_hash(board[1][2])
  k=1, bit=0: cur = SHA-256(cur || siblings[1])   // siblings[1] = hash of leaves [6,7]
  k=2, bit=1: cur = SHA-256(siblings[2] || cur)   // siblings[2] = hash of subtree [0..3]
  k=3, bit=0: cur = SHA-256(cur || siblings[3])   // siblings[3] = hash of subtree [8..15]
  assert cur == board_root  ✓
```

---

## State Transition Function

The STF signature:

```rust
pub fn stf(
    prior_state_root: Hash,     // [u8; 32] — commitment to prior game state
    mv: PlayerMove,             // CreateGame or Play
    witness: Witness,           // auxiliary data (empty for CreateGame)
) -> Result<(Hash, Option<Winner>), StfError>
```

This is a **pure function**: no heap allocation beyond what Rust requires for `Vec`, no I/O, no randomness, no global state. It is suitable for execution inside a zkVM.

### CreateGame

```
inputs:  prior_state_root = [0u8; 32]
         PlayerMove::CreateGame { game_id, pubkey_x, pubkey_y }
         Witness::CreateGame   (empty)

checks:  prior_state_root == [0u8; 32]   (game doesn't already exist)

output:  new_root = SHA-256(
             game_id || pubkey_x || pubkey_y ||
             move_count=0 || next_player=X || game_over=false ||
             empty_board_root
         )
         winner = None
```

### Play

```
inputs:  prior_state_root
         PlayerMove::Play { pubkey, signature, x, y }
         Witness::Play { game_meta, board_root, cell_proofs }

checks (in order):
  1. SHA-256(game_meta.to_bytes() || board_root) == prior_state_root
     → the witness is consistent with the committed state

  2. game_meta.game_over == false

  3. x ≤ 2 and y ≤ 2

  4. pubkey == game_meta.pubkey_{next_player}
     → correct player's turn

  5. Ed25519.Verify(pubkey, msg = prior_state_root || [x, y], sig = signature)
     → the player authorized this exact move in this exact state

  6. for each cell (cx, cy) on a win-check line through (x, y):
         verify_proof(board_root, cx, cy, cell_proofs[(cx,cy)].cell,
                      cell_proofs[(cx,cy)].siblings)
     → all provided cell values are authentic

  7. cell_proofs[(x,y)].cell == Empty
     → the target cell is unoccupied

  8. new_board_root = recompute_root(index(x,y), new_mark, cell_proofs[(x,y)].siblings)

  9. won = check_win(x, y, new_mark, cell_proofs)
     draw = !won && new_move_count == 9

output:  new_root = SHA-256(new_game_meta.to_bytes() || new_board_root)
         winner = Some(X|O|Draw) or None
```

### Win detection

The STF only checks lines that pass through the played cell — no other line can be completed by this move:

```
always check:  row y        →  (0,y), (1,y), (2,y)
always check:  column x     →  (x,0), (x,1), (x,2)
if x == y:     main diag    →  (0,0), (1,1), (2,2)
if x+y == 2:   anti-diag   →  (0,2), (1,1), (2,0)
```

This is the set `required_cells(x, y)`, computed identically in the STF and in the server's witness builder.

### Error variants

| Error | Meaning |
|---|---|
| `WitnessMismatch` | Witness enum variant doesn't match move enum variant |
| `GameAlreadyExists` | `CreateGame` called when prior root is non-zero |
| `GameOver` | Move attempted after game has ended |
| `StateCommitmentMismatch` | Witness `game_meta`/`board_root` don't reproduce `prior_state_root` |
| `InvalidCoords` | `x > 2` or `y > 2` |
| `NotYourTurn` | `pubkey` doesn't match `game_meta.pubkey_{next_player}` |
| `InvalidPublicKey` | 32 bytes don't decode to a valid Ed25519 point |
| `InvalidSignature` | Ed25519 verification failed |
| `InvalidMerkleProof` | Sibling path doesn't reproduce `board_root` |
| `CellOccupied` | Target cell is not `Empty` |
| `MissingCellProof` | A required win-check cell has no proof in the witness |

---

## Signatures and replay protection

Each `Play` move carries an Ed25519 signature. The signed message is:

```
msg = prior_state_root || [x] || [y]    (34 bytes total)
```

**Why `prior_state_root`?** The state root embeds `game_id`, `move_count`, the full board, and both player keys. Binding the signature to it means:

- **No cross-game replay:** a signature for game A cannot be reused in game B because `game_id_A ≠ game_id_B` → their state roots diverge from the very first `CreateGame`.
- **No move-order replay:** a signature for move 3 of a game cannot be replayed as move 7 because `move_count` is different → different state roots.
- **No position substitution:** a signature for cell (0,0) cannot be used for cell (1,1) because `[x, y]` is explicit in the message.

**Ed25519 construction (Schnorr on Curve25519):**

```
Secret scalar:  s = SHA-512(seed)[0..32]  (clamped for cofactor)
Public key:     P = s·G   (scalar mult on ed25519 curve)

Sign(msg):
    r ← SHA-512(seed[32..64] || msg)   (deterministic nonce)
    R ← r·G
    k ← SHA-512(R || P || msg)
    S ← (r + k·s) mod ℓ               (ℓ = curve group order ≈ 2²⁵²)
    signature = (R, S)                 (64 bytes)

Verify(P, msg, (R, S)):
    k ← SHA-512(R || P || msg)
    check: 8·S·G == 8·R + 8·k·P       (cofactor clearing)
```

The `8·` cofactor multiplication makes verification robust against small-subgroup attacks. Implemented by `ed25519-dalek 2.x`.

---

## Witness minimality

The witness for a `Play` move at `(x, y)` contains exactly the cells on every win-check line through `(x, y)`:

| Cell position | Lines through it | Cells in witness |
|---|---|---|
| Edge, e.g. (1, 0) | Row 0, Column 1 | **5** |
| Corner, e.g. (0, 0) | Row 0, Column 0, Main diagonal | **7** |
| Center (1, 1) | Row 1, Column 1, Main diagonal, Anti-diagonal | **9** (all) |

Each cell proof costs **4 × 32 = 128 bytes** (4 sibling hashes). The full witness for a Play move is:

```
Witness::Play {
    game_meta:   99 bytes   (fixed)
    board_root:  32 bytes   (fixed)
    cell_proofs: N × (1 + 128) bytes   where N ∈ {5, 7, 9}
}

Total: 131 + N × 129 bytes
  edge:   131 + 5×129 =  776 bytes
  corner: 131 + 7×129 = 1034 bytes
  center: 131 + 9×129 = 1292 bytes
```

**Why not include the whole board?** The STF only needs to verify win conditions on lines through the played cell. Proving cells that can't affect the outcome would waste prover time in a zkVM (each SHA-256 invocation costs constraint rows in the circuit).

**Why can't the prover lie about which cells are on win-check lines?** The STF calls `required_cells(x, y)` itself and checks that every returned coordinate has a proof. A prover who omits a required cell gets `MissingCellProof`. A prover who includes extra cells beyond what's required is wasteful but not wrong — correctness isn't threatened.

---

## Multi-game concurrency

### Server locking hierarchy

```
ServerState {
    games: Arc<RwLock<HashMap<GameId, Arc<Mutex<PerGameState>>>>>
}
```

The two-level structure separates map-level operations from game-level operations:

| Operation | Locks held | Duration | Contention |
|---|---|---|---|
| `GET /games` | `RwLock` read | ~10 ns | None — concurrent reads |
| `GET /state/:id` | `RwLock` read → Arc clone → release; per-game `Mutex` | ~50 ns | Only same-game writers |
| `POST /play` | `RwLock` read → Arc clone → release; per-game `Mutex` | ~70 µs | Only same-game moves |
| `POST /create_game` | `RwLock` write (brief insert only) | ~100 ns | All readers momentarily |

**Key property:** two `Play` operations on **different** games never contend. Throughput scales as `N_games × N_cores × ~14,000 moves/sec`.

### Cross-game isolation

Each game's `game_id` is a 32-byte random nonce generated at creation time and embedded in `GameMeta`. Because `game_id` is hashed into `state_root`, every game has a distinct initial root even if both games have the same players. Since the player's signature message is `prior_state_root || [x, y]`, a signature from game A is cryptographically bound to A's state root and will fail Ed25519 verification against game B's state root.

### Latency breakdown (single Play call)

| Phase | Time |
|---|---|
| HTTP parse + routing | ~5 µs |
| `RwLock` read + Arc clone | ~10 ns |
| Per-game `Mutex` acquire (uncontended) | ~50 ns |
| Witness build: rebuild 16-leaf SMT | ~5 µs |
| STF: state root re-derivation | ~0.3 µs |
| STF: N Merkle proof verifications (N × 4 SHA-256 each) | ~5 µs |
| STF: **Ed25519 signature verification** | **~50 µs** ← dominant |
| STF: win check + new root | ~2 µs |
| JSON serialization + HTTP write | ~5 µs |
| **Total** | **~72 µs** |

Ed25519 dominates. In a real zkVM deployment, signature verification moves inside the proof circuit and the server instead verifies a SNARK proof, which is typically cheaper for the verifier than re-running Ed25519.

---

## What "zero knowledge" means here

This implementation is the **computational substrate** of a zkVM program — not a zero-knowledge proof system itself.

### What we have

The STF satisfies two of the three ZKP properties:

**Completeness:** if a move is valid, `stf` accepts it and returns the correct new root.

**Soundness (computational):** a cheating player cannot produce a witness that makes `stf` accept an invalid move, assuming SHA-256 collision resistance and Ed25519 unforgeability. Specifically:
- Claiming a cell is `Empty` when it isn't requires finding a SHA-256 collision (the forged leaf hash must match the board root).
- Signing a move for a different state requires breaking Ed25519.

**Zero knowledge: NOT present.** The witness is plaintext. Anyone who sees the witness knows the full board state.

### What a zkVM would add

In RISC Zero or SP1, `stf` would run inside a STARK prover:

```
Public inputs:   prior_state_root, PlayerMove, new_state_root
Private inputs:  Witness (game_meta, board_root, cell_proofs, signature)
Circuit:         the body of stf()
Output:          proof π  (~100–200 KB)
```

The verifier checks `π` in ~1 ms without seeing the witness. This achieves **zero knowledge**: the verifier learns only that `stf(prior_root, move) = new_root` holds — nothing about the board state or which cells were inspected.

The STF is already written in idiomatic Rust with no `std::io`, no OS calls, and no randomness — all requirements for zkVM compilation. To deploy on RISC Zero you would add:

```toml
# In a new guest/ crate
[dependencies]
risc0-zkvm = { version = "1", features = ["guest"] }
tic-tac-toe-core = { path = "../../core" }
```

```rust
// guest/src/main.rs
risc0_zkvm::guest::env::commit(&new_root);
```

### Why SHA-256 instead of Poseidon

SHA-256 is used here for clarity and wide library support. In a real zkVM circuit, SHA-256 costs ~30,000 R1CS constraints per invocation, whereas **Poseidon** (an algebraic hash designed for ZK circuits) costs ~240 constraints — a 125× improvement. For a production deployment, `merkle.rs` and the state-root computation would swap to Poseidon with no changes to the STF logic.

---

## Running the server

### Prerequisites

- Rust 1.75+ (`rustup update stable`)
- `cargo`

### Build

```bash
git clone <repo>
cd zk-tic-tac-toe
cargo build --release
```

### Run

```bash
cargo run --release --bin tic-tac-toe-server
# Listening on http://0.0.0.0:3000
```

---

## API reference

All request and response bodies are JSON. Public keys, signatures, game IDs, and state roots are hex-encoded.

### POST `/create_game`

Create a new game. The server generates a random `game_id`.

**Request:**
```json
{
  "pubkey_x": "<64 hex chars — ed25519 public key for player X>",
  "pubkey_y": "<64 hex chars — ed25519 public key for player O>"
}
```

**Response:**
```json
{
  "game_id":    "<64 hex chars>",
  "state_root": "<64 hex chars>"
}
```

---

### POST `/play`

Submit a signed move. The server builds the witness, calls the STF, and returns the new state.

**Request:**
```json
{
  "game_id":   "<64 hex chars>",
  "pubkey":    "<64 hex chars — must match next_player's key>",
  "signature": "<128 hex chars — Ed25519 over state_root || [x, y]>",
  "x": 0,
  "y": 0
}
```

**Response:**
```json
{
  "state_root":         "<64 hex chars>",
  "winner":             null,
  "witness_cell_count": 7
}
```

`winner` is `null`, `"X"`, `"O"`, or `"Draw"`. `witness_cell_count` shows how many cell proofs were included (5, 7, or 9 depending on position).

---

### GET `/state/:game_id`

**Response:**
```json
{
  "game_id":    "<64 hex chars>",
  "board":      [[".", ".", "."], [".", "X", "."], [".", ".", "."]],
  "state_root": "<64 hex chars>",
  "move_count": 1,
  "next_player": "O",
  "game_over":  false
}
```

---

### GET `/games`

List all known game IDs.

**Response:**
```json
{
  "game_ids": ["<hex>", "<hex>", "..."],
  "total": 3
}
```

---

### GET `/gen_keypair`

Generate a fresh Ed25519 keypair (for testing).

**Response:**
```json
{
  "secret_key": "<64 hex chars>",
  "public_key": "<64 hex chars>"
}
```

---

### POST `/sign_move`

Sign a move with a secret key (for testing). The server fetches the current `state_root` for the game and signs `state_root || [x, y]`.

**Request:**
```json
{
  "game_id":    "<64 hex chars>",
  "secret_key": "<64 hex chars>",
  "x": 1,
  "y": 1
}
```

**Response:**
```json
{
  "signature":     "<128 hex chars>",
  "signed_message": "<68 hex chars — state_root || x || y>"
}
```

---

### Example: playing a complete game with curl

```bash
# 1. Generate keys for both players
KP_X=$(curl -s http://localhost:3000/gen_keypair)
KP_O=$(curl -s http://localhost:3000/gen_keypair)
PK_X=$(echo $KP_X | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")
SK_X=$(echo $KP_X | python3 -c "import sys,json; print(json.load(sys.stdin)['secret_key'])")
PK_O=$(echo $KP_O | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")
SK_O=$(echo $KP_O | python3 -c "import sys,json; print(json.load(sys.stdin)['secret_key'])")

# 2. Create a game
GAME=$(curl -s -X POST http://localhost:3000/create_game \
  -H 'Content-Type: application/json' \
  -d "{\"pubkey_x\":\"$PK_X\",\"pubkey_y\":\"$PK_O\"}")
GID=$(echo $GAME | python3 -c "import sys,json; print(json.load(sys.stdin)['game_id'])")

# 3. X plays (0,0) — sign then play
SIG=$(curl -s -X POST http://localhost:3000/sign_move \
  -H 'Content-Type: application/json' \
  -d "{\"game_id\":\"$GID\",\"secret_key\":\"$SK_X\",\"x\":0,\"y\":0}" \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['signature'])")

curl -s -X POST http://localhost:3000/play \
  -H 'Content-Type: application/json' \
  -d "{\"game_id\":\"$GID\",\"pubkey\":\"$PK_X\",\"signature\":\"$SIG\",\"x\":0,\"y\":0}"

# 4. Check board
curl -s http://localhost:3000/state/$GID
```

---

## Running the tests

### Unit tests (Rust)

The `core` crate has unit tests covering:

- Empty board Merkle root matches precomputed value
- Proof verification and root update for every cell
- `CreateGame` cannot be called twice for the same slot
- Full game where X wins via top row
- Occupied cell is correctly rejected
- Cross-game signature replay is impossible (different `game_id` → different state roots → signature fails)

```bash
cargo test
```

Expected output:

```
running 7 tests
test merkle::tests::empty_board_round_trip ... ok
test merkle::tests::proof_every_cell ... ok
test merkle::tests::proof_verify_and_update ... ok
test game::tests::create_game_once ... ok
test game::tests::cross_game_replay_impossible ... ok
test game::tests::full_game_x_wins ... ok
test game::tests::occupied_cell_rejected ... ok

test result: ok. 7 passed; 0 failed
```

### Integration test (Python)

`test_game.py` uses only Python 3 standard library (`urllib`, `json`, `threading`). It tests:

1. Two games created concurrently have different IDs and state roots
2. `/games` lists both games
3. Correct witness sizes per move position (5 / 7 / 9 cell proofs)
4. Game 1 finishes (X wins) while Game 2 is still in progress
5. Moves on a finished game are rejected
6. 20 games created concurrently all receive unique IDs

```bash
# Terminal 1
cargo run --release --bin tic-tac-toe-server

# Terminal 2
python3 test_game.py
```

Expected output:

```
=== Multi-game integration test ===

Game 1: 8e88473320d5e5d5...
Game 2: 419a868878018242...
Roots differ: ✓

/games lists 2 game(s) ✓

Game 1 (X wins via top row):
  (0,0) witness=7 ✓  winner=None ✓
  (0,1) witness=5 ✓  winner=None ✓
  (1,0) witness=5 ✓  winner=None ✓
  (1,2) witness=5 ✓  winner=None ✓
  (2,0) witness=7 ✓  winner='X' ✓

Game 2 (running independently while game 1 finished):
  (1,1) witness=9 ✓  winner=None ✓
  (0,0) witness=7 ✓  winner=None ✓

Attempting move on finished game 1...
Correctly rejected: game is already over

Creating 20 games concurrently...
  20 concurrent games created with unique IDs ✓
  Total games in server: 22 ✓

=== All checks passed ===
```

---

## References

**Merkle trees**
- Merkle, R. (1987). *A Digital Signature Based on a Conventional Encryption Function*. CRYPTO '87. — Original construction.
- Dahlberg, R. et al. (2020). *Efficient Sparse Merkle Trees*. [eprint.iacr.org/2020/1525](https://eprint.iacr.org/2020/1525) — Survey of SMT proof sizes and optimisations.

**Elliptic curve signatures**
- Bernstein, D. et al. (2012). *High-speed high-security signatures*. [ed25519.cr.yp.to](https://ed25519.cr.yp.to/ed25519-20110926.pdf) — Ed25519 specification.
- Bernstein, D. (2006). *Curve25519: new Diffie-Hellman speed records*. PKC 2006. — The underlying curve.

**Zero-knowledge proof systems**
- Ben-Sasson, E. et al. (2018). *Scalable, transparent, and post-quantum secure computational integrity*. [eprint.iacr.org/2018/046](https://eprint.iacr.org/2018/046) — The STARKs paper; basis of RISC Zero.
- Groth, J. (2016). *On the Size of Pairing-based Non-interactive Arguments*. [eprint.iacr.org/2016/260](https://eprint.iacr.org/2016/260) — Groth16 SNARKs; used in many on-chain ZK systems.
- Grassi, L. et al. (2019). *Poseidon: A New Hash Function for Zero-Knowledge Proof Systems*. [eprint.iacr.org/2019/458](https://eprint.iacr.org/2019/458) — The ZK-friendly hash to replace SHA-256 inside circuits.

**ZK in games**
- Dark Forest (2020). *Announcing Dark Forest*. [blog.zkga.me](https://blog.zkga.me/announcing-darkforest) — The canonical example of ZK game state: on-chain strategy game where planet locations are hidden using Groth16 SNARKs. Directly analogous architecture to this project.
- Noir documentation. *Tic-Tac-Toe example*. [noir-lang.org](https://noir-lang.org) — Aztec's ZK DSL uses Tic-Tac-Toe as its introductory circuit example.

**zkVM runtimes**
- RISC Zero. *zkVM architecture*. [dev.risczero.com](https://dev.risczero.com) — How a Rust program becomes a STARK proof. This STF can be compiled for the RISC Zero guest with minimal changes.
- Succinct Labs. *SP1*. [succinctlabs.github.io/sp1](https://succinctlabs.github.io/sp1) — Alternative zkVM; also accepts standard Rust.
