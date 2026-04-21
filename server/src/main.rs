//! Web server — constructs witnesses and calls the pure STF.
//!
//! ## Concurrency model
//!
//! ```text
//! ServerState {
//!     games: RwLock<HashMap<GameId, Arc<Mutex<PerGameState>>>>
//! }
//! ```
//!
//! * The outer `RwLock` protects the game *map*.  It is held in read mode for
//!   the duration of a single pointer clone (~10 ns) and in write mode only
//!   during `CreateGame` to insert one entry.
//!
//! * Each `PerGameState` has its own `Mutex`.  Two moves on **different** games
//!   never contend.  Two moves on the **same** game are serialised, which is
//!   required for correctness (the second move must see the first move's root).
//!
//! ## Throughput ceiling (single node, 1 game/player)
//!
//!   Ed25519 verify ≈ 50 µs  →  ~20 000 moves/s per core
//!   With N independent games: N × 20 000 moves/s (no cross-game contention)
//!
//! ## Endpoints
//!
//! | Method | Path              | Description                               |
//! |--------|-------------------|-------------------------------------------|
//! | POST   | /create_game      | Create a new game; returns `game_id`      |
//! | POST   | /play             | Submit a signed move for a specific game  |
//! | GET    | /state/:game_id   | Board + metadata for one game             |
//! | GET    | /games            | List all known game IDs                   |
//! | GET    | /gen_keypair      | Testing: generate an ed25519 keypair      |
//! | POST   | /sign_move        | Testing: sign a move for a specific game  |

use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use ed25519_dalek::{SigningKey, Signer};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use tic_tac_toe_core::{
    cell_index, play_message, required_cells, stf, Cell, CellProof, GameId, GameMeta, MerkleTree,
    Player, PlayerMove, PublicKey, Signature, Witness, Winner,
};
use tokio::sync::{Mutex, RwLock};

// ---------------------------------------------------------------------------
// Per-game state (protected by its own Mutex)
// ---------------------------------------------------------------------------

struct PerGameState {
    state_root: [u8; 32],
    board: [[Cell; 3]; 3],
    game_meta: GameMeta,
}

impl PerGameState {
    /// Minimal Play witness: only cells on win-check lines through (x, y).
    fn build_play_witness(&self, x: u8, y: u8) -> Witness {
        let tree = MerkleTree::from_board(&self.board);
        let board_root = tree.root();
        let cell_proofs = required_cells(x, y)
            .into_iter()
            .map(|(cx, cy)| CellProof {
                x: cx,
                y: cy,
                cell: self.board[cy as usize][cx as usize],
                siblings: tree.proof(cell_index(cx, cy)),
            })
            .collect();
        Witness::Play { game_meta: self.game_meta.clone(), board_root, cell_proofs }
    }
}

// ---------------------------------------------------------------------------
// Server state
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct ServerState {
    /// Outer RwLock: read to look up a game; write only to insert a new game.
    /// Arc<Mutex<..>>: per-game serialisation without global blocking.
    games: Arc<RwLock<HashMap<GameId, Arc<Mutex<PerGameState>>>>>,
}

impl ServerState {
    fn new() -> Self {
        ServerState { games: Arc::new(RwLock::new(HashMap::new())) }
    }

    /// Read-lock the map, clone the Arc for the given game, release the lock.
    /// The caller then locks the Arc independently — other games are unaffected.
    async fn get_game(&self, game_id: &GameId) -> Option<Arc<Mutex<PerGameState>>> {
        self.games.read().await.get(game_id).cloned()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn bad_request(msg: impl ToString) -> (StatusCode, String) {
    (StatusCode::BAD_REQUEST, msg.to_string())
}

fn not_found(msg: impl ToString) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, msg.to_string())
}

fn decode32(s: &str) -> Result<[u8; 32], (StatusCode, String)> {
    hex::decode(s)
        .map_err(|e| bad_request(e))?
        .try_into()
        .map_err(|_| bad_request("expected 32-byte hex"))
}

fn decode64(s: &str) -> Result<[u8; 64], (StatusCode, String)> {
    hex::decode(s)
        .map_err(|e| bad_request(e))?
        .try_into()
        .map_err(|_| bad_request("expected 64-byte hex"))
}

// ---------------------------------------------------------------------------
// Request / response shapes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateGameReq {
    pubkey_x: String,
    pubkey_y: String,
}

#[derive(Serialize)]
struct CreateGameResp {
    game_id: String,
    state_root: String,
}

#[derive(Deserialize)]
struct PlayReq {
    game_id: String,
    pubkey: String,
    signature: String,
    x: u8,
    y: u8,
}

#[derive(Serialize)]
struct PlayResp {
    state_root: String,
    winner: Option<String>,
    /// Number of cell proofs sent — useful for observing witness minimality.
    witness_cell_count: usize,
}

#[derive(Serialize)]
struct GameStateResp {
    game_id: String,
    board: Vec<Vec<String>>,
    state_root: String,
    move_count: u8,
    next_player: String,
    game_over: bool,
}

#[derive(Serialize)]
struct GamesResp {
    game_ids: Vec<String>,
    total: usize,
}

#[derive(Serialize)]
struct KeypairResp {
    secret_key: String,
    public_key: String,
}

#[derive(Deserialize)]
struct SignMoveReq {
    game_id: String,
    secret_key: String,
    x: u8,
    y: u8,
}

#[derive(Serialize)]
struct SignMoveResp {
    signature: String,
    /// The raw bytes that were signed (hex), for debugging.
    signed_message: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn handle_create_game(
    State(srv): State<ServerState>,
    Json(req): Json<CreateGameReq>,
) -> Result<Json<CreateGameResp>, (StatusCode, String)> {
    let pubkey_x: PublicKey = decode32(&req.pubkey_x)?;
    let pubkey_y: PublicKey = decode32(&req.pubkey_y)?;

    // Generate a random game_id — this is what differentiates concurrent games
    // and prevents cross-game signature replay.
    let game_id: GameId = {
        use rand::RngCore;
        let mut id = [0u8; 32];
        OsRng.fill_bytes(&mut id);
        id
    };

    let mv = PlayerMove::CreateGame { game_id, pubkey_x, pubkey_y };
    let (new_root, _) = stf([0u8; 32], mv, Witness::CreateGame).map_err(|e| bad_request(e))?;

    let per_game = PerGameState {
        state_root: new_root,
        board: [[Cell::Empty; 3]; 3],
        game_meta: GameMeta {
            game_id,
            pubkey_x,
            pubkey_y,
            move_count: 0,
            next_player: Player::X,
            game_over: false,
        },
    };

    // Write-lock only long enough to insert the new entry.
    srv.games.write().await.insert(game_id, Arc::new(Mutex::new(per_game)));

    Ok(Json(CreateGameResp {
        game_id: hex::encode(game_id),
        state_root: hex::encode(new_root),
    }))
}

async fn handle_play(
    State(srv): State<ServerState>,
    Json(req): Json<PlayReq>,
) -> Result<Json<PlayResp>, (StatusCode, String)> {
    let game_id: GameId = decode32(&req.game_id)?;
    let pubkey: PublicKey = decode32(&req.pubkey)?;
    let signature: Signature = decode64(&req.signature)?;

    // Read-lock just to clone the Arc; released immediately.
    let game_arc = srv.get_game(&game_id).await.ok_or_else(|| not_found("game not found"))?;

    // Lock only this game — other games are unblocked.
    let mut gs = game_arc.lock().await;

    if gs.game_meta.game_over {
        return Err(bad_request("game is already over"));
    }

    let witness = gs.build_play_witness(req.x, req.y);
    let cell_count = match &witness {
        Witness::Play { cell_proofs, .. } => cell_proofs.len(),
        _ => 0,
    };

    let prior_root = gs.state_root;
    let mv = PlayerMove::Play { pubkey, signature, x: req.x, y: req.y };
    let (new_root, winner) = stf(prior_root, mv, witness).map_err(|e| bad_request(e))?;

    // Apply the STF's output to the server's mirror state.
    let mark = gs.game_meta.next_player.to_cell();
    gs.board[req.y as usize][req.x as usize] = mark;
    gs.state_root = new_root;
    gs.game_meta.move_count += 1;
    gs.game_meta.next_player = gs.game_meta.next_player.other();
    if winner.is_some() {
        gs.game_meta.game_over = true;
    }

    Ok(Json(PlayResp {
        state_root: hex::encode(new_root),
        winner: winner.map(|w| match w {
            Winner::X => "X",
            Winner::O => "O",
            Winner::Draw => "Draw",
        }.to_string()),
        witness_cell_count: cell_count,
    }))
}

async fn handle_state(
    State(srv): State<ServerState>,
    Path(game_id_hex): Path<String>,
) -> Result<Json<GameStateResp>, (StatusCode, String)> {
    let game_id: GameId = decode32(&game_id_hex)?;
    let game_arc = srv.get_game(&game_id).await.ok_or_else(|| not_found("game not found"))?;
    let gs = game_arc.lock().await;

    let board = gs.board.iter().map(|row| {
        row.iter().map(|c| match c {
            Cell::Empty => ".".to_string(),
            Cell::X => "X".to_string(),
            Cell::O => "O".to_string(),
        }).collect()
    }).collect();

    Ok(Json(GameStateResp {
        game_id: hex::encode(game_id),
        board,
        state_root: hex::encode(gs.state_root),
        move_count: gs.game_meta.move_count,
        next_player: match gs.game_meta.next_player {
            Player::X => "X".to_string(),
            Player::O => "O".to_string(),
        },
        game_over: gs.game_meta.game_over,
    }))
}

async fn handle_list_games(State(srv): State<ServerState>) -> Json<GamesResp> {
    let game_ids: Vec<String> = srv.games.read().await.keys().map(hex::encode).collect();
    let total = game_ids.len();
    Json(GamesResp { game_ids, total })
}

async fn handle_gen_keypair() -> Json<KeypairResp> {
    let sk = SigningKey::generate(&mut OsRng);
    Json(KeypairResp {
        secret_key: hex::encode(sk.to_bytes()),
        public_key: hex::encode(sk.verifying_key().to_bytes()),
    })
}

async fn handle_sign_move(
    State(srv): State<ServerState>,
    Json(req): Json<SignMoveReq>,
) -> Result<Json<SignMoveResp>, (StatusCode, String)> {
    let game_id: GameId = decode32(&req.game_id)?;
    let sk_bytes: [u8; 32] = decode32(&req.secret_key)?;
    let sk = SigningKey::from_bytes(&sk_bytes);

    let game_arc = srv.get_game(&game_id).await.ok_or_else(|| not_found("game not found"))?;
    let gs = game_arc.lock().await;

    let msg = play_message(&gs.state_root, req.x, req.y);
    let sig = sk.sign(&msg);

    Ok(Json(SignMoveResp {
        signature: hex::encode(sig.to_bytes()),
        signed_message: hex::encode(msg),
    }))
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    let srv = ServerState::new();

    let app = Router::new()
        .route("/create_game",   post(handle_create_game))
        .route("/play",          post(handle_play))
        .route("/state/:game_id", get(handle_state))
        .route("/games",         get(handle_list_games))
        .route("/gen_keypair",   get(handle_gen_keypair))
        .route("/sign_move",     post(handle_sign_move))
        .with_state(srv);

    let addr = "0.0.0.0:3000";
    println!("Listening on http://{addr}");
    println!();
    println!("POST /create_game    {{\"pubkey_x\":\"<hex32>\",\"pubkey_y\":\"<hex32>\"}}");
    println!("POST /play           {{\"game_id\":\"<hex32>\",\"pubkey\":\"<hex32>\",\"signature\":\"<hex64>\",\"x\":0,\"y\":0}}");
    println!("GET  /state/:game_id");
    println!("GET  /games");
    println!("GET  /gen_keypair");
    println!("POST /sign_move      {{\"game_id\":\"<hex32>\",\"secret_key\":\"<hex32>\",\"x\":0,\"y\":0}}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
