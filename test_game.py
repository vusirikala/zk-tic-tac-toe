#!/usr/bin/env python3
"""
End-to-end integration test for the multi-game server.

Tests:
1. Multiple concurrent games with independent state
2. Correct witness sizes per cell position
3. Cross-game isolation (moves in game A don't affect game B)
4. /games listing
5. X wins in one game while another is still in progress
"""
import json, sys, threading, time, urllib.request, urllib.error

BASE = "http://localhost:3000"

def post(path, body=None):
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(f"{BASE}{path}", data=data,
                                  headers={"Content-Type": "application/json"},
                                  method="POST")
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())

def get(path):
    with urllib.request.urlopen(f"{BASE}{path}") as r:
        return json.loads(r.read())

def gen_keypair():     return get("/gen_keypair")
def list_games():      return get("/games")

def create_game(pk_x, pk_y):
    return post("/create_game", {"pubkey_x": pk_x, "pubkey_y": pk_y})

def sign_move(game_id, sk, x, y):
    return post("/sign_move", {"game_id": game_id, "secret_key": sk, "x": x, "y": y})

def play(game_id, pk, sig, x, y):
    return post("/play", {"game_id": game_id, "pubkey": pk, "signature": sig, "x": x, "y": y})

def state(game_id):
    return get(f"/state/{game_id}")

def check(cond, msg):
    if not cond:
        print(f"FAIL: {msg}")
        sys.exit(1)

print("=== Multi-game integration test ===\n")

# ── Keypairs ─────────────────────────────────────────────────────────────────
kp_x1 = gen_keypair()   # players for game 1
kp_o1 = gen_keypair()
kp_x2 = gen_keypair()   # players for game 2
kp_o2 = gen_keypair()

# ── Create two independent games ─────────────────────────────────────────────
g1 = create_game(kp_x1["public_key"], kp_o1["public_key"])
g2 = create_game(kp_x2["public_key"], kp_o2["public_key"])
gid1, gid2 = g1["game_id"], g2["game_id"]

check(gid1 != gid2,                   "game IDs must differ")
check(g1["state_root"] != g2["state_root"], "initial roots must differ (different game_ids)")
print(f"Game 1: {gid1[:16]}...")
print(f"Game 2: {gid2[:16]}...")
print(f"Roots differ: ✓\n")

# ── /games listing ───────────────────────────────────────────────────────────
games = list_games()
check(games["total"] >= 2,            "/games total must be ≥ 2")
check(gid1 in games["game_ids"],      "game 1 must appear in /games")
check(gid2 in games["game_ids"],      "game 2 must appear in /games")
print(f"/games lists {games['total']} game(s) ✓\n")

# ── Game 1: X wins via top row — check witness sizes ─────────────────────────
# X: (0,0) corner  → 7 cells
# O: (0,1) edge    → 5 cells
# X: (1,0) edge    → 5 cells
# O: (1,2) edge    → 5 cells
# X: (2,0) corner  → 7 cells  (X wins — row 0 complete)

print("Game 1 (X wins via top row):")
moves1 = [
    (kp_x1, 0, 0, 7, None),
    (kp_o1, 0, 1, 5, None),
    (kp_x1, 1, 0, 5, None),
    (kp_o1, 1, 2, 5, None),
    (kp_x1, 2, 0, 7, "X"),
]
for kp, x, y, exp_cells, exp_winner in moves1:
    sig = sign_move(gid1, kp["secret_key"], x, y)["signature"]
    r = play(gid1, kp["public_key"], sig, x, y)
    ok_cells   = "✓" if r["witness_cell_count"] == exp_cells   else f"✗(got {r['witness_cell_count']})"
    ok_winner  = "✓" if r["winner"] == exp_winner              else f"✗(got {r['winner']!r})"
    print(f"  ({x},{y}) witness={r['witness_cell_count']} {ok_cells}  winner={r['winner']!r} {ok_winner}")
    check(r["witness_cell_count"] == exp_cells,  f"wrong witness size at ({x},{y})")
    check(r["winner"] == exp_winner,             f"wrong winner at ({x},{y})")

s1 = state(gid1)
check(s1["game_over"],   "game 1 must be over")
print()

# ── Game 2: still running while game 1 finished ───────────────────────────────
print("Game 2 (running independently while game 1 finished):")
moves2 = [
    (kp_x2, 1, 1, 9, None),    # center → row+col+both diags = 9 cells
    (kp_o2, 0, 0, 7, None),
]
for kp, x, y, exp_cells, exp_winner in moves2:
    sig = sign_move(gid2, kp["secret_key"], x, y)["signature"]
    r = play(gid2, kp["public_key"], sig, x, y)
    ok_cells  = "✓" if r["witness_cell_count"] == exp_cells else f"✗(got {r['witness_cell_count']})"
    ok_winner = "✓" if r["winner"] == exp_winner            else f"✗(got {r['winner']!r})"
    print(f"  ({x},{y}) witness={r['witness_cell_count']} {ok_cells}  winner={r['winner']!r} {ok_winner}")
    check(r["witness_cell_count"] == exp_cells,  f"wrong witness size at ({x},{y})")
    check(r["winner"] == exp_winner,             f"wrong winner at ({x},{y})")

s2 = state(gid2)
check(not s2["game_over"],   "game 2 must still be active")
check(s2["move_count"] == 2, "game 2 should have 2 moves")
print()

# ── Play on finished game must fail ──────────────────────────────────────────
print("Attempting move on finished game 1...")
try:
    sig = sign_move(gid1, kp_x1["secret_key"], 2, 2)["signature"]
    play(gid1, kp_x1["public_key"], sig, 2, 2)
    print("FAIL: should have been rejected")
    sys.exit(1)
except urllib.error.HTTPError as e:
    print(f"Correctly rejected: {e.read().decode()}\n")

# ── Concurrent game creation stress test ─────────────────────────────────────
print("Creating 20 games concurrently...")
errors = []
created = []

def make_game(idx):
    try:
        kpx = gen_keypair()
        kpo = gen_keypair()
        r = create_game(kpx["public_key"], kpo["public_key"])
        created.append(r["game_id"])
    except Exception as e:
        errors.append(str(e))

threads = [threading.Thread(target=make_game, args=(i,)) for i in range(20)]
for t in threads: t.start()
for t in threads: t.join()

check(len(errors) == 0,             f"concurrent creation errors: {errors}")
check(len(set(created)) == 20,      "all 20 game IDs must be unique")

games_after = list_games()
check(games_after["total"] >= 22,   f"expected ≥22 games, got {games_after['total']}")
print(f"  20 concurrent games created with unique IDs ✓")
print(f"  Total games in server: {games_after['total']} ✓")
print()

print("=== All checks passed ===")
