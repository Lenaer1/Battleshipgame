import random
from dataclasses import dataclass, field


#  Microsoft SEAL via sealy (BFV scheme)

from sealy import (
    BFVEncoder,
    BfvEncryptionParametersBuilder,
    BFVEvaluator,
    CoefficientModulus,
    Context,
    Decryptor,
    DegreeType,
    Encryptor,
    KeyGenerator,
    PlainModulus,
    SecurityLevel,
)


#SEAL BFV crypto wrapper


class SealBFVCrypto:
    """
    Wrapper around SEAL BFV operations using sealy.

    We:
    - Encode a small integer value (cell: 0,1..5)
    - Encrypt to ciphertext
    - Multiply homomorphically by a random plaintext r
    - Decrypt and read the first slot to decide hit/miss
    """

    def __init__(self):
        # Encryption parameters: BFV over integers
        # 8192-degree polynomial, 128-bit security, batching-enabled plain modulus
        params = (
            BfvEncryptionParametersBuilder()
            .with_poly_modulus_degree(DegreeType(8192))
            .with_coefficient_modulus(
                CoefficientModulus.create(
                    DegreeType(8192), [50, 30, 30, 50, 50]
                )
            )
            .with_plain_modulus(PlainModulus.batching(DegreeType(8192), 32))
            .build()
        )

        self.ctx = Context(params, False, SecurityLevel(128))
        self.keygen = KeyGenerator(self.ctx)

        self.encoder = BFVEncoder(self.ctx)
        self.public_key = self.keygen.create_public_key()
        self.secret_key = self.keygen.secret_key()

        self.encryptor = Encryptor(self.ctx, self.public_key)
        self.decryptor = Decryptor(self.ctx, self.secret_key)
        self.evaluator = BFVEvaluator(self.ctx)

    def encrypt_int(self, value: int):
        """Encrypt a single small integer as a BFV ciphertext."""
        # encode as a 1-slot vector [value]
        pt = self.encoder.encode_int([value])
        return self.encryptor.encrypt(pt)

    def decrypt_first(self, ciphertext) -> int:
        """Decrypt ciphertext and return the first integer slot."""
        pt = self.decryptor.decrypt(ciphertext)
        vec = self.encoder.decode_int(pt)
        # vec is the batched vector; we only care about slot 0
        return int(vec[0])

    def blind_multiply_random(self, ciphertext):
        """
        Homomorphically multiply by a random non-zero integer r:
            Enc(v) * r  → Enc(r * v)
        Used to hide the original ship ID and only reveal zero vs non-zero.
        """
        # Choose some non-zero r in a small range; enough to distinguish 0 vs non-zero
        r = random.randint(1, 100)
        pt_r = self.encoder.encode_int([r])
        return self.evaluator.multiply_plain(ciphertext, pt_r)


# Battleship game logic

BOARD_SIZE = 10
SHIP_SIZES = [5, 4, 3, 2, 2]   # total ship cells = 16


@dataclass
class Board:
    size: int = BOARD_SIZE
    grid: list = field(default_factory=lambda: [[0]*BOARD_SIZE for _ in range(BOARD_SIZE)])
    hits: list = field(default_factory=lambda: [[False]*BOARD_SIZE for _ in range(BOARD_SIZE)])
    total_ship_cells: int = 0
    hits_count: int = 0

    def place_ships_random(self):
        """Randomly place ships on a 10x10 grid without overlap."""
        self.grid = [[0]*self.size for _ in range(self.size)]
        self.hits = [[False]*self.size for _ in range(self.size)]
        self.total_ship_cells = 0
        self.hits_count = 0

        ship_id = 1
        for length in SHIP_SIZES:
            placed = False
            while not placed:
                orientation = random.choice(["H", "V"])

                if orientation == "H":
                    row = random.randrange(self.size)
                    col = random.randrange(self.size - length + 1)
                    if all(self.grid[row][col+i] == 0 for i in range(length)):
                        for i in range(length):
                            self.grid[row][col+i] = ship_id
                        placed = True
                else:
                    row = random.randrange(self.size - length + 1)
                    col = random.randrange(self.size)
                    if all(self.grid[row+i][col] == 0 for i in range(length)):
                        for i in range(length):
                            self.grid[row+i][col] = ship_id
                        placed = True

            self.total_ship_cells += length
            ship_id += 1

    def register_shot(self, x: int, y: int, hit: bool):
        """
        Record a shot at (x,y). Returns False if already shot.
        """
        if self.hits[x][y]:
            return False
        self.hits[x][y] = True
        if hit:
            self.hits_count += 1
        return True

    def all_sunk(self) -> bool:
        return self.hits_count >= self.total_ship_cells


@dataclass
class Player:
    name: str
    crypto: SealBFVCrypto
    board: Board
    enc_board: list = field(default_factory=list)
    points: int = 0

    def encrypt_board(self):
        """Encrypt entire 10x10 board, cell by cell."""
        self.enc_board = [
            [self.crypto.encrypt_int(self.board.grid[r][c]) for c in range(self.board.size)]
            for r in range(self.board.size)
        ]


@dataclass
class Server:
    """
    Untrusted server:
    - Holds only encrypted boards and SEAL public params via Player.crypto.
    - For each guess, blinds the ciphertext and asks "defender" to decrypt.
    """

    def process_guess(self, attacker: Player, defender: Player, x: int, y: int) -> bool:
        # If already shot, treat as miss
        if defender.board.hits[x][y]:
            return False

        c_cell = defender.enc_board[x][y]

        # Blind the ciphertext homomorphically: Enc(v) -> Enc(r*v)
        c_blind = defender.crypto.blind_multiply_random(c_cell)

        # Defender "decrypts" the blinded result locally
        m_blind = defender.crypto.decrypt_first(c_blind)

        # If cell was 0, r*0 = 0 → miss; else r*ship_id != 0 → hit
        hit = (m_blind != 0)

        defender.board.register_shot(x, y, hit)
        return hit


# Display input helpers

def display_final_board(board: Board):
    """Print a 10x10 view with ships/hits/misses."""
    print("   " + " ".join(str(i) for i in range(10)))
    print("  +" + "--"*10)
    for r in range(10):
        row = []
        for c in range(10):
            if board.grid[r][c] != 0 and board.hits[r][c]:
                row.append("H")  # hit ship
            elif board.grid[r][c] != 0:
                row.append("S")  # ship not hit
            elif board.hits[r][c]:
                row.append("X")  # miss
            else:
                row.append(".")  # untouched water
        print(f"{r} | " + " ".join(row))


def get_human_guess(defender: Player):
    """Ask the human for a coordinate (with 'q' to quit)."""
    while True:
        try:
            x_str = input("Enter X (0–9) or 'q' to quit: ").strip()
            if x_str.lower() == "q":
                raise KeyboardInterrupt
            y_str = input("Enter Y (0–9) or 'q' to quit: ").strip()
            if y_str.lower() == "q":
                raise KeyboardInterrupt

            x = int(x_str)
            y = int(y_str)

            if 0 <= x <= 9 and 0 <= y <= 9:
                if defender.board.hits[x][y]:
                    print("You already shot there. Try again.")
                else:
                    return x, y
            else:
                print("Out of range, please use 0–9.")
        except ValueError:
            print("Invalid input, please enter numbers.")
        except KeyboardInterrupt:
            print("\nExiting game.")
            raise


def random_guess(attacker: Player, defender: Player):
    """Random coordinate for AI that is not already shot."""
    while True:
        x = random.randrange(10)
        y = random.randrange(10)
        if not defender.board.hits[x][y]:
            return x, y


#Game loop


def play_game():
    # Create SEAL crypto context per player
    crypto_alice = SealBFVCrypto()
    crypto_bob = SealBFVCrypto()

    # Plain boards
    board_alice = Board()
    board_bob = Board()
    board_alice.place_ships_random()
    board_bob.place_ships_random()

    alice = Player("Alice (You)", crypto_alice, board_alice)
    bob = Player("Bob (Computer)", crypto_bob, board_bob)

    # Encrypt both boards
    alice.encrypt_board()
    bob.encrypt_board()

    server = Server()

    print("\n============================")
    print("   HOMOMORPHIC BATTLESHIP")
    print("   (SEAL BFV via sealy)")
    print("============================\n")
    print("Your ships are placed randomly on a 10x10 board.")
    print("Both boards are encrypted using Microsoft SEAL (BFV).")
    print("Hit/miss detection is done homomorphically.\n")

    current = alice
    opponent = bob
    turn = 0

    try:
        while True:
            turn += 1
            print(f"\n------ TURN {turn} ------")

            if current is alice:
                print("\nYour turn!")
                x, y = get_human_guess(bob)
            else:
                x, y = random_guess(bob, alice)
                print(f"Bob shoots at ({x}, {y})")

            hit = server.process_guess(current, opponent, x, y)
            if hit:
                current.points += 1

            if current is alice:
                print(f"You shot ({x}, {y}) → {'HIT!' if hit else 'MISS'}")
            else:
                print(f"Bob's shot at ({x}, {y}) → {'HIT!' if hit else 'MISS'}")

            if opponent.board.all_sunk():
                print("\n============================")
                print(f"     {current.name} WINS!")
                print("============================\n")
                break

            # Switch players
            current, opponent = opponent, current

    except KeyboardInterrupt:
        print("\nGame interrupted by user.\n")

    # Final stats and board reveal
    print("\n========== FINAL SCORES ==========")
    print(f"Alice hits: {alice.points} / {alice.board.total_ship_cells}")
    print(f"Bob hits:   {bob.points} / {bob.board.total_ship_cells}")

    print("\n===== Alice's Board =====")
    display_final_board(alice.board)

    print("\n===== Bob's Board =====")
    display_final_board(bob.board)



#Rin Game


if __name__ == "__main__":
    play_game()
