# Battleship game
This project implements a privacy preserving Battleship game using Microsoft SEAL (BFV homomorphic encryption).
The goal is to demonstrate how encrypted computation can be applied to a classic game while ensuring that no player or server learns the opponent’s board contents.

Two parties participate:

i) Alice (the user) – plays interactively by entering coordinates.  
ii) Bob (the machine) – the computer player, whose guesses are randomly selected.  

Each player’s 10×10 board is fully encrypted using the BFV scheme from the Microsoft SEAL library.  

Ship placements are encoded as integers and encrypted.  

All hit/miss checks are performed under encryption:
the server blinds the ciphertext and Alice or Bob decrypts only the final, blinded result.

The server cannot see plaintext ship positions at any point.

GAME FLOW
-Alice and Bob each have five ships (sizes: 5, 4, 3, 2, 2).  
-Ship positions are randomized and change every time the program is run.  
-Both boards are encrypted immediately after ship placement.  
-Alice and Bob alternate firing shots at coordinates.  
-Each guess is processed homomorphically:  
-The encrypted cell value is multiplied by a random blinding factor.  
-A decrypted value of 0 indicates a MISS.  
-Any non-zero decrypted value indicates a HIT.  
-The game continues until one player’s entire fleet is destroyed.  

When one side wins:  

The final scores (total hits) are printed. 
A full board reveal displays:
S – ship not hit  
H – ship hit  
X – miss  
. – untouched water  
