# fast_miner/miner.py
import os
import time
import multiprocessing
import signal
from web3 import Web3
from Crypto.Hash import keccak

# Configuration (fill in ENV variables or hardcode)
PRIVATE_KEY = os.getenv("PRIVATE_KEY")
ADDRESS = Web3.to_checksum_address(os.getenv("WALLET_ADDRESS"))
INFURA_URL = os.getenv("INFURA_URL")
CONTRACT_ADDRESS = Web3.to_checksum_address("0xE5544a2A5fA9b175da60D8Eec67adD5582bB31b0")

ABI = [
    {"constant": True, "name": "prev_hash", "outputs": [{"name": "", "type": "bytes32"}], "type": "function"},
    {"constant": True, "name": "max_value", "outputs": [{"name": "", "type": "uint256"}], "type": "function"},
    {"constant": False, "name": "mint", "inputs": [{"name": "value", "type": "bytes32"}], "type": "function"},
    {"anonymous": False, "inputs": [{"indexed": True, "name": "minter", "type": "address"}], "name": "Mint", "type": "event"}
]

w3 = Web3(Web3.HTTPProvider(INFURA_URL))
contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=ABI)
stop_flag = multiprocessing.Event()

def keccak256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()

def mine(shared_data, result_queue, worker_id):
    tries = 0
    last_log = time.time()
    while not stop_flag.is_set():
        prev_hash = shared_data["prev_hash"]
        max_value = shared_data["max_value"]
        value = os.urandom(32)
        hash_bytes = keccak256(value + prev_hash)
        hash_int = int.from_bytes(hash_bytes, "big")
        tries += 1

        if hash_int <= max_value:
            print(f"[+] Worker {worker_id} solved after {tries} tries")
            result_queue.put(value)
            stop_flag.set()
            return

        if time.time() - last_log > 5:
            print(f"Worker {worker_id}: {tries} tries so far...")
            last_log = time.time()

def send_mint_tx(value: bytes):
    nonce = w3.eth.get_transaction_count(ADDRESS, "pending")
    tx = contract.functions.mint(value).build_transaction({
        "chainId": 1,
        "gas": 250000,
        "gasPrice": w3.eth.gas_price,
        "nonce": nonce,
    })
    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    print(f"[🚀] Mint TX sent: https://etherscan.io/tx/{tx_hash.hex()}")

def run_miner():
    manager = multiprocessing.Manager()
    shared_data = manager.dict()
    shared_data["prev_hash"] = contract.functions.prev_hash().call()
    shared_data["max_value"] = contract.functions.max_value().call()

    result_queue = multiprocessing.Queue()
    processes = []
    num_cores = multiprocessing.cpu_count()
    print(f"⛏️ Mining on {num_cores} cores...")

    for i in range(num_cores):
        p = multiprocessing.Process(target=mine, args=(shared_data, result_queue, i))
        p.start()
        processes.append(p)

    value = result_queue.get()
    send_mint_tx(value)

    for p in processes:
        p.terminate()

def handle_sigterm(sig, frame):
    print("\n[!] Caught shutdown signal, exiting cleanly.")
    stop_flag.set()

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, handle_sigterm)
    while True:
        run_miner()
        stop_flag.clear()
        print("[*] Restarting mining loop...")
