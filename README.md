\# 🔨 Fast Ethereum Mining Bot



A high-speed parallel Ethereum miner for on-chain contracts with proof-of-work logic. This bot:



\- Listens for mint events

\- Mines in parallel across all CPU cores

\- Sends mint transactions when a valid nonce is found



\## 🚀 Running on Vast.ai



1\. Create a Vast.ai instance with:

&nbsp;  - Base image: `python:3.11-slim`

&nbsp;  - GPU: Optional (CPU preferred)

&nbsp;  - Disk: 2–5 GB

&nbsp;  - Ports: None



2\. Upload your `PRIVATE\_KEY` via env var or secret volume (NEVER hard-code it!)



3\. SSH into your instance and run:



```bash

git clone https://github.com/hampusniskala/eth-miner.git

cd eth-miner

bash start.sh



