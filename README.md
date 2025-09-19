# Ship Proxy System 

## Overview
This project implements the **Ship Proxy (client)** and **Offshore Proxy (server)** to reduce satellite internet costs by maintaining a **single persistent TCP connection** from the ship to shore.  
All HTTP/HTTPS requests from browsers or tools like `curl` are routed through the ship proxy and forwarded sequentially to the offshore proxy, which relays them to the internet.

- **Client (Ship Proxy)** → runs inside the ship, exposes port `8080`.
- **Server (Offshore Proxy)** → runs offshore, listens on port `9090`.
- **Sequential Handling** → all requests processed one at a time over the persistent connection.
- **Supports** → HTTP, HTTPS (via CONNECT), all HTTP methods (GET/POST/PUT/DELETE, etc.).

---

## Running with Docker Compose
### 1. Build and Start
```bash
docker compose up --build -d

esting the Proxy

Run these commands from your host (Linux/Mac).
On Windows, replace curl with curl.exe.

HTTP Test
curl -x http://localhost:8080 http://httpforever.com/

POST Test
curl -x http://localhost:8080 -X POST \
     -H "Content-Type: application/json" \
     -d '{"user":"joe","action":"board"}' \
     http://httpbin.org/post

HTTPS Test
curl -x http://localhost:8080 https://www.example.com/

Sequential Requests (parallel test)
curl -x http://localhost:8080 http://httpforever.com/ & \
curl -x http://localhost:8080 http://httpforever.com/ & \
curl -x http://localhost:8080 http://httpforever.com/ &
wait