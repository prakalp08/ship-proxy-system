# Ship Proxy System

## Overview
This project implements the **Ship Proxy (client)** and **Offshore Proxy (server)** to reduce satellite internet costs by maintaining a **single persistent TCP connection**.  
All HTTP/HTTPS traffic is routed through the ship proxy → offshore proxy → internet.

- **Ship Proxy (client)** → runs on port `8080`  
- **Offshore Proxy (server)** → runs on port `9090`  
- **Supports** → HTTP, HTTPS (CONNECT), all HTTP methods  

---

## Running with Docker Compose

### Build & Start
```
docker compose up --build -d
```

### Stop
```
docker compose down
```
### Testing

#### Run these from your host machine:

##### HTTP
```
curl -x http://localhost:8080 http://httpforever.com/
```
##### POST
```
curl -x http://localhost:8080 -X POST \
  -H "Content-Type: application/json" \
  -d '{"user":"joe","action":"board"}' \
  http://httpbin.org/post
```
##### HTTPS
```
curl -x http://localhost:8080 https://www.example.com/
```
##### Sequential Requests
```
curl -x http://localhost:8080 http://httpforever.com/ & \
curl -x http://localhost:8080 http://httpforever.com/ & \
curl -x http://localhost:8080 http://httpforever.com/ &
wait
```

## Architecture

```mermaid
flowchart LR
    Browser[Browser / Curl] --> ShipProxy[Ship Proxy<br/>:8080]
    ShipProxy --> OffshoreProxy[Offshore Proxy<br/>:9090]
    OffshoreProxy --> Internet[Internet]
```
