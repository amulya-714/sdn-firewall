# SDN-Based Firewall using Mininet + Ryu

## Team
- Amulya P (AM458)
- Vikas R (AM477)
- Anjali Arun (AM421)

## Project Overview
This project implements a Software-Defined Networking (SDN) firewall. It uses the Ryu controller to monitor OpenFlow 1.3 switches and automatically installs flow rules to block unauthorized traffic from a specific host (10.0.0.4).

## Setup & Compatibility
**Note:** This version includes fixes for Python 3.13 compatibility (Eventlet monkey patching).

### Execution
1. **Controller:** `python3 ./bin/ryu-manager firewall_controller.py`
2. **Topology:** `sudo -E python3 topology.py`

## Execution Results

### 1. Controller & Topology Setup
The controller starts and identifies the blocked IP list.
![Setup](./screenshots/Screenshot%202026-04-16%20at%2010.08.39.png)

### 2. Allowed Traffic (h1 -> h2)
Standard traffic is permitted with 0% packet loss.
![Allowed](./screenshots/Screenshot%202026-04-16%20at%2010.10.40.png)

### 3. Firewall Block (h4 -> h1)
Traffic from 10.0.0.4 is identified and dropped by the controller.
![Blocked](./screenshots/Screenshot%202026-04-16%20at%2010.11.18.png)

### 4. Flow Table Proof
The OpenFlow 1.3 flow table shows the `actions=drop` rule for the blocked IP.
![Flows](./screenshots/Screenshot%202026-04-16%20at%2010.11.49.png)

### 5. Performance Metrics
- **Throughput:** ~79 Gbits/sec
- **Avg Latency:** ~1.2 ms
![Performance](./screenshots/Screenshot%202026-04-16%20at%2010.17.11.png)
