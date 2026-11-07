# ⚡ Tracex vBlack

**Tracex** is a lightweight, low-overhead network path diagnostics and socket latency monitoring tool written in C. Designed to perform raw packet analysis, detect bottleneck hops, and measure response times across network routes.

---

## 🚀 Features

* **Low-Overhead Execution:** Written in pure C for minimal memory footprint and fast processing.
* **Latency Calculation:** Measures ICMP/TCP round-trip time (RTT) for every network hop.
* **Bottleneck Detection:** Identifies packet loss and high-latency points along the route.
* **Clean CLI Output:** Minimalist terminal interface optimized for Linux execution environments.

---

## 🛠️ Prerequisites & Installation

### Dependencies
Ensure you have a C compiler (`gcc`) and standard build utilities installed:

```bash
sudo apt update
sudo apt install build-essential gcc
