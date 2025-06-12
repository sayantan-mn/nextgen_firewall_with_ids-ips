# 🛡️ Real-Time Firewall + IPS/IDS Dashboard

A web based network monitoring and threat detection with intrusion prevention system that captures real-time packets, analyzes traffic, applies firewall rules, and visualizes data using a React dashboard.

## 🚀 What This Project Does

Traditional security tools are not enough in a world where cyber threats evolve faster than coffee brews. This project captures **live packet traffic**, applies **dynamic firewall rules**, and intelligently detects suspicious behavior like **DoS attacks** — all while visualizing the data in real time.

# Key features include:

✅ Real-time packet sniffing using **Scapy**  
✅ Live traffic analysis + protocol breakdown  
✅ **Dynamic IP blocking** based on suspicious patterns  
✅ Visual dashboards using **React + Recharts**  
✅ Manual firewall rule management (add/remove IPs)  
✅ Real-time alerts via **WebSockets**  
✅ Logging of system events and blocked IPs  
✅ Clean, responsive UI with intuitive data presentation

## ⚙️ Tech Stack
- **Backend**: Flask, Scapy, Flask-SocketIO
- **Frontend**: React.js, Recharts, Socket.IO-client
- **Protocol Support**: TCP, UDP

## 🧠 Motivation

Most firewalls and intrusion systems work in isolation. But real-world networks need real-time, unified insights. This project was built to solve that — to give admins and security teams a **single window** into their traffic, threats, and security rules, all in one place.

## 📊 Dashboard Preview


## 📈 What It Can Do (So Far)

- ✅ Monitor live network traffic  
- ✅ Visualize packet flow over time  
- ✅ Automatically detect and block potential DoS attacks  
- ✅ Let users manage firewall rules via a UI  
- ✅ Display real-time statistics on protocols and source IPs  
- ✅ Maintain logs for every major event


## 📦 Installation Guide

### 📌 Prerequisites
- Python 3.8+
- Node.js & npm
- `pip` and virtual environment (optional but recommended)

#### ▶️ Step 1: Clone the Repository

#### 🧪 Step 2: Set up the Backend
- cd backend_flask
- pip install -r requirements.txt
- venv\Scripts\activate
- python packet_chk.py

#### 💻 Step 3: Set up the Frontend
- cd frontend_react
- npm start

### 🔒 Use Cases
- Home network security
- University or research lab monitoring
- Teaching and demonstration for cybersecurity students
- Lightweight enterprise traffic monitoring
- Open-source extension base for future research

### 📜 License
This project is open-source and available under the MIT License.
