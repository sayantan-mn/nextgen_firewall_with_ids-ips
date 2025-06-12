from flask import Flask, request, jsonify # type: ignore
from flask_socketio import SocketIO, emit # type: ignore
from scapy.all import sniff, IP, TCP, UDP
import threading, time, datetime
import socket
import os
import json

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

# Firewall and IPS Data Structures
# Stores allow/block rules
#firewall_rules
firewallRule = [
    {"action": "block", "ip": "192.168.1.100", "port": 22, "protocol": "TCP"}, 
    {"action": "allow", "ip": "192.168.1.50", "port": 80, "protocol": "TCP"},  
    {"action": "block", "ip": "192.168.1.101", "port": 22, "protocol": "TCP"}, 
    {"action": "allow", "ip": "192.168.1.212", "port": 80, "protocol": "TCP"} ,
    # {"action": "block", "ip": "192.168.1.16", "port": 443, "protocol": "TCP"}, 
     ]  

# blocked_ips = {"192.168.1.18": 1700000000.123, "10.0.0.2": 1700000050.456}  # Stores temporarily blocked IPs (for DoS/IPS)
blocked_ips = {'11.11.11.11': {'expiry': 1739814806.9177449, 'reason': 'Manually'}, '192.168.2.2': {'expiry': 1739814822.9061577, 'reason': 'DoS'}}
connection_tracking = {}  # Tracks connections for stateful inspection

system_logs = []  # Stores system logs
traffic_stats = {"packet_count": 0, "source_ips": {}, "protocols": {"TCP": 0, "UDP": 0, "OTHER": 0}} #captures traffic data

mal_ports = [21,22, 23, 25, 137, 139, 445, 31337, 3389, 3306]
# IPS Configuration
DOS_THRESHOLD = 200  # Packets per second per IP
BLOCK_DURATION = 30  # Time (seconds) to block an IP
ip_packet_count = {}

# pkt_lst = {}
# pkt_cnt = 0

# Logging of blocked data into json file
log_file_path = os.path.join(os.getcwd(), "firewall_logs.json")
def log_event(event):
    system_logs.append(event)
    with open(log_file_path, "a") as log_file:
        log_file.write(str(datetime.datetime.now()) + " " + json.dumps(event) + "\n")

def check_firewall_rules(src_ip, dst_ip, src_port, dst_port, protocol):
    for rule in firewallRule:
        if (rule['ip'] == src_ip or rule['ip'] == dst_ip) and (rule['port'] == dst_port or rule['port'] == src_port or rule['port'] == "") and rule['protocol'] == protocol:
            return rule['action']  # "allow" or "block"
    return "allow"

def check_blocked_rules(ipaddr):
    fl=1
    if ipaddr in blocked_ips.keys():
        fl=0
    return fl

def check_port(prt):
    if prt in mal_ports:
        return 0
    return 1

def detect_intrusion(packet):
    global ip_packet_count
    if IP in packet:
        src_ip = packet[IP].src
        
        # Track Packet Count for DoS Detection
        if src_ip in ip_packet_count:
            ip_packet_count[src_ip] += 1
        else:
            ip_packet_count[src_ip] = 1

def reset_packet_counts():
    # """ Resets packet count every second for DoS tracking """
    global ip_packet_count
    while True:
        time.sleep(1)
        for ip, count in ip_packet_count.items():
            if count > DOS_THRESHOLD:
                # blocked_ips[ip] = time.time() + BLOCK_DURATION
                blocked_ips[ip] = {"expiry": time.time() + BLOCK_DURATION, "reason": "Probable DoS Attack"}
                socketio.emit("ip_blockedDOS", {"ip": ip, "reason": "Probable DoS Attack"})
                log_event({"type": "IPS_BLOCK", "ip": ip, "reason": "Probable DoS Attack"})
                # print(f"[IPS BLOCK] {ip} blocked for suspected DoS attack.")
        ip_packet_count = {}
        
    

def packet_callback(packet):
    alwd = 1 #1-> allowed, 0-> blocked
    # global pkt_cnt
    if IP in packet:
        # pkt_cnt += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        #traffic stats update
        traffic_stats["packet_count"] += 1
        traffic_stats["source_ips"].setdefault(src_ip, 0)
        traffic_stats["source_ips"][src_ip] += 1
        
        # Check if IP is dynamically blocked
        if src_ip in blocked_ips and time.time() < blocked_ips[src_ip]["expiry"]:
            # print(f"[BLOCKED] {src_ip} -> {dst_ip} (Blocked by IPS)")
            return
        elif src_ip in blocked_ips:
            del blocked_ips[src_ip]  # Unblock after time expires
            # print(f"[UNBLOCKED] {src_ip} (Auto Unblocked)")
        
        proto = "OTHER"
        src_port, dst_port = None, None
        flag = "None"
        
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            proto = "TCP"
            traffic_stats["protocols"]["TCP"] += 1
            # flg = packet[TCP].flags
            if packet[TCP].flags == 2:
                flag="SYN_SENT"
            elif packet[TCP].flags == 18:
                flag="CONN_ESTD"
            elif packet[TCP].flags & 1:
                flag="FIN"
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            proto = "UDP"
            traffic_stats["protocols"]["UDP"] += 1
        else:
            traffic_stats["protocols"]["OTHER"] += 1
            
        #stateful inspection by adding the active connections to a tracking list
        conn = (src_ip, src_port, dst_ip, dst_port, proto)
        rev_conn = (dst_ip, dst_port, src_ip, src_port, proto)
        curr_time = time.time()
        # print(f"Packet: {conn}")
        
        if conn not in connection_tracking and rev_conn not in connection_tracking:
            connection_tracking[conn] = curr_time
        #     print(f"[NEW CONNECTION] {conn} Flag: {flag}")
        # else:
        #     print(f"[EXISTING CONNECTION] {conn} Flag: {flag}")
            
        # Remove stale connections (timeout after 60 seconds)
        stale_connections = [cn for cn, tmstmp in connection_tracking.items()
            if curr_time - tmstmp > 60 ]
        for cn in stale_connections:
            del connection_tracking[cn]
            # print(f"[CONNECTION TIMEOUT] {cn}")
        
        action = check_firewall_rules(src_ip, dst_ip, src_port, dst_port, proto)
        if action == "block":
            alwd=0
            log_event({"type": "FIREWALL BLOCK", "ip": src_ip,"dest_ip":dst_ip, "port": src_port, "protocol": proto, "reason": "Firewall_rule"})
            print(f"[BLOCKED] {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port} (Firewall Rule Match)")
            #return
        
        if (check_blocked_rules(src_ip) == 0) or (check_blocked_rules(dst_ip) == 0):
            alwd=0
            print(f"{src_ip}, {dst_ip} Connection is blocked (blocked rule set)")
        
        if (check_port(src_port) == 0) or (check_port(dst_port) == 0): #malicious port check
            alwd=0
            print(f"{src_port}, {dst_port} Connection is blocked (Blocked port)")
            log_event({"type": "PORT_BLOCK", "ip": src_port, "reason": "Malicious port used"})
        
        detect_intrusion(packet)
        
        # Emit to WebSocket clients
        #Send data to front end 
        packet_data = {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "flags": flag,  # Convert flags to string
            "al": alwd
        }
        socketio.emit("packet", packet_data)
        # print(f"[ALLOWED] {proto} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")

@app.route("/firewall/rules", methods=["GET", "POST", "DELETE"])
def manage_firewall():
    if request.method == "GET":
        return jsonify(firewallRule)
    elif request.method == "POST":
        data = request.json
        if data not in firewallRule:
            firewallRule.append(data)
        return jsonify({"message": "Firewall Rule added"})
    elif request.method == "DELETE":
        data = request.json
        firewallRule.remove(data)
        return jsonify({"message": "Firewall Rule removed"})

@app.route("/blocked_ips", methods=["GET", "POST", "DELETE"])
def manage_blocked_ips():
    if request.method == "GET":
        print("BlockedIPs are:",blocked_ips)
        # return jsonify(list(blocked_ips.keys()))
        return jsonify([{ "ip": ip, "reason": details["reason"] } for ip, details in blocked_ips.items()])
    
    # POST request to add IP addr to blocked list
    elif request.method == "POST":
        data = request.json
        print(f"Received data: {data}")
        ip = data.get("ip")
        reason = data.get("reason")
        print(ip)
        if ip:
            # blocked_ips[ip] = time.time()
            # return jsonify({"message": f"{ip} blocked manually"})
            blocked_ips[ip] = {"expiry": time.time() + BLOCK_DURATION, "reason": reason}
            log_event({"type": "Manual Block", "ip": ip, "reason": reason})
            return jsonify({"message": f"{ip} blocked manually", "status": "ok"})
        
        return jsonify({"message": "Invalid IP address", "status": "error"})
        
        # if data:
        #     blocked_ips[data] = time.time()
        #     # return jsonify({"message": f"{ip} blocked manually"})
        # return jsonify({"message": "Invalid IP address"})
            
        
    elif request.method == "DELETE":
        data = request.json
        ip = data.get("ip")
        if ip in blocked_ips:
            del blocked_ips[ip]
            return jsonify({"message": f"{ip} unblocked", "status": "ok"})
        return jsonify({"message": "IP not found", "status": "error"})
    
#system logs
@app.route("/system_logs", methods=["GET"])
def get_logs():
    return jsonify(system_logs)    

# live traffic status
@app.route("/traffic_stats", methods=["GET"])
def get_traffic_stats():
    sorted_ips = sorted(traffic_stats["source_ips"].items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify({
        "packet_count": traffic_stats["packet_count"],
        "top_10_ips": sorted_ips,
        "protocol_dist": traffic_stats["protocols"]
    })

@app.route("/track_conn", methods=["GET"])
def track_connections():
    if request.method == "GET":
        return jsonify(list(connection_tracking.keys()))

def start_sniffing():
    sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    # print("IP address of the system is: ",socket.gethostbyname(socket.gethostname()))
    # threading.Thread(target=reset_time_pkts, daemon=True).start()
    threading.Thread(target=reset_packet_counts, daemon=True).start()
    threading.Thread(target=start_sniffing, daemon=True).start()
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
    
