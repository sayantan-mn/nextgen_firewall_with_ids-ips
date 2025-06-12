import React, { useState, useEffect } from "react";
import { io, protocol } from "socket.io-client";
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, Tooltip, CartesianGrid, Label } from "recharts";
import "./App.css";
// import "./styles.css";
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';

const socket = io("http://localhost:5000");

export default function Dashboard() {
  const [packets, setPackets] = useState([]);
  const [firewallRules, setFirewallRules] = useState([]);
  const [blockedIPs, setBlockedIPs] = useState([]);
  const [connections, setConnections] = useState([]);

  const [alerts, setAlerts] = useState([]);
  const [logs, setLogs] = useState([]);
  const [trafficStats, setTrafficStats] = useState({ packet_count: 0, top_10_ips: [], protocol_dist: { TCP: 0, UDP: 0, OTHER: 0 }, });

  const [inputIP, setInputIP] = useState(""); //to block IP address
  const [inputRsn, setInputRsn] = useState(""); //reason to block IPaddr
  const [fw_ip, setFwIP] = useState("");
  const [fw_port, setFwPort] = useState("");
  const [fw_proto, setFwProto] = useState("");
  const [fw_actn, setFwAction] = useState("");

  const [packetCount, setPacketCount] = useState([]);

  // let newPacket = {}

  useEffect(() => {
    let packetsReceived = 0;

    const interval = setInterval(() => {
      setPacketCount((prevPackets) => {
        const newPacket = { time: new Date().toLocaleTimeString(), count: packetsReceived };
        packetsReceived = 0;
        return [newPacket, ...prevPackets].slice(0, 50);
      });
    }, 1000);


    socket.on("packet", (packet) => {
      setPackets((prev) => [packet, ...prev.slice(0, 99)]);
      packetsReceived++;
    });

    // DoS attack notification
    socket.on("ip_blockedDOS", (bk_ip) => {
      toast.error(`⚠️ IP ${bk_ip.ip} blocked: ${bk_ip.reason}`);
      fetchBlockedIPs();
    });

    fetchFirewallRules();
    fetchBlockedIPs();
    fetchConnections();

    fetchAlerts();
    fetchLogs();
    
    fetchTrafficStats();
    // const statsInterval = setInterval(fetchTrafficStats, 5000);

    return () => {
      // clearInterval(interval);
      // clearInterval(statsInterval);
    };
  }, []);

  const fetchFirewallRules = async () => {
    const res = await fetch("http://localhost:3000/firewall/rules");
    const data = await res.json();
    setFirewallRules(data);
  };

  const fetchBlockedIPs = async () => {
    const res = await fetch("http://localhost:3000/blocked_ips");
    const data = await res.json();
    setBlockedIPs(data);
  };

  // connection_tracking
  const fetchConnections = async() =>{
    const res = await fetch("http://localhost:3000/track_conn");
    const data = await res.json();
    setConnections(data);
    fetchConnections();
  }

  const addFirewallRule = async (ip, port, protocol, action) => {
    const resp = await fetch("http://localhost:3000/firewall/rules", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip, port, protocol, action }),
    });
    const data = await resp.json();
    toast.success(data.message);
    fetchFirewallRules();
  };

  const removeFirewallRule = async (rule) => {
    const resp = await fetch("http://localhost:3000/firewall/rules", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(rule),
    });
    const data = await resp.json();
    toast.success(data.message);
    fetchFirewallRules();
  };

  const unblockIP = async (ip) => {
    const resp = await fetch("http://localhost:3000/blocked_ips", {
      method: "DELETE",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip }),
    });
    const data = await resp.json();
    toast.success(data.message);
    fetchBlockedIPs();
  };

  const blockIP = async (inpIP, inpRsn) => {
    const resp = await fetch("http://localhost:3000/blocked_ips", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ip: inpIP, reason: inpRsn}),
    });
    const data = await resp.json();
    if(data.status === "ok"){
      toast.success(data.message);
    }
    else{
      toast.error(data.message);
    }
    
    fetchBlockedIPs();
  };



  const fetchAlerts = async () => {
    const response = await fetch("http://localhost:3000/system_logs");
    const data = await response.json();
    setAlerts(data);
    fetchAlerts();
  };

  const fetchLogs = async () => {
    const response = await fetch("http://localhost:3000/system_logs");
    const data = await response.json();
    setLogs(data);
    fetchLogs();
  };

  const fetchTrafficStats = async () => {
    const response = await fetch("http://localhost:3000/traffic_stats");
    const data = await response.json();
    setTrafficStats(data);
    fetchTrafficStats();
    // style={{ padding: "20px" }}
  };
 
  // const protocolColors = { TCP: "#8884d8", UDP: "#82ca9d", OTHER: "#ffc658" };
  const protocolColors = { TCP: "#655df1", UDP: "#71eda0", OTHER: "#fab834" };

  return (
    <div className="main_div"> 
      <h1>Firewall demonstration</h1>

      <div className="live_traf">
      <h2>Live Traffic</h2>
          <div className="live_traf_graph">
          <p>Total Packets processed: {trafficStats.packet_count}</p>
          <LineChart width={1200} height={200} data={packetCount.map(({ time, count }) => ({ time, count }))}>
            <XAxis dataKey="time"/>
            <YAxis />
            <CartesianGrid strokeDasharray="1 1" />
            <Tooltip />
            <Line type="monotone" dataKey="count" stroke="#a6e083" /> 
            {/* stroke="#8884d8" */}
          </LineChart>
          </div>

          <div className="live_traf_table"> 
          <table id="live_table">
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Dest IP</th>
                <th>Source Port</th>
                <th>Dest Port</th>
                <th>Protocol</th>
                <th>Flags</th>
                {/* <th>Alwd</th> */}
              </tr>
            </thead>
            <tbody>
              {packets.map((pkt, index) => (
                <tr key={index} bgcolor={pkt.al === 1? "#56a85b":"#874646"}>
                  <td>{pkt.src_ip}</td>
                  <td>{pkt.dst_ip}</td>
                  <td>{pkt.src_port}</td>
                  <td>{pkt.dst_port}</td>
                  <td>{pkt.protocol}</td>
                  <td>{pkt.flags}</td>
                  {/* <td>{pkt.al}</td> */}
                </tr>
                
              ))}
            </tbody>
          </table>
          </div>
      </div>

      <div className="firewall_rules">
        <h2>Firewall Rules</h2>      
        <div className="firewall_rules_table">
          <table id="fw_table">
            <tr>
              <th>Rule IP</th>
              <th>Rule Port</th>
              <th>Protocol</th>
              <th>Action</th>
              <th>Remove rule</th>
            </tr>
            
            {firewallRules.map((rule, index) => (
              <tr key={index} align="center" bgcolor={rule.action === 'allow'? "#56a85b":"#874646"}>
                <td>{rule.ip}</td>
                <td>{rule.port}</td>
                <td>{rule.protocol}</td>
                <td>{rule.action}</td> 
                <td><button onClick={() => removeFirewallRule(rule)}>Remove</button></td>
              </tr>
            ))}
          </table>
        </div>

        <div className="firewall_rule_add">
          <label>IP Address: </label>
          <input type="text" name="fw_ipblk" value={fw_ip} onChange={(e) => setFwIP(e.target.value)}></input>
          <label>Port Number: </label>
          <input type="text" name="fw_portblk" value={fw_port} onChange={(e) => setFwPort(e.target.value)}></input>
          <label>Protocol: </label>
          <label>
            <input type="radio" name="proto_radio" value="TCP" onChange={(e)=> setFwProto(e.target.value)}/> TCP
          </label>
          
          <label>
            <input type="radio" name="proto_radio" value="UDP" onChange={(e)=> setFwProto(e.target.value)}/> UDP
          </label>
          <p>Current Protocol: {fw_proto}</p>
          <label>Action: </label>
          <label>
            <input type="radio" name="action_radio" value="allow" onChange={(e)=> setFwAction(e.target.value)}/> ALLOW
          </label>
          <label>
            <input type="radio" name="action_radio" value="block" onChange={(e)=> setFwAction(e.target.value)}/> BLOCK
          </label>
          <p>Current Action selected: {fw_actn}</p>
          <button onClick={() => addFirewallRule(fw_ip, fw_port, fw_proto, fw_actn)}>Add Rule</button>
        </div>
      </div>
      
      

      <div className="blocked_ips">
        <div className="blocked_ips_table">
        <h2>Blocked IPs</h2>
          <table id="blk_ip_table">
            <tr align="center">
              <th>IP Addr</th>
              <th>Reason</th>
              <th>Action</th>
            </tr>
            {blockedIPs.map((ipad, index) => (
              <tr key={index} align="center">
                <td>{ipad.ip}</td>
                <td>{ipad.reason}</td>
                <td><button type="button" onClick={() => unblockIP(ipad.ip)}>Unblock</button></td>
              </tr>
            ))}
          </table>
        </div>

        <div className="blocked_ips_add">
          <label>IP Address to block: </label>
          <input type="text" name="blk_ipaddr" value={inputIP} onChange={(e) => setInputIP(e.target.value)}/>
          <label>Reason to block: </label>
          <input type="text" name="blk_ipaddr_rsn" value={inputRsn} onChange={(e) => setInputRsn(e.target.value)}/>
          <button type="button" onClick={() => blockIP(inputIP, inputRsn)}>Block IP</button>
          <p>Current Input: {inputIP} {inputRsn}</p>
        </div>
      </div>
      
      <div className="conn_tracking">
        <h2>Connection tracking</h2>
        <div className="conn_tracking_table" >
          <table id="ct_table">
            <tr align="center">
              <th>Source IP</th>
              <th>Source Port</th>
              <th>Dest IP</th>
              <th>Dest Port</th>
              <th>Protocol</th>
            </tr>
          
            {connections.map((conn,index) => (
              <tr key={index} align="center">
                <td>{conn[0]}</td>
                <td>{conn[1]}</td>
                <td>{conn[2]}</td>
                <td>{conn[3]}</td>
                <td>{conn[4]}</td>
              </tr>
            ))}
          </table>
        </div>
      </div>

      <div className="traf_stats">
        
        <div className="traf_stats_table">
        <h1>Traffic Statistics</h1>
        <p>Packets Processed: {trafficStats.packet_count}</p>
        <h3>Top 10 Frequent Source IPs</h3>
        <table border='1' width="50%">
          <tr>
            <th>IP addr</th>
            <th>No of Packets</th>
          </tr>
          {trafficStats.top_10_ips.map(([ip, count], index) => (
            <tr key={index}>
              <td>{ip}</td>
              <td>{count} packets</td>
            
            </tr>
          ))} 
        </table>
        </div>

        <div className="traf_stats_graph">
          <h3>Top 10 Source IPs</h3>
          <BarChart width={500} height={300} data={trafficStats.top_10_ips.map(([ip, count]) => ({ ip, count }))} layout="vertical" >
            <XAxis type="number"/>
            <YAxis dataKey="ip" type="category" width={200}/>
            <Bar dataKey="count" fill="#635bf6" />
            <Tooltip />
          </BarChart>
        </div>
      </div>
      
      <div className="proto_dist">
        
        <div className="proto_dist_table">
        <h1>Protocol Distribution</h1>
          <table id="proto_table">
            <tr>
              <th>Protocol</th>
              <th>Packets received</th>
            </tr>
            {Object.entries(trafficStats.protocol_dist).map(([protocol, count], index) => (
              <tr key={index} align="center">
                <td>{protocol}</td>
                <td>{count}</td>
              </tr>
            ))}
          </table>
        </div>

        <div className="proto_dist_graph">
          {/* Protocol Distribution Pie Chart */}
          <PieChart width={400} height={400}>
            <Pie
              data={Object.entries(trafficStats.protocol_dist).map(([protocol, count]) => ({ protocol, count }))}
              dataKey="count"
              nameKey="protocol"
              cx="50%"
              cy="50%"
              innerRadius={80}
              outerRadius={120}
              fill="#8884d8"
              label >
                <Label 
                value={`${trafficStats.packet_count} pkts`}
                position="center"
                style={{
                  fontSize: "30px",
                  fontWeight: "bold",
                  fill: "white", //white
                }} />
                                 
              {Object.entries(trafficStats.protocol_dist).map(([protocol]) => (
                <Cell key={protocol} fill={protocolColors[protocol]} />
              ))}
            </Pie>
            <Tooltip />
          </PieChart>
        </div>
      </div>

      <div className="alerts_and_logs">
      <div className="alerts">
        <h2>IDS/IPS Alerts</h2>
        <ul>
          {alerts.map((alert, index) => (
            <li key={index}>{alert.type} - {alert.ip} - {alert.reason}</li>
          ))}
        </ul>
      </div>
      <div className="logs">
        <h2>System Logs</h2>
        <ul>
          {logs.map((log, index) => (
            <li key={index}>{JSON.stringify(log)}</li>
          ))}
        </ul>
      </div>
      

      </div>
      <ToastContainer position="top-right" autoClose={5000} theme="light"/>
    {/* End div close */}
    </div>
  );
}

