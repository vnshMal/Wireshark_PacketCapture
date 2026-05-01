# Wireshark_PacketCapture
*Group Members:** Vansh Malik, Aikagra Gupta
**Date:** 1st May 2026

---

## 1. Problem Statement
The objective of this project is to analyze real-time network traffic and detect suspicious activities. Using Wireshark and Python, we captured network packets, identified various protocols (HTTP, DNS, TCP, UDP, ICMP), applied filters to isolate specific traffic, and analyzed the data for potential anomalies such as SYN floods and repeated DNS queries.

---

## 2. Tools Used
- **Wireshark:** To view and filter raw packet captures (`.pcap`).
- **Python:** For packet parsing (`scapy`) and visual representation (`matplotlib`).
- **OBS Studio / Built-in Screen Recorder:** To record the demonstration video.

---

## 3. Tasks Completed

### 3.1 Packet Capture
We captured network traffic containing various protocols. For demonstration, we generated a sample containing normal traffic alongside simulated attacks.
*The generated capture file `sample_traffic.pcap` is attached in the repository.*

### 3.2 Protocol Identification and Filtering
Using Wireshark, we applied the following display filters to identify specific traffic types:


### 3.3 Protocol Distribution Chart
Using our Python script (`analyze_traffic.py`), we parsed the `.pcap` file and generated the following distribution chart to visualize the proportion of protocols in the capture.

![Protocol Distribution](protocol_distribution.png)

---

## 4. Anomaly Detection and Suspicious Packet Report
We analyzed the capture for potential anomalies. Our automated script detected the following activities:

1. **SYN Flood Detection:**
   - **Finding:** A high volume of TCP packets with only the SYN flag set targeting a single destination.
   - **Details:** 1000 SYN packets sent to `10.0.0.5:80`. This indicates a potential Denial of Service (DoS) attempt aiming to exhaust server resources.

2. **Repeated DNS Queries:**
   - **Finding:** Excessive DNS requests for the same domain originating from a single IP.
   - **Details:** IP `192.168.1.100` requested `malicious-site.com` over 300 times in a short burst. This could indicate a misconfigured application, malware beaconing, or DNS tunneling.

---

## 5. Deliverables Checklist
- [x] **PDF Report:** (Convert this Markdown file to PDF).
- [x] **.pcap File:** `sample_traffic.pcap` is provided in the repository.
- [x] **Code:** `analyze_traffic.py` and `generate_pcap.py` are pushed to GitHub.
- [x] **Screen Recording:** Demonstrating Wireshark filters and running the Python script.
