import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from scapy.all import (
    sniff, IP, IPv6, TCP, UDP, ICMP, ARP, DNS,
    ICMPv6EchoRequest, ICMPv6EchoReply,
    Ether, Raw
)
from scapy.utils import PcapReader
from datetime import datetime
from collections import Counter, defaultdict, deque
from threading import Thread, Lock
from queue import Queue, Empty
import csv
import json
import html as html_escape
import socket
import time
import ssl
import ipaddress
import urllib.request
import urllib.error
import urllib.parse
from html.parser import HTMLParser


# =========================
# APPLICATION CONFIGURATION
# =========================

APP_TITLE = "NetScope | Network Packet Analyzer"

BG_COLOR = "#F4F7FB"
CARD_COLOR = "#FFFFFF"
PRIMARY_COLOR = "#2563EB"
TEXT_COLOR = "#1E293B"
MUTED_COLOR = "#64748B"
BORDER_COLOR = "#E2E8F0"

packets_queue = Queue()
capture_lock = Lock()

captured_packets = []
packet_objects = {}
protocol_counts = Counter()
# Processing-time events used by the rolling live traffic monitor.
traffic_events = deque(maxlen=10000)

# Security-event tracking (heuristics, not proof of an attack)
security_alerts = []
alert_signatures = set()
recent_syn_attempts = defaultdict(deque)
recent_source_packets = defaultdict(deque)
recent_port_scan_attempts = defaultdict(deque)
detected_port_scans = set()

capture_running = False
pcap_import_running = False
packet_number = 0


# =========================
# PACKET ANALYSIS
# =========================

def analyze_packet(packet):
    global packet_number

    try:
        timestamp = datetime.fromtimestamp(
            float(packet.time)
        ).strftime("%H:%M:%S")

        source_ip = "Unknown"
        destination_ip = "Unknown"
        protocol = "Other"
        source_port = "-"
        destination_port = "-"
        application = "-"

        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst

        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst

        if ARP in packet:
            source_ip = packet[ARP].psrc
            destination_ip = packet[ARP].pdst
            protocol = "ARP"

        elif TCP in packet:
            protocol = "TCP"
            source_port = packet[TCP].sport
            destination_port = packet[TCP].dport

        elif UDP in packet:
            protocol = "UDP"
            source_port = packet[UDP].sport
            destination_port = packet[UDP].dport

        elif ICMP in packet:
            protocol = "ICMP"

        elif (
            ICMPv6EchoRequest in packet
            or ICMPv6EchoReply in packet
        ):
            protocol = "ICMPv6"

        elif IPv6 in packet and packet.haslayer("ICMPv6"):
            protocol = "ICMPv6"

        elif IPv6 in packet:
            protocol = "IPv6"

        elif IP in packet:
            protocol = "IPv4"

        if DNS in packet:
            application = "DNS"

        size = len(packet)

        with capture_lock:
            packet_number += 1
            current_number = packet_number

            protocol_counts[protocol] += 1

            record = {
                "No.": current_number,
                "Time": timestamp,
                "Source IP": source_ip,
                "Destination IP": destination_ip,
                "Protocol": protocol,
                "Source Port": source_port,
                "Destination Port": destination_port,
                "Application": application,
                "Size (Bytes)": size
            }

            captured_packets.append(record)
            packet_objects[current_number] = packet
            # Use processing time so live captures and imported PCAPs can both
            # feed the monitor. Importing a large PCAP may briefly show a spike.
            traffic_events.append((time.time(), size, protocol))

            # Basic traffic heuristics. These identify patterns for review,
            # not confirmed attacks.
            packet_time = float(packet.time)
            source_key = source_ip
            source_times = recent_source_packets[source_key]
            source_times.append(packet_time)
            while source_times and packet_time - source_times[0] > 10:
                source_times.popleft()

            if len(source_times) >= 120:
                signature = ("high-volume-source", source_key)
                if signature not in alert_signatures:
                    alert_signatures.add(signature)
                    security_alerts.append({
                        "Time": timestamp,
                        "Severity": "Medium",
                        "Rule": "High packet rate",
                        "Source": source_ip,
                        "Destination": "Multiple / unknown",
                        "Details": (
                            f"At least {len(source_times)} packets from this source "
                            "were observed within 10 seconds. Review context before concluding."
                        )
                    })

            if TCP in packet:
                tcp_layer = packet[TCP]
                flags = int(tcp_layer.flags)
                is_syn_without_ack = bool(flags & 0x02) and not bool(flags & 0x10)
                if is_syn_without_ack:
                    syn_key = (source_ip, destination_ip, int(tcp_layer.dport))
                    syn_times = recent_syn_attempts[syn_key]
                    syn_times.append(packet_time)
                    while syn_times and packet_time - syn_times[0] > 30:
                        syn_times.popleft()

                    if len(syn_times) >= 8:
                        signature = ("repeated-syn",) + syn_key
                        if signature not in alert_signatures:
                            alert_signatures.add(signature)
                            security_alerts.append({
                                "Time": timestamp,
                                "Severity": "Medium",
                                "Rule": "Repeated TCP SYN attempts",
                                "Source": source_ip,
                                "Destination": f"{destination_ip}:{tcp_layer.dport}",
                                "Details": (
                                    f"At least {len(syn_times)} TCP SYN packets without ACK "
                                    "were observed from the same source to this destination "
                                    "within 30 seconds. This can also occur during normal connection attempts."
                                )
                            })

            # Port-scan heuristic: track TCP SYN packets without ACK to
            # different destination ports on the same target over 30 seconds.
            # This is a detection indicator, not proof of malicious activity.
            if TCP in packet:
                tcp_layer = packet[TCP]
                flags = int(tcp_layer.flags)
                is_syn_without_ack = bool(flags & 0x02) and not bool(flags & 0x10)
                if is_syn_without_ack and source_ip != "Unknown" and destination_ip != "Unknown":
                    scan_key = (source_ip, destination_ip)
                    scan_attempts = recent_port_scan_attempts[scan_key]
                    scan_attempts.append((packet_time, int(tcp_layer.dport)))
                    while scan_attempts and packet_time - scan_attempts[0][0] > 30:
                        scan_attempts.popleft()

                    unique_ports = {port for _, port in scan_attempts}
                    if len(unique_ports) >= 12 and scan_key not in detected_port_scans:
                        detected_port_scans.add(scan_key)
                        severity = "High" if len(unique_ports) >= 20 else "Medium"
                        security_alerts.append({
                            "Time": timestamp,
                            "Severity": severity,
                            "Rule": "Possible TCP port scan",
                            "Source": source_ip,
                            "Destination": destination_ip,
                            "Details": (
                                f"TCP SYN attempts reached {len(unique_ports)} distinct destination ports "
                                "within 30 seconds. This may indicate port scanning; validate against "
                                "authorized scanners and normal network activity."
                            )
                        })

        packets_queue.put(record)

    except Exception as error:
        print("Packet analysis error:", error)


# =========================
# PACKET CAPTURE
# =========================

def capture_worker():
    global capture_running

    try:
        sniff(
            prn=analyze_packet,
            store=False,
            stop_filter=lambda packet: not capture_running
        )

    except Exception as error:
        packets_queue.put({
            "type": "error",
            "message": str(error)
        })

    finally:
        capture_running = False
        packets_queue.put({"type": "stopped"})


def start_capture():
    global capture_running

    if capture_running:
        return

    capture_running = True

    start_button.config(state="disabled")
    stop_button.config(state="normal")
    status_label.config(
        text="● Capturing packets",
        foreground="#16A34A"
    )

    Thread(
        target=capture_worker,
        daemon=True
    ).start()


def stop_capture():
    global capture_running

    capture_running = False

    stop_button.config(state="disabled")

    status_label.config(
        text="Stopping capture...",
        foreground="#D97706"
    )


# =========================
# OFFLINE PCAP FILE ANALYZER
# =========================

def import_pcap_file():
    """Load packets from a .pcap or .pcapng file into the current packet table."""
    global pcap_import_running

    if capture_running:
        messagebox.showwarning(
            "Capture Running",
            "Stop live capture before importing a PCAP file."
        )
        return

    if pcap_import_running:
        messagebox.showinfo(
            "Import In Progress",
            "A capture file is already being analyzed. Please wait."
        )
        return

    file_path = filedialog.askopenfilename(
        title="Select a packet capture file",
        filetypes=[
            ("Packet capture files", "*.pcap *.pcapng *.cap"),
            ("All files", "*.*")
        ]
    )

    if not file_path:
        return

    pcap_import_running = True
    import_pcap_button.config(state="disabled")
    start_button.config(state="disabled")
    status_label.config(
        text="● Analyzing capture file...",
        foreground="#D97706"
    )

    Thread(
        target=pcap_import_worker,
        args=(file_path,),
        daemon=True
    ).start()


def pcap_import_worker(file_path):
    """Read the capture off the GUI thread to keep the application responsive."""
    count = 0
    try:
        with PcapReader(file_path) as reader:
            for packet in reader:
                analyze_packet(packet)
                count += 1

        packets_queue.put({
            "type": "pcap_import_done",
            "path": file_path,
            "count": count
        })
    except Exception as error:
        packets_queue.put({
            "type": "pcap_import_error",
            "message": str(error)
        })


# =========================
# DASHBOARD UPDATES
# =========================

def update_dashboard():
    total = len(captured_packets)

    total_value.config(text=str(total))

    with capture_lock:
        tcp_count = protocol_counts["TCP"]
        udp_count = protocol_counts["UDP"]
        other_count = sum(
            count
            for protocol, count in protocol_counts.items()
            if protocol not in ("TCP", "UDP")
        )

    tcp_value.config(text=str(tcp_count))
    udp_value.config(text=str(udp_count))
    other_value.config(text=str(other_count))


def apply_filter(*args):
    selected_protocol = filter_var.get()
    query = search_var.get().strip().lower()

    for item in packet_table.get_children():
        packet_table.delete(item)

    with capture_lock:
        records = list(captured_packets)

    for record in records:

        # Protocol filter
        if (
            selected_protocol != "All Protocols"
            and record["Protocol"] != selected_protocol
        ):
            continue

        # Search across packet fields
        searchable_text = " ".join(
            str(value)
            for value in record.values()
        ).lower()

        if query and query not in searchable_text:
            continue

        packet_table.insert(
            "",
            "end",
            values=(
                record["No."],
                record["Time"],
                record["Source IP"],
                record["Destination IP"],
                record["Protocol"],
                record["Source Port"],
                record["Destination Port"],
                record["Application"],
                record["Size (Bytes)"]
            )
        )

def process_queue():
    global capture_running

    updated = False

    try:
        while True:
            record = packets_queue.get_nowait()

            if record.get("type") == "error":
                messagebox.showerror(
                    "Capture Error",
                    "Could not capture packets.\n\n"
                    + record["message"]
                    + "\n\nCheck your permissions and "
                      "network capture setup."
                )

            elif record.get("type") == "pcap_import_done":
                global pcap_import_running
                pcap_import_running = False
                import_pcap_button.config(state="normal")
                start_button.config(state="normal")
                status_label.config(
                    text=f"● File analysis complete: {record['count']} packets",
                    foreground="#16A34A"
                )
                messagebox.showinfo(
                    "PCAP Analysis Complete",
                    f"Analyzed {record['count']} packets from:\n{record['path']}\n\n"
                    "The packets are now available in the table, filters, details, "
                    "statistics, security alerts, and report tools."
                )

            elif record.get("type") == "pcap_import_error":
                pcap_import_running = False
                import_pcap_button.config(state="normal")
                start_button.config(state="normal")
                status_label.config(
                    text="● Capture file analysis failed",
                    foreground="#DC2626"
                )
                messagebox.showerror(
                    "PCAP Import Error",
                    "Could not analyze this capture file.\n\n" + record["message"]
                )

            elif record.get("type") == "stopped":
                capture_running = False

                start_button.config(state="normal")
                stop_button.config(state="disabled")

                status_label.config(
                    text="● Capture stopped",
                    foreground=MUTED_COLOR
                )

            else:
                selected_protocol = filter_var.get()

                if (
                    selected_protocol == "All Protocols"
                    or record["Protocol"] == selected_protocol
                ):
                    packet_table.insert(
                        "",
                        "end",
                        values=(
                            record["No."],
                            record["Time"],
                            record["Source IP"],
                            record["Destination IP"],
                            record["Protocol"],
                            record["Source Port"],
                            record["Destination Port"],
                            record["Application"],
                            record["Size (Bytes)"]
                        )
                    )

                updated = True

    except Empty:
        pass

    update_dashboard()

    if updated:
        children = packet_table.get_children()

        if children:
            packet_table.see(children[-1])

    root.after(150, process_queue)


# =========================
# CSV EXPORT
# =========================

def export_csv():
    with capture_lock:
        records = list(captured_packets)

    if not records:
        messagebox.showinfo(
            "No Data",
            "Capture some packets before exporting."
        )
        return

    filename = filedialog.asksaveasfilename(
        title="Export Captured Packets",
        defaultextension=".csv",
        filetypes=[("CSV files", "*.csv")]
    )

    if not filename:
        return

    try:
        with open(
            filename,
            "w",
            newline="",
            encoding="utf-8"
        ) as file:
            writer = csv.DictWriter(
                file,
                fieldnames=records[0].keys()
            )

            writer.writeheader()
            writer.writerows(records)

        messagebox.showinfo(
            "Export Successful",
            f"Packet data saved successfully:\n{filename}"
        )

    except OSError as error:
        messagebox.showerror(
            "Export Error",
            str(error)
        )

# =========================
# PACKET DETAILS
# =========================

def view_packet_details():
    selected_items = packet_table.selection()

    if not selected_items:
        messagebox.showinfo(
            "Select Packet",
            "Please select a packet from the table first."
        )
        return

    selected_item = selected_items[0]
    values = packet_table.item(
        selected_item,
        "values"
    )

    if not values:
        return

    packet_id = int(values[0])

    with capture_lock:
        packet = packet_objects.get(packet_id)

        record = next(
            (
                item
                for item in captured_packets
                if item["No."] == packet_id
            ),
            None
        )

    if packet is None or record is None:
        messagebox.showerror(
            "Packet Not Found",
            "The original packet is not available."
        )
        return

    # Identify packet layers
    layers = []

    current_layer = packet

    while current_layer:
        layers.append(
            current_layer.__class__.__name__
        )

        current_layer = current_layer.payload

        if not current_layer:
            break

    # Identify TCP flags
    tcp_flags = "-"

    if TCP in packet:
        tcp_flags = str(packet[TCP].flags)

    # Collect DNS details
    dns_details = "No DNS layer detected"

    if DNS in packet:
        dns_layer = packet[DNS]

        dns_details = (
            f"DNS ID: {dns_layer.id}\n"
            f"Response: "
            f"{'Yes' if dns_layer.qr else 'No'}\n"
            f"Questions: {dns_layer.qdcount}\n"
            f"Answers: {dns_layer.ancount}"
        )

        if dns_layer.qd is not None:
            try:
                dns_name = dns_layer.qd.qname

                if isinstance(dns_name, bytes):
                    dns_name = dns_name.decode(
                        "utf-8",
                        errors="replace"
                    )

                dns_details += (
                    f"\nQuery Name: {dns_name}"
                )

            except (AttributeError, TypeError):
                pass

    # Build packet details text
    details = f"""
PACKET DETAILS
{'=' * 50}

Packet Number:       {record['No.']}
Timestamp:           {record['Time']}

NETWORK INFORMATION
{'=' * 50}

Source IP:           {record['Source IP']}
Destination IP:      {record['Destination IP']}
Protocol:            {record['Protocol']}

TRANSPORT INFORMATION
{'=' * 50}

Source Port:         {record['Source Port']}
Destination Port:    {record['Destination Port']}
TCP Flags:           {tcp_flags}

PACKET INFORMATION
{'=' * 50}

Packet Size:         {record['Size (Bytes)']} bytes
Application:         {record['Application']}
Packet Layers:       {' / '.join(layers)}

DNS INFORMATION
{'=' * 50}

{dns_details}
"""

    # Create details popup
    details_window = tk.Toplevel(root)

    details_window.title(
        f"Packet Details - #{packet_id}"
    )

    details_window.geometry("650x650")
    details_window.configure(bg=CARD_COLOR)

    tk.Label(
        details_window,
        text=f"Packet #{packet_id} Details",
        font=("Segoe UI", 17, "bold"),
        bg=CARD_COLOR,
        fg=PRIMARY_COLOR
    ).pack(anchor="w", padx=20, pady=(20, 10))

    details_text = tk.Text(
        details_window,
        font=("Consolas", 10),
        bg="#F8FAFC",
        fg=TEXT_COLOR,
        wrap="word",
        relief="flat",
        padx=15,
        pady=15
    )

    details_text.pack(
        fill="both",
        expand=True,
        padx=20,
        pady=(0, 20)
    )

    details_text.insert("1.0", details.strip())
    details_text.config(state="disabled")
# =========================
# PROTOCOL STATISTICS
# =========================

def open_statistics_window():
    """Show protocol distribution and top destination IPs."""
    stats_window = tk.Toplevel(root)
    stats_window.title("NetScope | Traffic Statistics")
    stats_window.geometry("1050x650")
    stats_window.minsize(850, 550)
    stats_window.configure(bg=BG_COLOR)

    tk.Label(
        stats_window,
        text="Network Traffic Statistics",
        font=("Segoe UI", 20, "bold"),
        bg=BG_COLOR,
        fg=TEXT_COLOR
    ).pack(anchor="w", padx=22, pady=(18, 3))

    tk.Label(
        stats_window,
        text="Visual summary of captured protocols and most common destination IPs.",
        font=("Segoe UI", 10),
        bg=BG_COLOR,
        fg=MUTED_COLOR
    ).pack(anchor="w", padx=22, pady=(0, 14))

    charts = tk.Frame(stats_window, bg=BG_COLOR)
    charts.pack(fill="both", expand=True, padx=18, pady=(0, 12))
    charts.grid_columnconfigure(0, weight=1)
    charts.grid_columnconfigure(1, weight=1)
    charts.grid_rowconfigure(0, weight=1)

    protocol_canvas = tk.Canvas(
        charts, bg=CARD_COLOR, highlightthickness=1,
        highlightbackground=BORDER_COLOR
    )
    protocol_canvas.grid(row=0, column=0, sticky="nsew", padx=(0, 8))

    destination_canvas = tk.Canvas(
        charts, bg=CARD_COLOR, highlightthickness=1,
        highlightbackground=BORDER_COLOR
    )
    destination_canvas.grid(row=0, column=1, sticky="nsew", padx=(8, 0))

    def draw_bar_chart(canvas, title, data, empty_message):
        canvas.delete("all")
        canvas.update_idletasks()
        width = max(canvas.winfo_width(), 380)
        height = max(canvas.winfo_height(), 360)
        canvas.create_text(
            20, 22, anchor="w", text=title,
            font=("Segoe UI", 13, "bold"), fill=TEXT_COLOR
        )

        if not data:
            canvas.create_text(
                width / 2, height / 2, text=empty_message,
                font=("Segoe UI", 11), fill=MUTED_COLOR,
                width=width - 50, justify="center"
            )
            return

        left = 28
        right = width - 24
        top = 62
        bottom = height - 45
        chart_height = max(bottom - top, 80)
        max_value = max(value for _, value in data) or 1
        row_height = chart_height / len(data)
        label_width = min(135, max(90, width * 0.30))
        bar_left = left + label_width
        bar_width = max(right - bar_left - 45, 50)

        for index, (label, value) in enumerate(data):
            y = top + index * row_height
            bar_height = min(24, row_height * 0.58)
            canvas.create_text(
                left, y + row_height / 2, anchor="w",
                text=str(label)[:22], font=("Segoe UI", 9),
                fill=TEXT_COLOR
            )
            canvas.create_rectangle(
                bar_left, y + (row_height - bar_height) / 2,
                bar_left + bar_width, y + (row_height + bar_height) / 2,
                fill="#E2E8F0", outline=""
            )
            actual_width = bar_width * value / max_value
            canvas.create_rectangle(
                bar_left, y + (row_height - bar_height) / 2,
                bar_left + actual_width, y + (row_height + bar_height) / 2,
                fill=PRIMARY_COLOR, outline=""
            )
            canvas.create_text(
                min(bar_left + actual_width + 7, right),
                y + row_height / 2, anchor="w",
                text=str(value), font=("Segoe UI", 9, "bold"),
                fill=TEXT_COLOR
            )

    def refresh_statistics():
        with capture_lock:
            records = list(captured_packets)

        protocols = Counter(item["Protocol"] for item in records)
        destinations = Counter(item["Destination IP"] for item in records)
        protocol_data = protocols.most_common()
        destination_data = [
            item for item in destinations.most_common(8)
            if item[0] not in ("Unknown", "-")
        ]

        draw_bar_chart(
            protocol_canvas, "Packets by Protocol", protocol_data,
            "No packets captured yet. Start capture to see statistics."
        )
        draw_bar_chart(
            destination_canvas, "Top Destination IPs", destination_data,
            "No destination IP data available yet."
        )
        total = len(records)
        summary_label.config(text=f"Total captured packets: {total}")

    bottom_bar = tk.Frame(stats_window, bg=BG_COLOR)
    bottom_bar.pack(fill="x", padx=22, pady=(0, 18))

    summary_label = tk.Label(
        bottom_bar, text="Total captured packets: 0",
        font=("Segoe UI", 10, "bold"), bg=BG_COLOR, fg=TEXT_COLOR
    )
    summary_label.pack(side="left")

    tk.Button(
        bottom_bar, text="Refresh Statistics", command=refresh_statistics,
        bg=PRIMARY_COLOR, fg="white", activebackground="#1D4ED8",
        activeforeground="white", font=("Segoe UI", 10, "bold"),
        relief="flat", padx=14, pady=8, cursor="hand2"
    ).pack(side="right")

    stats_window.update_idletasks()
    refresh_statistics()


# =========================
# SECURITY ALERTS
# =========================

def open_security_alerts():
    alert_window = tk.Toplevel(root)
    alert_window.title("NetScope | Security Alerts")
    alert_window.geometry("1050x560")
    alert_window.minsize(800, 400)
    alert_window.configure(bg=BG_COLOR)

    tk.Label(
        alert_window,
        text="Security Alerts & Traffic Anomalies",
        font=("Segoe UI", 18, "bold"),
        bg=BG_COLOR,
        fg=TEXT_COLOR
    ).pack(anchor="w", padx=20, pady=(18, 4))

    tk.Label(
        alert_window,
        text=("Heuristic alerts for repeated TCP SYN attempts, high packet rates, and possible TCP port scans. "
              "Port-scan alerts are raised after SYN attempts reach 12 distinct destination ports "
              "on one target within 30 seconds. Alerts are indicators, not proof of an attack."),
        font=("Segoe UI", 9),
        bg=BG_COLOR,
        fg=MUTED_COLOR,
        wraplength=980,
        justify="left"
    ).pack(anchor="w", padx=20, pady=(0, 12))

    table_frame = tk.Frame(alert_window, bg=CARD_COLOR)
    table_frame.pack(fill="both", expand=True, padx=20, pady=(0, 12))

    columns = ("Time", "Severity", "Rule", "Source", "Destination", "Details")
    table = ttk.Treeview(table_frame, columns=columns, show="headings")
    widths = {
        "Time": 80, "Severity": 85, "Rule": 190,
        "Source": 145, "Destination": 175, "Details": 420
    }
    for column in columns:
        table.heading(column, text=column)
        table.column(column, width=widths[column], minwidth=70, anchor="w")

    y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=table.yview)
    x_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=table.xview)
    table.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
    table.grid(row=0, column=0, sticky="nsew")
    y_scroll.grid(row=0, column=1, sticky="ns")
    x_scroll.grid(row=1, column=0, sticky="ew")
    table_frame.grid_rowconfigure(0, weight=1)
    table_frame.grid_columnconfigure(0, weight=1)

    footer = tk.Frame(alert_window, bg=BG_COLOR)
    footer.pack(fill="x", padx=20, pady=(0, 16))
    count_label = tk.Label(footer, text="0 alerts", bg=BG_COLOR, fg=MUTED_COLOR,
                           font=("Segoe UI", 9, "bold"))
    count_label.pack(side="left")

    def refresh_alert_table():
        if not alert_window.winfo_exists():
            return
        for row in table.get_children():
            table.delete(row)
        with capture_lock:
            alerts_snapshot = list(security_alerts)
        for alert in alerts_snapshot:
            table.insert("", "end", values=tuple(alert[key] for key in columns))
        count_label.config(text=f"{len(alerts_snapshot)} alert(s)")

    def schedule_alert_refresh():
        if alert_window.winfo_exists():
            refresh_alert_table()
            alert_window.after(1500, schedule_alert_refresh)

    tk.Button(
        footer, text="Refresh Now", command=refresh_alert_table,
        bg=PRIMARY_COLOR, fg="white", activebackground="#1D4ED8",
        activeforeground="white", font=("Segoe UI", 10, "bold"),
        relief="flat", padx=14, pady=8, cursor="hand2"
    ).pack(side="right")

    schedule_alert_refresh()


# =========================
# GENERATE HTML REPORT
# =========================

def generate_html_report():
    """Export captured packet summaries and heuristic alerts as a standalone HTML report."""
    with capture_lock:
        records = list(captured_packets)
        alerts = list(security_alerts)
        protocol_summary = Counter(record.get("Protocol", "Other") for record in records)
        destination_summary = Counter(
            record.get("Destination IP", "Unknown") for record in records
            if record.get("Destination IP", "Unknown") not in ("Unknown", "-")
        )

    if not records:
        messagebox.showinfo("No Captured Data", "Capture some packets before generating a report.")
        return

    filename = filedialog.asksaveasfilename(
        title="Save NetScope Report",
        defaultextension=".html",
        filetypes=[("HTML report", "*.html"), ("All files", "*.*")],
        initialfile="netscope_report.html"
    )
    if not filename:
        return

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_bytes = sum(int(record.get("Size (Bytes)", 0) or 0) for record in records)

    def esc(value):
        return html_escape.escape(str(value if value is not None else ""))

    protocol_rows = chr(10).join(
        f"<tr><td>{esc(protocol)}</td><td>{count}</td></tr>"
        for protocol, count in protocol_summary.most_common()
    ) or '<tr><td colspan="2">No protocol data</td></tr>'

    destination_rows = chr(10).join(
        f"<tr><td>{esc(address)}</td><td>{count}</td></tr>"
        for address, count in destination_summary.most_common(10)
    ) or '<tr><td colspan="2">No destination data</td></tr>'

    alert_rows = chr(10).join(
        "<tr>" + "".join(
            f"<td>{esc(alert.get(key, ''))}</td>"
            for key in ("Time", "Severity", "Rule", "Source", "Destination", "Details")
        ) + "</tr>"
        for alert in alerts
    ) or '<tr><td colspan="6">No heuristic alerts were recorded.</td></tr>'

    packet_rows = chr(10).join(
        "<tr>" + "".join(
            f"<td>{esc(record.get(key, ''))}</td>"
            for key in (
                "No.", "Time", "Source IP", "Destination IP", "Protocol",
                "Source Port", "Destination Port", "Application", "Size (Bytes)"
            )
        ) + "</tr>"
        for record in records
    )

    report = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>NetScope Network Analysis Report</title>
<style>
:root {{ color-scheme: light; }} body {{ margin:0; font-family:Segoe UI,Arial,sans-serif; background:#f4f7fb; color:#1e293b; }}
header {{ background:#1d4ed8; color:white; padding:28px 5%; }} header h1 {{ margin:0 0 8px; }} main {{ max-width:1400px; margin:24px auto; padding:0 20px 40px; }}
.cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px; margin:20px 0; }}
.card, section {{ background:white; border:1px solid #e2e8f0; border-radius:10px; padding:18px; margin-bottom:18px; }} .label {{ color:#64748b; font-size:13px; }} .value {{ font-size:26px; font-weight:700; margin-top:8px; }}
h2 {{ margin-top:0; font-size:19px; }} .table-wrap {{ overflow-x:auto; }} table {{ width:100%; border-collapse:collapse; font-size:13px; }} th,td {{ border-bottom:1px solid #e2e8f0; padding:9px 10px; text-align:left; vertical-align:top; overflow-wrap:anywhere; }} th {{ background:#eff6ff; }}
.note {{ color:#64748b; font-size:13px; line-height:1.5; }} @media print {{ body {{ background:white; }} header {{ background:white; color:#1e293b; border-bottom:2px solid #1d4ed8; }} main {{ max-width:none; }} section,.card {{ break-inside:avoid; }} }}
</style>
</head>
<body>
<header><h1>NetScope</h1><div>Network Packet Analysis Report</div><div>Generated: {esc(generated_at)}</div></header>
<main>
<div class="cards">
<div class="card"><div class="label">Total Packets</div><div class="value">{len(records)}</div></div>
<div class="card"><div class="label">Protocols Observed</div><div class="value">{len(protocol_summary)}</div></div>
<div class="card"><div class="label">Total Captured Bytes</div><div class="value">{total_bytes:,}</div></div>
<div class="card"><div class="label">Heuristic Alerts</div><div class="value">{len(alerts)}</div></div>
</div>
<section><h2>Protocol Summary</h2><div class="table-wrap"><table><thead><tr><th>Protocol</th><th>Packets</th></tr></thead><tbody>{protocol_rows}</tbody></table></div></section>
<section><h2>Top Destination IP Addresses</h2><div class="table-wrap"><table><thead><tr><th>Destination IP</th><th>Packets</th></tr></thead><tbody>{destination_rows}</tbody></table></div></section>
<section><h2>Security Alerts</h2><p class="note">These alerts are based on simple traffic heuristics. They are indicators to investigate, not proof of malicious activity.</p><div class="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Rule</th><th>Source</th><th>Destination</th><th>Details</th></tr></thead><tbody>{alert_rows}</tbody></table></div></section>
<section><h2>Captured Packets ({len(records)})</h2><div class="table-wrap"><table><thead><tr><th>No.</th><th>Time</th><th>Source IP</th><th>Destination IP</th><th>Protocol</th><th>Source Port</th><th>Destination Port</th><th>Application</th><th>Size (Bytes)</th></tr></thead><tbody>{packet_rows}</tbody></table></div></section>
<p class="note">Privacy note: this report contains captured network metadata. Review it before sharing. NetScope is an educational analyzer; results depend on the packets visible to the capture interface.</p>
</main></body></html>"""

    try:
        with open(filename, "w", encoding="utf-8", newline="") as report_file:
            report_file.write(report)
        messagebox.showinfo(
            "Report Generated",
            "Your NetScope report was saved successfully:" + chr(10) + filename
        )
    except OSError as error:
        messagebox.showerror("Report Error", str(error))




# =========================
# CLEAR PACKETS
# =========================

def clear_packets():
    if pcap_import_running:
        messagebox.showwarning(
            "Import In Progress",
            "Wait for the capture file analysis to finish before clearing data."
        )
        return

    if capture_running:
        messagebox.showwarning(
            "Capture Running",
            "Stop packet capture before clearing records."
        )
        return

    if not messagebox.askyesno(
        "Clear Packets",
        "Do you want to clear all captured packet records?"
    ):
        return

    global packet_number

    with capture_lock:
        captured_packets.clear()
        packet_objects.clear()
        protocol_counts.clear()
        security_alerts.clear()
        alert_signatures.clear()
        recent_syn_attempts.clear()
        recent_source_packets.clear()
        recent_port_scan_attempts.clear()
        detected_port_scans.clear()
        packet_number = 0

    for item in packet_table.get_children():
        packet_table.delete(item)

    update_dashboard()


# =========================
# WEBSITE AND URL ANALYZER
# =========================

class WebPageParser(HTMLParser):
    """Extract public page title, description, visible text, and links."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.in_title = False
        self.title_parts = []
        self.description = ""
        self.text_parts = []
        self.links = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "meta":
            name = (attrs.get("name") or attrs.get("property") or "").lower()
            if name in ("description", "og:description") and not self.description:
                self.description = attrs.get("content", "")
        if tag.lower() == "a" and attrs.get("href") and len(self.links) < 50:
            self.links.append((attrs.get("href", ""), ""))

    def handle_endtag(self, tag):
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data):
        cleaned = " ".join(data.split())
        if not cleaned:
            return
        if self.in_title:
            self.title_parts.append(cleaned)
        elif len(" ".join(self.text_parts)) < 15000:
            self.text_parts.append(cleaned)


def _safe_header_value(headers, name):
    try:
        return headers.get(name, "Not provided")
    except Exception:
        return "Not available"


def analyze_url_data(raw_url):
    """Fetch a public web page and return its metadata and basic security findings."""
    raw_url = raw_url.strip()
    if not raw_url:
        raise ValueError("Enter a website URL first.")

    if not urllib.parse.urlsplit(raw_url).scheme:
        raw_url = "https://" + raw_url

    parsed = urllib.parse.urlsplit(raw_url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Only http:// and https:// website URLs are supported.")
    if not parsed.hostname:
        raise ValueError("That URL does not contain a valid domain name.")
    if parsed.username or parsed.password:
        raise ValueError("For safety, URLs containing embedded usernames or passwords are not accepted.")

    normalized_url = urllib.parse.urlunsplit((
        parsed.scheme.lower(), parsed.netloc, parsed.path or "/", parsed.query, parsed.fragment
    ))
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    findings = []

    # DNS information
    try:
        resolved = sorted({item[4][0] for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)})
    except Exception as exc:
        resolved = []
        findings.append(f"DNS lookup failed: {exc}")

    # Basic URL pattern checks (heuristics, not a malware verdict)
    lower_url = normalized_url.lower()
    if parsed.scheme.lower() != "https":
        findings.append("The URL uses HTTP rather than HTTPS; traffic may not be encrypted.")
    if len(normalized_url) > 200:
        findings.append("The URL is unusually long; verify that it is expected.")
    if "@" in parsed.netloc:
        findings.append("The URL contains an @ character in its authority section; verify the actual hostname carefully.")
    suspicious_terms = ("login", "verify", "account", "password", "wallet", "urgent", "secure", "update")
    matched_terms = [term for term in suspicious_terms if term in lower_url]
    if matched_terms:
        findings.append("URL contains words sometimes used in phishing lures: " + ", ".join(matched_terms) + ". This alone does not mean it is malicious.")
    try:
        ipaddress.ip_address(host)
        findings.append("The website uses an IP address instead of a normal domain name; verify that this is expected.")
    except ValueError:
        if "xn--" in host.lower():
            findings.append("The domain contains Punycode. Check for look-alike Unicode characters.")

    request = urllib.request.Request(
        normalized_url,
        headers={
            "User-Agent": "NetScope-URL-Analyzer/1.0 (educational security analysis)",
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5"
        }
    )
    opener = urllib.request.build_opener()
    response = None
    http_error = None
    body = b""
    try:
        response = opener.open(request, timeout=12)
    except urllib.error.HTTPError as exc:
        http_error = exc
        response = exc
    except Exception as exc:
        raise RuntimeError(
            "Could not retrieve the page. Check the URL, internet connection, DNS, or website access.\n\n"
            + str(exc)
        ) from exc

    try:
        status_code = getattr(response, "status", None) or response.getcode()
        headers = response.headers
        final_url = response.geturl()
        content_type = _safe_header_value(headers, "Content-Type")
        content_length = _safe_header_value(headers, "Content-Length")
        server_header = _safe_header_value(headers, "Server")
        powered_by = _safe_header_value(headers, "X-Powered-By")
        security_headers = {
            "Strict-Transport-Security": _safe_header_value(headers, "Strict-Transport-Security"),
            "Content-Security-Policy": _safe_header_value(headers, "Content-Security-Policy"),
            "X-Content-Type-Options": _safe_header_value(headers, "X-Content-Type-Options"),
            "X-Frame-Options": _safe_header_value(headers, "X-Frame-Options"),
            "Referrer-Policy": _safe_header_value(headers, "Referrer-Policy")
        }
        body = response.read(1_000_000)
    finally:
        try:
            response.close()
        except Exception:
            pass

    if status_code >= 400:
        findings.append(f"The server returned HTTP status {status_code}.")
    if parsed.scheme.lower() == "https":
        missing = [name for name, value in security_headers.items() if value == "Not provided"]
        if missing:
            findings.append("Some common browser security headers were not present: " + ", ".join(missing) + ". Missing headers are not proof of a vulnerability.")

    # TLS certificate details. Certificate validation is performed by the default SSL context.
    certificate_summary = "Not checked (HTTP URL)."
    if parsed.scheme.lower() == "https":
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=8) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                    cert = tls_sock.getpeercert()
                    issuer = ", ".join(" ".join(part[0][1] for part in group) for group in cert.get("issuer", ())) or "Not available"
                    subject = ", ".join(" ".join(part[0][1] for part in group) for group in cert.get("subject", ())) or "Not available"
                    certificate_summary = (
                        f"TLS version: {tls_sock.version()}\n"
                        f"Cipher: {tls_sock.cipher()[0] if tls_sock.cipher() else 'Not available'}\n"
                        f"Certificate subject: {subject}\n"
                        f"Certificate issuer: {issuer}\n"
                        f"Valid from: {cert.get('notBefore', 'Not available')}\n"
                        f"Valid until: {cert.get('notAfter', 'Not available')}\n"
                        "Certificate validation: successful"
                    )
        except Exception as exc:
            certificate_summary = "TLS certificate check failed: " + str(exc)
            findings.append("TLS certificate details could not be verified by this analyzer.")

    page_title = "Not detected"
    description = "Not detected"
    page_text = "Page content was not parsed as HTML."
    extracted_links = []
    if "html" in str(content_type).lower() or body.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        charset = "utf-8"
        for part in str(content_type).split(";")[1:]:
            if "charset=" in part.lower():
                charset = part.split("=", 1)[1].strip().strip('"\'')
        try:
            html_text = body.decode(charset, errors="replace")
        except LookupError:
            html_text = body.decode("utf-8", errors="replace")
        parser = WebPageParser()
        try:
            parser.feed(html_text)
            page_title = " ".join(parser.title_parts) or "Not detected"
            description = parser.description or "Not detected"
            page_text = " ".join(parser.text_parts)[:15000] or "No visible text extracted."
            extracted_links = [urllib.parse.urljoin(final_url, href) for href, _ in parser.links]
        except Exception as exc:
            page_text = "HTML parsing failed: " + str(exc)

    if not findings:
        findings.append("No obvious issues were identified by these basic checks. This is not a guarantee that the URL is safe.")

    # Transparent heuristic score (not a guarantee that a website is safe).
    score_breakdown = []
    security_score = 0
    if parsed.scheme.lower() == "https":
        security_score += 20
        score_breakdown.append("HTTPS enabled: +20/20")
    else:
        score_breakdown.append("HTTPS enabled: +0/20 (HTTP is not encrypted)")

    if parsed.scheme.lower() == "https" and "Certificate validation: successful" in certificate_summary:
        security_score += 20
        score_breakdown.append("TLS certificate validation: +20/20")
    else:
        score_breakdown.append("TLS certificate validation: +0/20")

    if 200 <= int(status_code) < 400:
        security_score += 10
        score_breakdown.append("HTTP response status: +10/10")
    else:
        score_breakdown.append("HTTP response status: +0/10")

    headers_present = sum(1 for value in security_headers.values()
                          if value not in ("Not provided", "Not available", "", None))
    header_points = min(25, headers_present * 5)
    security_score += header_points
    score_breakdown.append(f"Common security headers: +{header_points}/25 ({headers_present}/5 found)")

    dns_ok = bool(resolved)
    if dns_ok:
        security_score += 5
        score_breakdown.append("DNS resolution: +5/5")
    else:
        score_breakdown.append("DNS resolution: +0/5")

    url_risk_phrases = (
        "URL is unusually long", "contains an @ character",
        "URL contains words sometimes used in phishing lures",
        "uses an IP address instead of a normal domain name", "contains Punycode"
    )
    url_risk_count = sum(1 for finding in findings if any(phrase in finding for phrase in url_risk_phrases))
    url_points = max(0, 10 - min(10, url_risk_count * 2))
    security_score += url_points
    score_breakdown.append(f"URL structure checks: +{url_points}/10 ({url_risk_count} indicator(s) flagged)")

    if str(final_url).lower().startswith("https://"):
        security_score += 10
        score_breakdown.append("Final destination uses HTTPS: +10/10")
    else:
        score_breakdown.append("Final destination uses HTTPS: +0/10")

    security_score = max(0, min(100, int(security_score)))
    if security_score >= 90:
        security_rating = "Strong security signals"
    elif security_score >= 75:
        security_rating = "Good security signals"
    elif security_score >= 50:
        security_rating = "Moderate security signals"
    elif security_score >= 25:
        security_rating = "Weak security signals"
    else:
        security_rating = "Very weak security signals"

    return {
        "security_score": security_score,
        "security_rating": security_rating,
        "score_breakdown": score_breakdown,
        "input_url": normalized_url,
        "final_url": final_url,
        "scheme": parsed.scheme.lower(),
        "domain": host,
        "path": parsed.path or "/",
        "query": parsed.query or "None",
        "resolved_ips": resolved or ["No IP addresses resolved"],
        "status_code": status_code,
        "content_type": content_type,
        "content_length": content_length,
        "server": server_header,
        "powered_by": powered_by,
        "security_headers": security_headers,
        "certificate": certificate_summary,
        "title": page_title,
        "description": description,
        "page_text": page_text,
        "links": extracted_links,
        "findings": findings,
        "http_error": str(http_error) if http_error else "None"
    }


def format_url_report(data):
    lines = [
        "NETSCOPE — WEBSITE & URL SECURITY ANALYSIS",
        "=" * 68,
        "",
        "URL INFORMATION",
        "-" * 68,
        f"Submitted URL:      {data['input_url']}",
        f"Final URL:          {data['final_url']}",
        f"Domain:             {data['domain']}",
        f"Scheme:             {data['scheme'].upper()}",
        f"Path:               {data['path']}",
        f"Query parameters:   {data['query']}",
        f"Resolved IPs:       {', '.join(data['resolved_ips'])}",
        "",
        "ESTIMATED WEBSITE SECURITY SCORE",
        "-" * 68,
        f"Score:              {data['security_score']}% / 100%",
        f"Assessment:         {data['security_rating']}",
        "Scoring breakdown:",
        *["  - " + item for item in data['score_breakdown']],
        "",
        "IMPORTANT: This is a heuristic score based on limited public checks, not a guarantee of safety.",
        "It does not prove the site is malware-free and may produce false positives or miss threats.",
        "",
        "HTTP RESPONSE",
        "-" * 68,
        f"Status code:        {data['status_code']}",
        f"Content type:       {data['content_type']}",
        f"Content length:     {data['content_length']}",
        f"Server:             {data['server']}",
        f"X-Powered-By:       {data['powered_by']}",
        f"Redirect/final URL: {data['final_url']}",
        "",
        "TLS CERTIFICATE",
        "-" * 68,
        data['certificate'],
        "",
        "COMMON SECURITY HEADERS",
        "-" * 68,
    ]
    for name, value in data["security_headers"].items():
        lines.append(f"{name}: {value}")
    lines.extend(["", "PAGE METADATA", "-" * 68,
                  f"Title: {data['title']}",
                  f"Description: {data['description']}",
                  "", "BASIC SECURITY CHECKS", "-" * 68])
    for finding in data["findings"]:
        lines.append("• " + finding)
    lines.extend(["", "EXTRACTED PAGE TEXT (limited preview)", "-" * 68,
                  data["page_text"], "", "EXTRACTED LINKS (up to 50)", "-" * 68])
    if data["links"]:
        lines.extend(data["links"])
    else:
        lines.append("No links extracted.")
    lines.extend(["", "LIMITATIONS", "-" * 68,
                  "This report covers publicly accessible response data only. It does not retrieve private/login-protected data,", 
                  "decrypted browser sessions, or the full media stream of a YouTube video. Heuristic findings are not a malware verdict."])
    return "\n".join(lines)


def open_url_analyzer():
    analyzer_window = tk.Toplevel(root)
    analyzer_window.title("NetScope | Website & URL Analyzer")
    analyzer_window.geometry("1050x760")
    analyzer_window.minsize(800, 600)
    analyzer_window.configure(bg=BG_COLOR)

    tk.Label(
        analyzer_window,
        text="Website & URL Analyzer",
        font=("Segoe UI", 20, "bold"),
        bg=BG_COLOR,
        fg=PRIMARY_COLOR
    ).pack(anchor="w", padx=22, pady=(18, 4))
    tk.Label(
        analyzer_window,
        text="Analyze public webpage metadata, response headers, DNS, TLS, links, and basic URL risk indicators.",
        font=("Segoe UI", 10),
        bg=BG_COLOR,
        fg=MUTED_COLOR
    ).pack(anchor="w", padx=22, pady=(0, 14))

    url_row = tk.Frame(analyzer_window, bg=BG_COLOR)
    url_row.pack(fill="x", padx=22, pady=(0, 12))
    url_var = tk.StringVar()
    url_entry = ttk.Entry(url_row, textvariable=url_var, font=("Segoe UI", 11))
    url_entry.pack(side="left", fill="x", expand=True, ipady=7)
    url_entry.insert(0, "https://www.youtube.com")

    score_panel = tk.Frame(analyzer_window, bg=CARD_COLOR, highlightbackground=BORDER_COLOR, highlightthickness=1)
    score_panel.pack(fill="x", padx=22, pady=(0, 12))
    score_label = tk.Label(
        score_panel, text="Estimated Website Security Score: Not analyzed yet",
        font=("Segoe UI", 14, "bold"), bg=CARD_COLOR, fg=PRIMARY_COLOR
    )
    score_label.pack(anchor="w", padx=14, pady=(10, 2))
    score_note = tk.Label(
        score_panel, text="Check any website’s security level and discover potential risks before you browse..",
        font=("Segoe UI", 9), bg=CARD_COLOR, fg=MUTED_COLOR
    )
    score_note.pack(anchor="w", padx=14, pady=(0, 10))

    result_frame = tk.Frame(analyzer_window, bg=CARD_COLOR, highlightbackground=BORDER_COLOR, highlightthickness=1)
    result_frame.pack(fill="both", expand=True, padx=22, pady=(0, 20))
    result_text = tk.Text(result_frame, wrap="word", font=("Consolas", 9), bg=CARD_COLOR, fg=TEXT_COLOR, padx=14, pady=14)
    result_scroll = ttk.Scrollbar(result_frame, orient="vertical", command=result_text.yview)
    result_text.configure(yscrollcommand=result_scroll.set)
    result_scroll.pack(side="right", fill="y")
    result_text.pack(side="left", fill="both", expand=True)
    result_text.insert("1.0", "Paste a website URL above and click Analyze URL.\n\nExample: https://www.youtube.com/watch?v=...\n\nOnly publicly accessible page information can be retrieved.")
    result_text.config(state="disabled")

    def show_report(report):
        result_text.config(state="normal")
        result_text.delete("1.0", "end")
        result_text.insert("1.0", report)
        result_text.config(state="disabled")
        result_text.see("1.0")

    def start_analysis():
        value = url_var.get().strip()
        if not value:
            messagebox.showwarning("URL Required", "Enter a website URL first.", parent=analyzer_window)
            return
        analyze_button.config(state="disabled", text="Analyzing...")
        show_report("Analyzing URL...\n\nResolving domain and retrieving publicly accessible page data. Please wait.")

        def worker():
            try:
                result = analyze_url_data(value)
                report = format_url_report(result)
                score = result["security_score"]
                rating = result["security_rating"]
                root.after(0, lambda report=report, score=score, rating=rating: finish(report, None, score, rating))
            except Exception as exc:
                root.after(0, lambda error=str(exc): finish(None, error))

        def finish(report, error, score=None, rating=None):
            if not analyzer_window.winfo_exists():
                return
            analyze_button.config(state="normal", text="Analyze URL")
            if error:
                score_label.config(text="Estimated Website Security Score: Not available", fg="#DC2626")
                show_report("URL ANALYSIS COULD NOT COMPLETE\n" + "=" * 60 + "\n\n" + error)
            else:
                if score is not None:
                    score_color = "#16A34A" if score >= 75 else ("#D97706" if score >= 50 else "#DC2626")
                    score_label.config(text=f"Estimated Website Security Score: {score}% — {rating}", fg=score_color)
                show_report(report)

        Thread(target=worker, daemon=True).start()

    analyze_button = tk.Button(
        url_row,
        text="Analyze URL",
        command=start_analysis,
        bg=PRIMARY_COLOR,
        fg="white",
        activebackground="#1D4ED8",
        activeforeground="white",
        font=("Segoe UI", 10, "bold"),
        relief="flat",
        padx=18,
        pady=9,
        cursor="hand2"
    )
    analyze_button.pack(side="left", padx=(10, 0))
    url_entry.bind("<Return>", lambda event: start_analysis())
    url_entry.focus_set()




# =========================
# IP REPUTATION CHECKER (PHASE 12)
# =========================

def open_ip_reputation_checker():
    """Check a public IP against AbuseIPDB using a user-supplied API key."""
    checker = tk.Toplevel(root)
    checker.title("NetScope | IP Reputation Checker")
    checker.geometry("760x620")
    checker.minsize(650, 520)
    checker.configure(bg=BG_COLOR)

    tk.Label(
        checker, text="IP Reputation Checker",
        font=("Segoe UI", 20, "bold"), bg=BG_COLOR, fg=TEXT_COLOR
    ).pack(anchor="w", padx=22, pady=(20, 4))
    tk.Label(
        checker,
        text="Check a public IP address against AbuseIPDB threat-intelligence data.",
        font=("Segoe UI", 10), bg=BG_COLOR, fg=MUTED_COLOR
    ).pack(anchor="w", padx=22, pady=(0, 16))

    form = tk.Frame(checker, bg=CARD_COLOR, highlightbackground=BORDER_COLOR, highlightthickness=1)
    form.pack(fill="x", padx=22, pady=(0, 14))
    form.columnconfigure(1, weight=1)

    tk.Label(form, text="Public IP address", font=("Segoe UI", 10, "bold"),
             bg=CARD_COLOR, fg=TEXT_COLOR).grid(row=0, column=0, sticky="w", padx=14, pady=(14, 6))
    ip_entry = tk.Entry(form, font=("Segoe UI", 11), relief="solid", bd=1)
    ip_entry.grid(row=0, column=1, sticky="ew", padx=(0, 14), pady=(14, 6), ipady=5)

    tk.Label(form, text="AbuseIPDB API key", font=("Segoe UI", 10, "bold"),
             bg=CARD_COLOR, fg=TEXT_COLOR).grid(row=1, column=0, sticky="w", padx=14, pady=6)
    key_entry = tk.Entry(form, font=("Segoe UI", 11), relief="solid", bd=1, show="*")
    key_entry.grid(row=1, column=1, sticky="ew", padx=(0, 14), pady=6, ipady=5)

    tk.Label(
        form,
        text="Your API key is used for this request only and is not saved by NetScope.",
        font=("Segoe UI", 9), bg=CARD_COLOR, fg=MUTED_COLOR, wraplength=620, justify="left"
    ).grid(row=2, column=0, columnspan=2, sticky="w", padx=14, pady=(2, 14))

    result_box = tk.Text(checker, height=15, wrap="word", font=("Consolas", 10),
                         bg="#FFFFFF", fg=TEXT_COLOR, relief="solid", bd=1, padx=12, pady=10)
    result_box.pack(fill="both", expand=True, padx=22, pady=(0, 12))
    result_box.insert("1.0", "Enter a public IP address and an AbuseIPDB API key, then click Check IP.\n\n"
                      "Private, loopback, link-local, and reserved IP addresses are not submitted.\n"
                      "Reputation data is an indicator and should be corroborated before taking action.")
    result_box.config(state="disabled")

    status = tk.Label(checker, text="Ready", font=("Segoe UI", 9), bg=BG_COLOR, fg=MUTED_COLOR)
    status.pack(anchor="w", padx=22, pady=(0, 8))

    def show_result(text):
        if not checker.winfo_exists():
            return
        result_box.config(state="normal")
        result_box.delete("1.0", "end")
        result_box.insert("1.0", text)
        result_box.config(state="disabled")

    def check_ip():
        raw_ip = ip_entry.get().strip()
        api_key = key_entry.get().strip()
        if not raw_ip or not api_key:
            messagebox.showwarning("Missing information", "Enter both an IP address and your AbuseIPDB API key.", parent=checker)
            return
        try:
            parsed_ip = ipaddress.ip_address(raw_ip)
        except ValueError:
            messagebox.showerror("Invalid IP", "Enter a valid IPv4 or IPv6 address.", parent=checker)
            return
        if not parsed_ip.is_global:
            messagebox.showwarning(
                "Public IP required",
                "This checker submits only globally routable public IP addresses. Private, loopback, link-local, and reserved addresses are not checked.",
                parent=checker
            )
            return

        check_button.config(state="disabled")
        status.config(text=f"Checking {parsed_ip} against AbuseIPDB…", fg=PRIMARY_COLOR)
        show_result("Checking reputation…\nPlease wait.")

        def worker():
            try:
                query = urllib.parse.urlencode({"ipAddress": str(parsed_ip), "maxAgeInDays": "90", "verbose": ""})
                request = urllib.request.Request(
                    "https://api.abuseipdb.com/api/v2/check?" + query,
                    headers={"Key": api_key, "Accept": "application/json", "User-Agent": "NetScope-Network-Analyzer"},
                    method="GET"
                )
                with urllib.request.urlopen(request, timeout=15) as response:
                    payload = json.loads(response.read().decode("utf-8", errors="replace"))
                data = payload.get("data", {})
                confidence = data.get("abuseConfidenceScore", "Unknown")
                total_reports = data.get("totalReports", 0)
                country = data.get("countryCode") or "Unknown"
                isp = data.get("isp") or "Unknown"
                domain = data.get("domain") or "Unknown"
                usage = data.get("usageType") or "Unknown"
                last_report = data.get("lastReportedAt") or "No report date available"
                is_public = data.get("isPublic", "Unknown")
                verdict = "Higher reported abuse confidence — investigate further" if isinstance(confidence, (int, float)) and confidence >= 50 else "Lower reported abuse confidence — not a guarantee of safety"
                report = (
                    "ABUSEIPDB IP REPUTATION RESULT\n"
                    "=" * 42 + "\n"
                    f"IP address:             {parsed_ip}\n"
                    f"Abuse confidence score:  {confidence}%\n"
                    f"Total reports:           {total_reports}\n"
                    f"Country:                 {country}\n"
                    f"ISP:                     {isp}\n"
                    f"Domain:                  {domain}\n"
                    f"Usage type:              {usage}\n"
                    f"Last reported:           {last_report}\n"
                    f"Public IP:               {is_public}\n\n"
                    f"Interpretation: {verdict}.\n\n"
                    "Important: A reputation score is a threat-intelligence signal, not proof that the IP is attacking you. Shared, dynamic, VPN, proxy, or cloud IPs can have mixed history. Confirm with packet evidence and your network context.\n\n"
                    "Data source: AbuseIPDB API (maximum report age: 90 days)."
                )
                checker.after(0, lambda: show_result(report))
                checker.after(0, lambda: status.config(text="Check completed", fg="#15803D") if checker.winfo_exists() else None)
            except urllib.error.HTTPError as exc:
                try:
                    details = exc.read().decode("utf-8", errors="replace")
                except Exception:
                    details = str(exc)
                err = f"AbuseIPDB returned HTTP {exc.code}.\n\n{details}\n\nCheck that your API key is valid and that your account's API limits have not been exceeded."
                checker.after(0, lambda: show_result(err))
                checker.after(0, lambda: status.config(text="Request failed", fg="#B91C1C") if checker.winfo_exists() else None)
            except Exception as exc:
                err = f"Unable to complete the reputation check.\n\n{exc}\n\nCheck your internet connection and try again."
                checker.after(0, lambda: show_result(err))
                checker.after(0, lambda: status.config(text="Request failed", fg="#B91C1C") if checker.winfo_exists() else None)
            finally:
                checker.after(0, lambda: check_button.config(state="normal") if checker.winfo_exists() else None)

        Thread(target=worker, daemon=True).start()

    controls = tk.Frame(checker, bg=BG_COLOR)
    controls.pack(fill="x", padx=22, pady=(0, 18))
    check_button = tk.Button(
        controls, text="Check IP Reputation", command=check_ip,
        bg=PRIMARY_COLOR, fg="white", activebackground="#1D4ED8", activeforeground="white",
        font=("Segoe UI", 10, "bold"), relief="flat", padx=16, pady=9, cursor="hand2"
    )
    check_button.pack(side="left")
    tk.Button(
        controls, text="Clear Results",
        command=lambda: show_result("Results cleared. Enter an IP address and API key to run another check."),
        bg=CARD_COLOR, fg=TEXT_COLOR, font=("Segoe UI", 10), relief="flat", padx=14, pady=9,
        cursor="hand2", highlightbackground=BORDER_COLOR
    ).pack(side="left", padx=(8, 0))

    ip_entry.focus_set()


# =========================
# LIVE TRAFFIC MONITOR (PHASE 11)
# =========================

def open_live_monitor():
    """Show a rolling 30-second packet-rate graph and recent traffic metrics."""
    monitor = tk.Toplevel(root)
    monitor.title("NetScope | Live Traffic Monitor")
    monitor.geometry("940x560")
    monitor.minsize(720, 460)
    monitor.configure(bg=BG_COLOR)

    tk.Label(
        monitor,
        text="Live Traffic Monitoring",
        font=("Segoe UI", 19, "bold"),
        bg=BG_COLOR,
        fg=TEXT_COLOR
    ).pack(anchor="w", padx=22, pady=(18, 2))

    tk.Label(
        monitor,
        text="Rolling packet rate over the last 30 seconds. Only traffic visible to NetScope is measured.",
        font=("Segoe UI", 10),
        bg=BG_COLOR,
        fg=MUTED_COLOR
    ).pack(anchor="w", padx=22, pady=(0, 14))

    metric_frame = tk.Frame(monitor, bg=BG_COLOR)
    metric_frame.pack(fill="x", padx=22, pady=(0, 14))

    pps_value = tk.Label(
        metric_frame, text="0 packets/s", font=("Segoe UI", 17, "bold"),
        bg=CARD_COLOR, fg=PRIMARY_COLOR, padx=18, pady=14,
        highlightbackground=BORDER_COLOR, highlightthickness=1
    )
    pps_value.pack(side="left", fill="x", expand=True, padx=(0, 8))

    bandwidth_value = tk.Label(
        metric_frame, text="0.00 KB/s", font=("Segoe UI", 17, "bold"),
        bg=CARD_COLOR, fg="#0F766E", padx=18, pady=14,
        highlightbackground=BORDER_COLOR, highlightthickness=1
    )
    bandwidth_value.pack(side="left", fill="x", expand=True, padx=(8, 0))

    graph_frame = tk.Frame(
        monitor, bg=CARD_COLOR,
        highlightbackground=BORDER_COLOR, highlightthickness=1
    )
    graph_frame.pack(fill="both", expand=True, padx=22, pady=(0, 14))

    graph = tk.Canvas(graph_frame, bg=CARD_COLOR, highlightthickness=0, height=300)
    graph.pack(fill="both", expand=True, padx=8, pady=8)

    footer = tk.Label(
        monitor,
        text="Tip: Start Capture to monitor live traffic. Importing a PCAP also adds processing events and can cause a temporary spike.",
        font=("Segoe UI", 9), bg=BG_COLOR, fg=MUTED_COLOR,
        wraplength=880, justify="left"
    )
    footer.pack(anchor="w", padx=22, pady=(0, 14))

    def refresh_graph():
        if not monitor.winfo_exists():
            return

        now = time.time()
        with capture_lock:
            events = list(traffic_events)

        recent = [(stamp, size, proto) for stamp, size, proto in events if now - stamp <= 30]
        last_second = [(stamp, size, proto) for stamp, size, proto in recent if now - stamp <= 1]
        pps_value.config(text=f"{len(last_second)} packets/s")
        bytes_per_second = sum(item[1] for item in last_second)
        bandwidth_value.config(text=f"{bytes_per_second / 1024:.2f} KB/s")

        per_second = [0] * 30
        current_second = int(now)
        for stamp, _size, _proto in recent:
            age = current_second - int(stamp)
            if 0 <= age < 30:
                per_second[29 - age] += 1

        graph.delete("all")
        width = max(graph.winfo_width(), 300)
        height = max(graph.winfo_height(), 180)
        left, right, top, bottom = 48, width - 18, 22, height - 38
        plot_width = max(right - left, 1)
        plot_height = max(bottom - top, 1)
        max_count = max(max(per_second, default=0), 1)

        # Horizontal guide lines and axis labels.
        for step in range(5):
            y = bottom - (plot_height * step / 4)
            value = int(max_count * step / 4)
            graph.create_line(left, y, right, y, fill="#E2E8F0")
            graph.create_text(left - 8, y, text=str(value), anchor="e",
                              fill=MUTED_COLOR, font=("Segoe UI", 8))

        graph.create_line(left, top, left, bottom, fill="#94A3B8")
        graph.create_line(left, bottom, right, bottom, fill="#94A3B8")
        slot = plot_width / 30
        for index, count in enumerate(per_second):
            bar_height = (count / max_count) * (plot_height - 3)
            x1 = left + index * slot + slot * 0.16
            x2 = left + (index + 1) * slot - slot * 0.16
            y1 = bottom - bar_height
            graph.create_rectangle(x1, y1, max(x2, x1 + 1), bottom,
                                   fill=PRIMARY_COLOR, outline="")

        graph.create_text(left, height - 16, text="30 seconds ago", anchor="w",
                          fill=MUTED_COLOR, font=("Segoe UI", 8))
        graph.create_text(right, height - 16, text="Now", anchor="e",
                          fill=MUTED_COLOR, font=("Segoe UI", 8))
        graph.create_text((left + right) / 2, 8, text="Packets per second",
                          fill=TEXT_COLOR, font=("Segoe UI", 9, "bold"))
        monitor.after(1000, refresh_graph)

    monitor.after(150, refresh_graph)


# =========================
# MAIN WINDOW
# =========================

root = tk.Tk()

root.title(APP_TITLE)
root.geometry("1500x850")
root.minsize(1100, 650)
root.configure(bg=BG_COLOR)


# =========================
# HEADER
# =========================

header = tk.Frame(
    root,
    bg=CARD_COLOR,
    height=75
)

header.pack(fill="x")
header.pack_propagate(False)

brand = tk.Frame(header, bg=CARD_COLOR)
brand.pack(side="left", padx=25)

tk.Label(
    brand,
    text="NetScope",
    font=("Segoe UI", 22, "bold"),
    bg=CARD_COLOR,
    fg=PRIMARY_COLOR
).pack(side="left")

tk.Label(
    brand,
    text="  NETWORK PACKET ANALYZER",
    font=("Segoe UI", 10),
    bg=CARD_COLOR,
    fg=MUTED_COLOR
).pack(side="left", padx=8)

status_label = tk.Label(
    header,
    text="● Ready to capture",
    font=("Segoe UI", 10, "bold"),
    bg=CARD_COLOR,
    fg=MUTED_COLOR
)

status_label.pack(side="right", padx=25)

url_analyzer_button = tk.Button(
    header,
    text="Website & Security Analyzer",
    command=open_url_analyzer,
    bg=PRIMARY_COLOR,
    fg="white",
    activebackground="#1D4ED8",
    activeforeground="white",
    font=("Segoe UI", 9, "bold"),
    relief="flat",
    padx=12,
    pady=8,
    cursor="hand2"
)
url_analyzer_button.pack(side="right", padx=(8, 12))


# =========================
# MAIN CONTENT
# =========================

content = tk.Frame(root, bg=BG_COLOR)
content.pack(fill="both", expand=True, padx=25, pady=20)

tk.Label(
    content,
    text="Network Overview",
    font=("Segoe UI", 20, "bold"),
    bg=BG_COLOR,
    fg=TEXT_COLOR
).pack(anchor="w")

tk.Label(
    content,
    text="Monitor and analyze live network traffic.",
    font=("Segoe UI", 10),
    bg=BG_COLOR,
    fg=MUTED_COLOR
).pack(anchor="w", pady=(4, 18))


# =========================
# STATISTIC CARDS
# =========================

stats_frame = tk.Frame(content, bg=BG_COLOR)
stats_frame.pack(fill="x", pady=(0, 20))


def create_stat_card(parent, title, value, column):
    card = tk.Frame(
        parent,
        bg=CARD_COLOR,
        highlightbackground=BORDER_COLOR,
        highlightthickness=1
    )

    card.grid(
        row=0,
        column=column,
        sticky="nsew",
        padx=(0 if column == 0 else 10, 0)
    )

    tk.Label(
        card,
        text=title,
        font=("Segoe UI", 10),
        bg=CARD_COLOR,
        fg=MUTED_COLOR
    ).pack(anchor="w", padx=18, pady=(15, 5))

    number = tk.Label(
        card,
        text=value,
        font=("Segoe UI", 24, "bold"),
        bg=CARD_COLOR,
        fg=TEXT_COLOR
    )

    number.pack(anchor="w", padx=18, pady=(0, 15))

    return number


for column in range(4):
    stats_frame.grid_columnconfigure(column, weight=1)

total_value = create_stat_card(
    stats_frame, "Total Packets", "0", 0
)

tcp_value = create_stat_card(
    stats_frame, "TCP Packets", "0", 1
)

udp_value = create_stat_card(
    stats_frame, "UDP Packets", "0", 2
)

other_value = create_stat_card(
    stats_frame, "Other Protocols", "0", 3
)


# =========================
# TOOLBAR
# =========================

toolbar = tk.Frame(content, bg=BG_COLOR)
toolbar.pack(fill="x", pady=(0, 12))

start_button = tk.Button(
    toolbar,
    text="▶  Start Capture",
    command=start_capture,
    bg=PRIMARY_COLOR,
    fg="white",
    activebackground="#1D4ED8",
    activeforeground="white",
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    padx=15,
    pady=9,
    cursor="hand2"
)

start_button.pack(side="left", padx=(0, 8))

stop_button = tk.Button(
    toolbar,
    text="■  Stop Capture",
    command=stop_capture,
    bg="#DC2626",
    fg="white",
    activebackground="#B91C1C",
    activeforeground="white",
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    padx=15,
    pady=9,
    cursor="hand2",
    state="disabled"
)

stop_button.pack(side="left", padx=(0, 8))

import_pcap_button = tk.Button(
    toolbar,
    text="Import PCAP",
    command=import_pcap_file,
    bg="#EDE9FE",
    fg="#5B21B6",
    activebackground="#DDD6FE",
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    padx=13,
    pady=9,
    cursor="hand2"
)

import_pcap_button.pack(side="left", padx=(0, 8))

live_monitor_button = tk.Button(
    toolbar,
    text="Live Traffic Monitor",
    command=open_live_monitor,
    bg="#E0F2FE",
    fg="#075985",
    activebackground="#BAE6FD",
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    padx=13,
    pady=9,
    cursor="hand2"
)
live_monitor_button.pack(side="left", padx=(0, 8))

ip_reputation_button = tk.Button(
    toolbar,
    text="IP Reputation Checker",
    command=open_ip_reputation_checker,
    bg="#F3E8FF",
    fg="#6B21A8",
    activebackground="#E9D5FF",
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    padx=13,
    pady=9,
    cursor="hand2"
)
ip_reputation_button.pack(side="left", padx=(0, 8))

export_button = tk.Button(
    toolbar,
    text="Export CSV",
    command=export_csv,
    bg=CARD_COLOR,
    fg=TEXT_COLOR,
    font=("Segoe UI", 10),
    relief="flat",
    padx=15,
    pady=9,
    cursor="hand2",
    highlightbackground=BORDER_COLOR
)

export_button.pack(side="right", padx=(8, 0))

generate_report_button = tk.Button(
    toolbar,
    text="Generate Report",
    command=generate_html_report,
    bg="#ECFDF5",
    fg="#166534",
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    padx=12,
    pady=9,
    cursor="hand2",
    highlightbackground=BORDER_COLOR
)

generate_report_button.pack(side="right", padx=(8, 0))

clear_button = tk.Button(
    toolbar,
    text="Clear Data",
    command=clear_packets,
    bg=CARD_COLOR,
    fg=TEXT_COLOR,
    font=("Segoe UI", 10),
    relief="flat",
    padx=15,
    pady=9,
    cursor="hand2",
    highlightbackground=BORDER_COLOR
)

clear_button.pack(side="right", padx=(8, 0))

statistics_button = tk.Button(
    toolbar,
    text="Traffic Statistics",
    command=open_statistics_window,
    bg=CARD_COLOR,
    fg=TEXT_COLOR,
    font=("Segoe UI", 10),
    relief="flat",
    padx=15,
    pady=9,
    cursor="hand2",
    highlightbackground=BORDER_COLOR
)

statistics_button.pack(side="right", padx=(8, 0))

security_alerts_button = tk.Button(
    toolbar,
    text="Security Alerts",
    command=open_security_alerts,
    bg="#FFF7ED",
    fg="#9A3412",
    font=("Segoe UI", 10, "bold"),
    relief="flat",
    padx=15,
    pady=9,
    cursor="hand2",
    highlightbackground=BORDER_COLOR
)

security_alerts_button.pack(side="right", padx=(8, 0))

view_details_button = tk.Button(
    toolbar,
    text="View Details",
    command=view_packet_details,
    bg=CARD_COLOR,
    fg=TEXT_COLOR,
    font=("Segoe UI", 10),
    relief="flat",
    padx=20,
    pady=12,
    width=18,
    cursor="hand2",
    highlightbackground=BORDER_COLOR
)

view_details_button.pack(side="right", padx=(8, 0))

filter_var = tk.StringVar(value="All Protocols")

protocol_filter = ttk.Combobox(
    toolbar,
    textvariable=filter_var,
    values=[
        "All Protocols",
        "TCP",
        "UDP",
        "ICMP",
        "ICMPv6",
        "ARP",
        "IPv4",
        "IPv6",
        "Other"
    ],
    state="readonly",
    width=17
)

protocol_filter.pack(side="left", padx=(8, 0))
protocol_filter.bind("<<ComboboxSelected>>", apply_filter)

# Packet Search

search_var = tk.StringVar()

search_entry = ttk.Entry(
    toolbar,
    textvariable=search_var,
    width=25
)

search_entry.pack(side="left", padx=(10, 5))

search_button = tk.Button(
    toolbar,
    text="Search",
    command=apply_filter,
    bg=CARD_COLOR,
    fg=TEXT_COLOR,
    font=("Segoe UI", 10),
    relief="flat",
    padx=12,
    pady=9,
    cursor="hand2"
)

search_button.pack(side="left")

search_entry.bind(
    "<Return>",
    lambda event: apply_filter()
)

# =========================
# PACKET TABLE
# =========================

table_card = tk.Frame(
    content,
    bg=CARD_COLOR,
    highlightbackground=BORDER_COLOR,
    highlightthickness=1
)

table_card.pack(fill="both", expand=True)

tk.Label(
    table_card,
    text="Captured Packets",
    font=("Segoe UI", 13, "bold"),
    bg=CARD_COLOR,
    fg=TEXT_COLOR
).pack(anchor="w", padx=15, pady=12)

table_container = tk.Frame(table_card, bg=CARD_COLOR)
table_container.pack(fill="both", expand=True, padx=12, pady=(0, 12))

columns = (
    "No.",
    "Time",
    "Source IP",
    "Destination IP",
    "Protocol",
    "Source Port",
    "Destination Port",
    "Application",
    "Size (Bytes)"
)

packet_table = ttk.Treeview(
    table_container,
    columns=columns,
    show="headings"
)

column_widths = {
    "No.": 60,
    "Time": 90,
    "Source IP": 230,
    "Destination IP": 230,
    "Protocol": 95,
    "Source Port": 95,
    "Destination Port": 115,
    "Application": 110,
    "Size (Bytes)": 100
}

for column in columns:
    packet_table.heading(column, text=column)

    packet_table.column(
        column,
        width=column_widths[column],
        minwidth=60,
        anchor="center"
    )

vertical_scroll = ttk.Scrollbar(
    table_container,
    orient="vertical",
    command=packet_table.yview
)

horizontal_scroll = ttk.Scrollbar(
    table_container,
    orient="horizontal",
    command=packet_table.xview
)

packet_table.configure(
    yscrollcommand=vertical_scroll.set,
    xscrollcommand=horizontal_scroll.set
)

packet_table.grid(row=0, column=0, sticky="nsew")
vertical_scroll.grid(row=0, column=1, sticky="ns")
horizontal_scroll.grid(row=1, column=0, sticky="ew")

table_container.grid_rowconfigure(0, weight=1)
table_container.grid_columnconfigure(0, weight=1)


# =========================
# TABLE STYLING
# =========================

style = ttk.Style()

style.theme_use("clam")

style.configure(
    "Treeview",
    background=CARD_COLOR,
    foreground=TEXT_COLOR,
    fieldbackground=CARD_COLOR,
    rowheight=30,
    font=("Segoe UI", 9)
)

style.configure(
    "Treeview.Heading",
    background="#EFF6FF",
    foreground=TEXT_COLOR,
    font=("Segoe UI", 9, "bold"),
    padding=8
)

style.map(
    "Treeview",
    background=[("selected", "#DBEAFE")],
    foreground=[("selected", TEXT_COLOR)]
)


# =========================
# FOOTER
# =========================

footer = tk.Label(
    root,
    text="NetScope  |  Educational Cybersecurity Project  |  "
         "Capture traffic only on authorized networks",
    bg=CARD_COLOR,
    fg=MUTED_COLOR,
    font=("Segoe UI", 9),
    pady=10
)

footer.pack(fill="x")


# =========================
# START APPLICATION
# =========================

root.after(150, process_queue)

root.mainloop()
