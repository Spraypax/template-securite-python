# Gestion de la capture réseau, analyse des paquets et détection d'intrusions

import threading
import time
from collections import defaultdict

from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP

from tp1.utils.lib import choose_interface, choose_duration, choose_packet_count, proto_name
from tp1.utils.config import logger


class Capture:
    """
    Classe principale de capture réseau.
    Gère la capture, l'analyse des protocoles et la détection d'intrusions (SQLi, ARP Spoofing).
    """

    def __init__(self) -> None:
        self.interface = choose_interface() or "ens33"
        self.duration = choose_duration()
        self.packet_count = choose_packet_count()   # 0 = illimité

        # Stockage des paquets bruts
        self.packets = []

        # Compteurs et mappings par protocole / IP
        self.protocol_counter = defaultdict(int)
        self.ip_packet_counter = defaultdict(int)
        self.ip_proto_map = defaultdict(set)
        self.ip_proto_counter = defaultdict(lambda: defaultdict(int))

        # Détections d'activités suspectes
        self.proto_suspicious = defaultdict(list)
        self.suspicious = []

        # Résumé textuel généré après analyse
        self.summary = ""

    def _handle_ip(self, packet) -> None:
        """Traite un paquet IP : identifie le protocole et trace src/dst."""
        proto = proto_name(packet[IP].proto)
        self.protocol_counter[proto] += 1

        src_ip, dst_ip = packet[IP].src, packet[IP].dst
        for ip in (src_ip, dst_ip):
            self.ip_packet_counter[ip] += 1
            self.ip_proto_map[ip].add(proto)
            self.ip_proto_counter[ip][proto] += 1

    def _handle_arp(self, packet) -> None:
        """Traite un paquet ARP : trace src/dst."""
        self.protocol_counter["ARP"] += 1

        src_ip, dst_ip = packet[ARP].psrc, packet[ARP].pdst
        for ip in (src_ip, dst_ip):
            self.ip_packet_counter[ip] += 1
            self.ip_proto_map[ip].add("ARP")
            self.ip_proto_counter[ip]["ARP"] += 1

    def _packet_handler(self, packet) -> None:
        """Traite chaque paquet capturé : routage vers le bon handler + détections."""
        self.packets.append(packet)

        if IP in packet:
            self._handle_ip(packet)
        elif ARP in packet:
            self._handle_arp(packet)
        else:
            self.protocol_counter["UNKNOWN"] += 1

        self._detect_sqli(packet)
        self._detect_arp_spoof(packet)


    def _detect_sqli(self, packet) -> None:
        """Détecte une injection SQL dans le payload TCP."""
        if not (hasattr(packet, "haslayer") and packet.haslayer(TCP)):
            return
        payload = getattr(packet[TCP], "payload", None)
        if payload and b"SELECT" in str(payload).encode():
            src = packet[IP].src if IP in packet else "Unknown"
            alert = f"[TCP] SQLi detected from {src}"
            self.suspicious.append(alert)
            self.proto_suspicious["TCP"].append(alert)

    def _detect_arp_spoof(self, packet) -> None:
        """Détecte un ARP Spoofing : IP source == IP destination."""
        if ARP in packet and packet[ARP].psrc == packet[ARP].pdst:
            alert = f"[ARP] ARP Spoofing from MAC {packet[ARP].hwsrc} / IP {packet[ARP].psrc}"
            self.suspicious.append(alert)
            self.proto_suspicious["ARP"].append(alert)


    def _display_progress(self, stop_event: threading.Event) -> None:
        """Affiche le temps restant et le nombre de paquets en temps réel."""
        start = time.time()
        while not stop_event.is_set():
            elapsed = time.time() - start
            remaining = max(0.0, float(self.duration) - elapsed)
            pkt_count = len(self.packets)

            if remaining >= 3600:
                time_str = f"{int(remaining // 3600)}h{int((remaining % 3600) // 60)}min"
            elif remaining >= 60:
                time_str = f"{int(remaining // 60)}min{int(remaining % 60)}s"
            else:
                time_str = f"{int(remaining)}s"

            pkt_str = f"{pkt_count}/{self.packet_count}" if self.packet_count > 0 else str(pkt_count)
            print(f"\rTemps restant: {time_str}  |  {pkt_str} packets   ", end="", flush=True)
            time.sleep(0.5)
        print()

    def capture_traffic(self) -> None:
        """
        Capture le trafic réseau.
        S'arrête lorsque la durée OU le nombre maximum de paquets est atteint.
        """
        count_str = f"max {self.packet_count} packets" if self.packet_count > 0 else "unlimited packets"
        logger.info(f"Capture sur {self.interface} ({count_str})")

        stop_event = threading.Event()
        thread = threading.Thread(target=self._display_progress, args=(stop_event,), daemon=True)
        thread.start()
        try:
            sniff(
                iface=self.interface,
                prn=self._packet_handler,
                count=self.packet_count,
                timeout=self.duration,
            )
        finally:
            stop_event.set()
            thread.join()


    def sort_network_protocols(self) -> dict:
        """Retourne les protocoles triés par nombre de paquets décroissant."""
        return dict(sorted(self.protocol_counter.items(), key=lambda x: x[1], reverse=True))

    def get_all_protocols(self) -> dict:
        """Retourne tous les protocoles capturés avec leur nombre de paquets."""
        return dict(self.protocol_counter)

    def get_proto_analysis(self) -> dict:
        """Retourne l'analyse par protocole avec statut légitime ou suspect."""
        return {
            proto: {
                "count": count,
                "status": "SUSPICIOUS" if self.proto_suspicious.get(proto) else "OK",
                "alerts": self.proto_suspicious.get(proto, []),
            }
            for proto, count in self.protocol_counter.items()
        }

    def analyse(self) -> None:
        """Lance l'analyse et génère le résumé textuel."""
        logger.debug(f"All protocols: {self.get_all_protocols()}")
        logger.debug(f"Sorted protocols: {self.sort_network_protocols()}")
        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """Retourne le résumé généré par analyse()."""
        return self.summary

    def _gen_summary(self) -> str:
        """Génère le résumé textuel complet : protocoles, IPs, et analyse du trafic."""
        lines = [
            "=== IDS SUMMARY ===\n",
            f"Interface: {self.interface}",
            f"Total packets capturé : {len(self.packets)}\n",
            "Protocols detecté :",
            f"{'Protocol':<12} {'Packets':>8}",
            "-" * 22,
        ]

        for proto, count in self.sort_network_protocols().items():
            lines.append(f"{proto:<12} {count:>8}")

        lines += [
            "\nPackets par IP address:",
            f"{'IP Address':<20} {'Packets':>8}  {'Protocols'}",
            "-" * 50,
        ]

        sorted_ips = sorted(self.ip_packet_counter.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips:
            proto_details = ", ".join(
                f"{p}: {c}" for p, c in sorted(self.ip_proto_counter.get(ip, {}).items())
            )
            lines.append(f"{ip:<20} {count:>8}  {proto_details}")

        lines.append("\nTraffic analysis:")
        if not self.suspicious:
            lines.append("All traffic is legitimate.")
        else:
            lines.extend(self.suspicious)

        return "\n".join(lines) + "\n"
