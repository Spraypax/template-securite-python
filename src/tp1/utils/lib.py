# Fonctions utilitaires : saisie utilisateur, gestion des protocoles

def hello_world() -> str:
    """Fonction de test hello world."""
    return "hello world"

def choose_interface() -> str:
    """Demande à l'utilisateur de choisir une interface réseau (défaut : eth0)."""
    try:
        iface = input("Choix interface (default eth0): ").strip()
        return iface if iface else "eth0"
    except Exception:
        return "ens33"


def choose_duration() -> int:
    """
    Demande la durée de capture avec support des suffixes h / min / m / s.
    Retourne une durée en secondes (défaut : 60s).
    """
    try:
        val = input("Capture duration (ex: 1h, 30min, 45s - default 1min): ").strip().lower()
        if not val:
            return 60
        if val.endswith("h"):
            return int(val[:-1]) * 3600
        elif val.endswith("min"):
            return int(val[:-3]) * 60
        elif val.endswith("m"):
            return int(val[:-1]) * 60
        elif val.endswith("s"):
            return int(val[:-1])
        else:
            return int(val) * 60  # sans suffixe = minutes par défaut
    except (ValueError, Exception):
        return 60


def choose_packet_count() -> int:
    """Demande le nombre maximum de paquets à capturer (0 = illimité)."""
    try:
        val = input("Max packets à capturer (0 = unlimited, default 0): ").strip()
        return int(val) if val else 0
    except (ValueError, Exception):
        return 0

# Mapping des numéros de protocole vers leur nom lisible
PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def proto_name(proto) -> str:
    """
    Convertit un numéro de protocole IP en nom lisible.
    Retourne 'UNKNOWN' si le protocole n'est pas reconnu.
    """
    try:
        proto_int = int(proto)
        return PROTO_MAP.get(proto_int, "UNKNOWN")
    except (ValueError, TypeError):
        if proto == "ARP":
            return "ARP"
        return "UNKNOWN"
