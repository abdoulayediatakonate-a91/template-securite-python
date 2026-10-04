from src.tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from scapy.all import rdpcap

class Capture:
    def __init__(self, pcap_path: str) -> None:
        #chemin du pcap
        self.pcap_path = pcap_path
        # la liste pour compter les paquets
        self.packets: list = []
        #dico qui contient protocole et nombre (str pour les protocoles et int pour les entiers)
        self.protocols: dict[str, int] = {}
        self.attacks: list[dict[str, str]] = []
        self.flag = ""
        self.summary = ""

        logger.info("Capture créée pour %s", pcap_path)

    def capture_traffic(self) -> None:
        #Lit le PCAP et récupère les paquets. """
        logger.info("Lecture du fichier pcap : %s", self.pcap_path)
        # rdpcap lit  le fichier et renvoie les paquets
        self.packets = rdpcap(self.pcap_path)
        logger.info("Le Nombre de paquets : %s", len(self.packets))

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        return ""

    def get_all_protocols(self) -> str:
        """
        Return all protocols captured with total packets number
        """
        return ""

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        Si un tra c est illégitime (exemple : Injection SQL, ARP
        Spoo ng, etc)
        a Noter la tentative d'attaque.
        b Relever le protocole ainsi que l'adresse réseau/physique
        de l'attaquant.
        c (FACULTATIF) Opérer le blocage de la machine
        attaquante.
        Sinon a cher que tout va bien
        """
        all_protocols = self.get_all_protocols()
        sort = self.sort_network_protocols()
        logger.debug(f"All protocols: {all_protocols}")
        logger.debug(f"Sorted protocols: {sort}")

        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        summary = ""
        return summary
