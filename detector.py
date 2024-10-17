import csv  # Import for CSV file handling.
import threading  # Import for running threads in parallel.
import requests  # Import for making HTTP requests (to get IP geolocation).
from scapy.all import *  # Import all modules from Scapy for packet sniffing and manipulation.
from data import *  # Import user-defined data, such as IP address (IP_ADDRESS).


class AttackDetector:
    """
    Class to detect and log DDoS attacks based on incoming network traffic.

    Attributes:
        - duration: The time (in seconds) to monitor traffic. Type: int
        - interface: The network interface to sniff packets on. Type: str
        - my_ip: The IP address of the machine to monitor for attacks. Type: str
        - packet_counts: A defaultdict to count packet types per source IP. Type: defaultdict
        - packet_timestamps: A defaultdict to store packet arrival times per source IP. Type: defaultdict
        - ddos_packet_threshold: The number of packets above which an IP is flagged for DDoS. Type: int
        - time_window: Time frame (in seconds) for DDoS packet rate checks. Type: int
        - csv_file: The filename to log detected attacks. Type: str
    """

    def __init__(self, duration=60, interface=conf.iface):
        """
        Initialize an instance of AttackDetector with default or provided values.

        Parameters:
            - duration: The duration to monitor for attacks in seconds. Type: int. Default: 60
            - interface: The network interface to sniff packets on. Type: str. Default: conf.iface
        """

        self.duration = duration  # Duration for the attack detection.
        self.my_ip = IP_ADDRESS  # Local IP address (from imported data).
        self.interface = interface  # Network interface to use for sniffing packets.
        self.packet_counts = defaultdict(lambda: defaultdict(int))  # Store packet counts by source IP and protocol.
        self.packet_timestamps = defaultdict(list)  # Store packet timestamps by source IP.
        self.ddos_packet_threshold = 50  # Threshold for packet counts to flag potential DDoS attacks.
        self.time_window = 60  # Time window for counting packets (in seconds).
        self.csv_file = "attack_log.csv"  # File to log detected attacks.

        # Create an empty attack log file (or clear existing file).
        with open(self.csv_file, mode='w') as file:
            pass

    def packet_callback(self, pkt):
        """
        Callback function to handle each captured packet.

        Parameters:
            - pkt: The packet captured during sniffing. Type: scapy.packet.Packet
        """

        print(pkt)
        if pkt.haslayer("IP"):  # Check if the packet has an IP layer.
            src_ip = pkt[IP].src  # Get source IP address.
            dst_ip = pkt[IP].dst  # Get destination IP address.
            current_time = time.time()  # Record the current time.

            if self.my_ip == dst_ip:  # Process the packet only if it's addressed to the local machine.
                if pkt.haslayer("TCP"):  # Check if the packet has a TCP layer.
                    self.packet_counts[src_ip]["TCP"] += 1
                    if pkt[TCP].flags.flagrepr() == "S":  # Check for SYN flag (SYN flood attack).
                        self.packet_counts[src_ip]["syn_flood"] += 1
                    elif pkt[TCP].flags.flagrepr() == "SA":  # Check for SYN-ACK flags (SYN-ACK attack).
                        self.packet_counts[src_ip]["syn_ack"] += 1
                elif pkt.haslayer("ICMP"):  # Check if the packet has an ICMP layer.
                    self.packet_counts[src_ip]["ICMP"] += 1
                    if pkt.haslayer(Raw):  # Check for large payload (Ping of Death).
                        self.packet_counts[src_ip]["pod"] += 1
                    elif pkt[ICMP].type == 8:  # Check for ICMP Echo Request (Smurf attack).
                        self.packet_counts[src_ip]["smurf"] += 1

                # Store packet timestamp and check if the source IP shows signs of a DDoS attack.
                self.packet_timestamps[src_ip].append(current_time)
                packet_size = len(pkt)  # Get the size of the packet.
                self.check_for_attacks(src_ip, packet_size, current_time)  # Check for any suspicious activities.

    def check_for_attacks(self, ip, packet_size, current_time):
        """
        Check if the source IP is performing any known DDoS attack types.

        Parameters:
            - ip: The source IP address of the packets to check for attacks. Type: str
            - packet_size: The size of the packet involved in the attack. Type: int
            - current_time: The timestamp of the packet capture (used to analyze time-based behavior). Type: float
        """

        counts = self.packet_counts[ip]  # Retrieve the packet counts for the given source IP.
        attack_type = None  # Initialize the attack_type as None.

        # Check if packet counts for each attack type have crossed the defined threshold.
        if counts["syn_flood"] > self.ddos_packet_threshold:  # Check if SYN flood attack is detected.
            attack_type = "syn_flood"
        if counts["syn_ack"] > self.ddos_packet_threshold:  # Check if SYN-ACK flood attack is detected.
            attack_type = "syn_ack"
        elif counts["pod"] > self.ddos_packet_threshold:  # Check if Ping of Death (PoD) attack is detected.
            attack_type = "pod"
        elif counts["smurf"] > self.ddos_packet_threshold:  # Check if Smurf attack is detected.
            attack_type = "smurf"

        if attack_type:
            if self.check_for_ddos(ip, current_time):  # Verify if the attack is happening within the time window.
                self.log_attack(ip, attack_type, packet_size)  # Log the attack if detected.
                self.packet_timestamps[ip] = []  # Reset timestamps after logging.
            self.packet_counts[ip] = defaultdict(int)  # Reset packet counts for the IP.

    def check_for_ddos(self, ip, current_time):
        """
        Determine if the source IP is conducting a DDoS attack within the time window.

        Parameters:
            - ip: The source IP address to evaluate. Type: str
            - current_time: The current time used to analyze packets within a time window. Type: float

        Returns:
            - bool: True if the IP exceeded the packet threshold within the time window, False otherwise.
        """

        # Remove packets older than the time window from the timestamps.
        self.packet_timestamps[ip] = [timestamp for timestamp in self.packet_timestamps[ip] if
                                      current_time - timestamp <= self.time_window]
        # Return True if the packet count exceeds the threshold.
        return len(self.packet_timestamps[ip]) > self.ddos_packet_threshold

    def log_attack(self, ip, attack_type, packet_size):
        """
        Log the detected attack details into a CSV file and print the attack to console.

        Parameters:
            - ip: The IP address of the source performing the attack. Type: str
            - attack_type: The type of the detected attack (e.g., syn_flood, smurf, pod). Type: str
            - packet_size: The size of the detected packet (in bytes). Type: int
        """

        country = self.get_ip_location(ip)  # Get the country of the source IP using geolocation.
        print(f"{ip} is flagged as {attack_type} from {country}")  # Print attack information.

        # Append attack details (IP, attack type, country, packet size, timestamp) to the CSV log file.
        with open(self.csv_file, mode='a', newline='') as file:  # Open the CSV file in append mode.
            writer = csv.writer(file)  # Create a CSV writer object.
            writer.writerow([ip, attack_type, country, packet_size, time.strftime("%Y-%m-%d %H:%M:%S")])  # Write the attack details in a new row.

    def get_ip_location(self, ip):
        """
        Retrieve the country of the IP address using the IP-API service.

        Parameters:
            - ip: The IP address to get the location of. Type: str

        Returns:
            - str: The country of the IP address if available, otherwise 'Unknown'.
        """

        try:
            response = requests.get(f"http://ip-api.com/json/{ip}")  # Make an API request to get geolocation.
            data = response.json()  # Parse the response as JSON.
            return data.get("country", "Hidden")  # Return the country or "Hidden" if unavailable.
        except:  # Handle any exceptions (e.g., network issues, invalid response).
            return "Hidden"  # Return "Hidden" if the request fails.

    def start(self):
        """
        Start the attack detection process, which sniffs packets on the specified network interface for the given duration.
        """

        print(f"Starting attack detection on interface {self.interface} for {self.duration} seconds.")
        end_time = time.time() + self.duration  # Set the time to stop the detection.

        # Start a thread to sniff packets and apply the callback function to each packet.
        sniff_thread = threading.Thread(
            target=lambda: sniff(iface=self.interface, prn=self.packet_callback, filter="tcp or icmp")) # Capture TCP or ICMP packets.
        sniff_thread.daemon = True  # Make the thread run in the background (terminates when the main program ends).
        sniff_thread.start()  # Start the sniffing thread.

        try:
            while time.time() < end_time:  # Continue detection until the end time is reached.
                time.sleep(1)  # Sleep for 1 second to avoid overloading the CPU.
            print("Attack detection was finished.")  # Inform that the detection has ended.
            sys.exit()  # Exit the program after completing the detection.
        except KeyboardInterrupt:  # Allow the user to stop the detection with Ctrl+C.
            print("Attack detection was stopped by user.") # Print a message indicating that the detection was manually stopped.
            sys.exit()  # Exit the program upon manual interruption.


# Main entry point of the program to initialize the attack detector with a given duration.
if __name__ == "__main__":
    # Command-line argument parser for the script.
    parser = argparse.ArgumentParser(description="DDoS attack detector.")  # Create an argument parser.
    parser.add_argument("duration", type=int, help="Duration of the attack in seconds.")  # Argument for the detection duration.

    # Check if any arguments were provided (besides the script name).
    if len(sys.argv) == 1:  # No arguments passed.
        print("No arguments provided. Using default duration.")
        detector = AttackDetector()  # Initialize the AttackDetector with default duration.
    else:
        args = parser.parse_args()  # Parse the command-line arguments.
        detector = AttackDetector(args.duration)  # Initialize the AttackDetector with the specified duration.

    detector.start()  # Start the attack detection.
