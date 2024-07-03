from scapy.all import rdpcap, Raw
import statistics


def compare_pcap_files(file1, file2):
    # Read packets from both pcap files
    packets1 = rdpcap(file1)
    packets2 = rdpcap(file2)
    total_packets = len(packets1)

    # Convert packets to a simpler, comparable format (e.g., raw payload data)
    packets1_set = { bytes(pkt.payload) for pkt in packets1 if pkt.haslayer(Raw) }
    packets2_set = { bytes(pkt.payload) for pkt in packets2 if pkt.haslayer(Raw) }

    # Find common and unique packets
    common_packets = packets1_set.intersection(packets2_set)
    unique_to_file1 = packets1_set.difference(packets2_set)
    unique_to_file2 = packets2_set.difference(packets1_set)

    return common_packets, unique_to_file1, unique_to_file2, total_packets

# Example usage
index = 1
file1 = 'attack_experiments/attack1/wired_data/d0/'

file2 = 'attack_experiments/attack1/wireless_data/d0/'
error_rates = []
while index < 6:
    common_packets, unique_to_file1, unique_to_file2, total_packets = compare_pcap_files(file1 + "wired_capture"+ str(index) + "_udp.pcap", file2 + "wireless_capture"+ str(index) + "_udp.pcap")
    # Error rate
    error_rates.append(len(unique_to_file1)/total_packets)
    
    index += 1

# Do the average of the error rates
error_rate_std_dev = statistics.stdev(error_rates)
print(f"Standard deviation of the error rates: {error_rate_std_dev}")
average_error_rate = sum(error_rates) / len(error_rates)
print(f"Average error rate for d0: {average_error_rate}")

# Example usage
index = 0
file1 = 'attack_experiments/attack1/wired_data/d2/'

file2 = 'attack_experiments/attack1/wireless_data/d2/'
error_rates = []
while index < 5:
    common_packets, unique_to_file1, unique_to_file2, total_packets = compare_pcap_files(file1 + "wired_2m_capture"+ str(index) + "_udp.pcap", file2 + "wireless_2m_capture"+ str(index) + "_udp.pcap")
    # Error rate
    error_rates.append(len(unique_to_file1)/total_packets)
    
    index += 1

# Do the average of the error rates and the standard deviation
# Calculate the standard deviation of the error rates
error_rate_std_dev = statistics.stdev(error_rates)
print(f"Standard deviation of the error rates: {error_rate_std_dev}")
average_error_rate = sum(error_rates) / len(error_rates)
print(f"Average error rate for d2: {average_error_rate}")