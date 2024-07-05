from sniffing.constants import MAC_ADDRESS_BENTRY_HEADER, MAC_ADDRESS_BENTRY_LENGTH, HEADER_MAPPING, DELIMETER_TYPES
from sniffing.layerscapy.HomePlugAV import *
from gps import *
import pyshark
from collections import Counter
import os

################### SNIFFER TOOLS ###################


# Sniffer control values
SNIFFER_ON = 1
SNIFFER_OFF = 0

def enable_sniff_mode(sourcemac, iface):
    print("[+] Enabling sniff mode")
    pkt = Ether(src=sourcemac) / HomePlugAV() / SnifferRequest(SnifferControl=SNIFFER_ON)
    sendp(pkt, iface=iface)

def disable_sniff_mode(sourcemac, iface):
    print("[+] Disabling sniff mode")
    pkt = Ether(src=sourcemac) / HomePlugAV() / SnifferRequest(SnifferControl=SNIFFER_OFF)
    sendp(pkt, iface=iface)

def get_network_information(sourcemac, iface):
    pkt = Ether(src=sourcemac) / HomePlugAV() / NetworkInformationRequest()
    sendp(pkt, iface=iface)

################### PACKET PROCESSING TOOLS ###################
    

def get_gps_coordinates(gpsd):
    nx = gpsd.next()
    if nx["class"] == "TPV":
        latitude = getattr(nx, "lat", "Unknown")
        longitude = getattr(nx, "lon", "Unknown")
        
        return latitude, longitude
    else:
        return "Unknown", "Unknown"


def get_mac_from_beacon(pkt):
    bentries = pkt["homeplug-av"].get("homeplug_av.bcn.bentries").split(":")

    # Move through the sequence alternating beacin entry header, beacon entry length, beacon entry until we get to the MAC Discovery beacon
    for i in range(0, len(bentries)):
        if bentries[i] == MAC_ADDRESS_BENTRY_HEADER and bentries[i + 1] == MAC_ADDRESS_BENTRY_LENGTH:
            mac = bentries[i + 2 : i + 2 + int(MAC_ADDRESS_BENTRY_LENGTH)]
            return ":".join(mac)
        

def extract_all_bentry_info(pkt):
    
    bentries = pkt["homeplug-av"].get("homeplug_av.bcn.bentries").split(":")
    
    i = 0
    nb_bentries = int(bentries[0], 16)
    
    i += 1 # Skip the number of bentries
    extracted_info = {}

    while i < len(bentries):
        if len(extracted_info) == nb_bentries:
            break
        # Extract beacon entry header and length
        bentry_header = bentries[i]
        bentry_length = int(bentries[i + 1], 16)

        # Extract content
        content = bentries[i + 2 : i + 2 + bentry_length]

        # Use the mapping to get the text description
        header_description = HEADER_MAPPING.get(bentry_header, "Unknown Header")

        # Store the extracted information in the dictionary
        if bentry_header == MAC_ADDRESS_BENTRY_HEADER:
            extracted_info[header_description] = ":".join(content)
        else:
            extracted_info[header_description] = content

        # Move to the next beacon entry
        i += 2 + bentry_length

    return extracted_info


################### EXPERIMENTS ###################


def capture_for_distance(distance, options, folder_name, add_to_filename=""):
    for i in range(0, int(options.epoch)):
        print(f"Epoch {i + 1}/{options.epoch}")
        file_path = f"sniffer_experiments/data/{folder_name}/capture_{add_to_filename}_{distance}_{i}.pcap"
        with open(file_path, "w") as f:
            f.write("")
        
        command = f"sudo tshark -i {options.iface} -a duration:{options.capture_time} -w {file_path}"
        os.system(command)
    
    cmd = f"mergecap -w {os.getcwd()}/sniffer_experiments/data/{folder_name}/capture_{distance}.pcap {os.getcwd()}/sniffer_experiments/data/{folder_name}/capture_{add_to_filename}_{distance}_*.pcap"
    os.system(cmd)
    print(f"Finished sniffing for {distance} meters")

def statistics_capture_for_distance(distance, distance_data, epoch_nb, folder_name, add_to_filename=""):
    
    distance_data[distance] = {
        "packet_count": [],
        "homeplug_packets_count": [],
        "delimiter_count": [],
        "detected_devices": [],
        "beacon_count_per_mac": [],
        "sof_ble_num_symbols": []
    }

    print(f"- Sniffing for {distance} meters -")

    for i in range(0, int(epoch_nb)):
        print(f"Epoch {i + 1}/{epoch_nb}")

        delimiter_count = {
            "BEACON": 0,
            "SOF": 0,
            "SACK": 0,
            "SOUND": 0,
            "REVERSE_SOF": 0,
            "RTS_CTS": 0
        }

        beacon_count_per_mac = {}
        detected_devices = []
        
        # Sniff & Capture ########################

        capture = pyshark.FileCapture(f"sniffer_experiments/data/{folder_name}/capture_{add_to_filename}_{distance}_{i}.pcap")
        capture.load_packets()
        
        # capture.sniff(timeout=int(options.capture_time))

        ##########################################

        # Analysis of the capture ################
        print(f"Captured {len(capture)} packets")
        distance_data[distance]["packet_count"].append(len(capture))

        index = 0
        nb_hp_packets = 0
        while index < len(capture):
            packet = capture[index]
            if "homeplug-av" in packet:

                # Count the number of HomePlug AV packets
                nb_hp_packets += 1

                delimeter_type = DELIMETER_TYPES.get(packet["homeplug-av"].get("homeplug_av.fc.del_type"), "None")
                if delimeter_type != "None":
                    delimiter_count[delimeter_type] += 1

                    if delimeter_type == "BEACON":

                        mac = get_mac_from_beacon(packet)
                        nid = packet["homeplug-av"].get("homeplug_av.bcn.nid")
                        
                        if mac not in detected_devices:
                            detected_devices.append(mac)

                        beacon_count_per_mac[mac] = beacon_count_per_mac.get(mac, 0) + 1
                        beacon_count_per_mac[nid] = beacon_count_per_mac.get(nid, 0) + 1
                    
                    if delimeter_type == "SOF":
                        
                        ble = packet["homeplug-av"].get("homeplug_av.sof.ble")
                        num_symbols = packet["homeplug-av"].get("homeplug_av.sof.num_sym")

                        distance_data[distance]["sof_ble_num_symbols"].append((ble, num_symbols))

            index += 1

        distance_data[distance]["homeplug_packets_count"].append(nb_hp_packets)
        distance_data[distance]["delimiter_count"].append(delimiter_count)
        distance_data[distance]["detected_devices"].append(detected_devices)
        distance_data[distance]["beacon_count_per_mac"].append(beacon_count_per_mac)

    sof_ble_counts = Counter(distance_data[distance]["sof_ble_num_symbols"])
    for item, count in sof_ble_counts.items():
        sof_ble_counts[item] /= int(epoch_nb)
    distance_data[distance]["sof_ble_num_symbols"] = sof_ble_counts
    
    print(f"HomePlug AV packets for {distance} meters: {nb_hp_packets}")
    
    return distance_data