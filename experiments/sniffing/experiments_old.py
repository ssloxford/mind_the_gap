#!/usr/bin/env python3
from prettytable import PrettyTable
import pyshark
import statistics
from layerscapy.HomePlugAV import *
from optparse import OptionParser
import pprint
from constants import *
from tools import enable_sniff_mode, disable_sniff_mode, get_mac_from_beacon

################### FUNCTIONS ###################        

def varying_distance_stats(options):

    table = PrettyTable()
    table.field_names = ["Distance", "HP Packet Rate", "StDev of HP Packet Rate", "Total Beacon Rate", "Beacon Rate / MAC", "SOF Rate", "SACK Rate", "RTS/CTS Rate"]

    CAPTURE_TIME = 60

    distance_data = {}

    def sniff_and_detect(distance):
        # Start detection for distance
        print(f"- Sniffing for {distance} meters -")

        distance_data[distance] = {
            "packet_rate": [],
            "homeplug_packets_rate": [],
            "delimiter_rates": {},
            "detected_devices": [],
        }

        delimiter_counts = {
                "BEACON": 0,
                "SOF": 0,
                "SACK": 0,
                "SOUND": 0,
                "REVERSE_SOF": 0,
                "RTS_CTS": 0
        }

        beacons_count_per_mac = {}

        
        # Average out the final results over epoch number of runs
        for i in range(0, int(options.epoch)):
            print(f"Epoch {i + 1}/{options.epoch}")

            # Sniff & Capture
            enable_sniff_mode(options.sourcemac, options.iface)
            
            capture = pyshark.LiveCapture(interface=options.iface)
            capture.sniff(timeout=CAPTURE_TIME)

            disable_sniff_mode(options.sourcemac, options.iface)

            print(f"Captured {len(capture)} packets")
            distance_data[distance]["packet_rate"].append(len(capture))
            
            # Analysis of the capture
            nb_homeplug_packets = 0
            index = 0
            while index < len(capture):
                
                if "homeplug-av" in capture[index]:

                    nb_homeplug_packets += 1
                    
                    delimeter_type = DELIMETER_TYPES.get(capture[index]["homeplug-av"].get("homeplug_av.fc.del_type"), "None")
                    if delimeter_type != "None":
                        delimiter_counts[delimeter_type] += 1

                        if delimeter_type == "BEACON":

                            mac = get_mac_from_beacon(capture[index])
                            nid = capture[index]["homeplug-av"].get("homeplug_av.bcn.nid")
                            
                            if mac not in distance_data[distance]["detected_devices"]:
                                distance_data[distance]["detected_devices"].append(mac)

                            beacons_count_per_mac[mac] = beacons_count_per_mac.get(mac, 0) + 1
                            beacons_count_per_mac[nid] = beacons_count_per_mac.get(nid, 0) + 1

                index+=1

            distance_data[distance]["homeplug_packets_rate"].append(nb_homeplug_packets)

        # Do the average of beacon rates, packet rates, homeplug packets rates TODO: should save all the data and do the average later
        distance_data[distance]["packet_rate"] = statistics.mean(distance_data[distance]["packet_rate"])
        distance_data[distance]["stdev_homeplug_packets_rate"] = statistics.stdev(distance_data[distance]["homeplug_packets_rate"])
        distance_data[distance]["homeplug_packets_rate"] = statistics.mean(distance_data[distance]["homeplug_packets_rate"])
        distance_data[distance]["beacon_rate_per_mac"] = {k: v / int(options.epoch) for k, v in beacons_count_per_mac.items()}
        delimiter_counts = {k: v / int(options.epoch) for k, v in delimiter_counts.items()}
        distance_data[distance]["delimiter_rates"] = delimiter_counts

        # "Distance", "HP Packet Rate", "StDev of HP Packet Rate", "Total Beacon Rate", "Beacon Rate / MAC or NID", "SOF Rate", "SACK Rate", "RTS/CTS Rate"
        table.add_row([
            distance,
            distance_data[distance]["homeplug_packets_rate"],
            distance_data[distance]["stdev_homeplug_packets_rate"],
            distance_data[distance]["delimiter_rates"]["BEACON"],
            distance_data[distance]["beacon_rate_per_mac"],
            distance_data[distance]["delimiter_rates"]["SOF"],
            distance_data[distance]["delimiter_rates"]["SACK"],
            distance_data[distance]["delimiter_rates"]["RTS_CTS"],
        ])

        print(f"- Finished sniffing {distance} -")
        print(table)
        print("\n\n")

    # Sniff at different distances
    while True:
        distance = input("Enter distance (in meters), or q if you want to end: ")
        if distance == "q":
            if options.output_file:
                with open("data_analysis/data/" + options.output_file, "w") as f:
                    pprint.pprint(distance_data, f)
            break
        sniff_and_detect(distance)

if __name__ == "__main__":
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage)
    parser.add_option(
        "-s",
        "--source",
        dest="sourcemac",
        default=DEFAULT_SOURCEMAC,
        help="source MAC address to use",
        metavar="SOURCEMAC",
    )
    parser.add_option(
        "-i",
        "--iface",
        dest="iface",
        default=DEFAULT_IFACE,
        help="select an interface to Enable sniff mode and sniff indicates packets",
        metavar="INTERFACE",
    )
    parser.add_option(
        "--epoch",
        dest="epoch",
        default=DEFAULT_EPOCH_NB,
        help="epoch number for the experiments",
    )
    parser.add_option(
        "-o",
        "--output_file",
        dest="output_file",
        default=DEFAULT_OUTPUT_FILE,
        help="output file for the devices recorded",
    )
    (options, args) = parser.parse_args()

    varying_distance_stats(options)