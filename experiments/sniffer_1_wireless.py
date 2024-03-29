#!/usr/bin/env python3
# from prettytable import PrettyTable

import statistics
from optparse import OptionParser
import pprint
from sniffing.tools import enable_sniff_mode, disable_sniff_mode, capture_for_distance
from sniffing.constants import DEFAULT_EPOCH_NB, DEFAULT_SNIFF_DURATION, DEFAULT_IFACE, DEFAULT_SOURCEMAC, DEFAULT_OUTPUT_FILE
import os
import json

# Start by doing test with 2 sniffers on the same line
# Then do test with 2 sniffers on different lines

distance_data = {}

def experiment1(options, world=False):
    # Start detection for distance
    print(f"- EXPERIMENT SETUP 1 - WIRELESS SNIFFER - NOT PART OF AVLN - PASSIVE -")

    # Enable sniff mode
    enable_sniff_mode(options.sourcemac, options.iface)

    # Capture for each distance
    while True:
        distance = input("Enter distance (in meters) to sniff for (q to stop): ")
        if distance == "q":
            # Save the results
            if options.output_file:
                if world:
                    with open(os.getcwd() + "/experiments/data/world_exp1/wireless_sniffer_" + options.output_file + ".json", "w") as f:
                        json.dump(distance_data, f)
                else:
                    with open(os.getcwd() + "/experiments/data/exp1/wireless_sniffer_" + options.output_file + ".json", "w") as f:
                        json.dump(distance_data, f)
            break
        capture_for_distance(distance, distance_data, options)
    
    # Disable sniff mode at the end of the experiments
    disable_sniff_mode(options.sourcemac, options.iface)

# def experiment2(options):
#     # Start detection for distance
#     print(f"- EXPERIMENT SETUP 2 - WIRELESS SNIFFER - PART OF AVLN - ACTIVE -")

#     # Enable sniff mode
#     enable_sniff_mode(options.sourcemac, options.iface)

#     # Capture for each distance
#     while True:
#         distance = input("Enter distance (in meters) to sniff for (q to stop): ")
#         if distance == "q":
#             # Save the results
#             if options.output_file:
#                 with open(os.getcwd() + "/experiments/data/exp1_wireless_sniffer_" + options.output_file + ".json", "w") as f:
#                     json.dump(distance_data, f)
#             break
#         capture_for_distance(distance, distance_data, options)
    
#     # Disable sniff mode at the end of the experiments
#     disable_sniff_mode(options.sourcemac, options.iface)

if __name__ == "__main__":
    usage = "usage: %prog [options] arg"
    parser = OptionParser(usage)
    parser.add_option(
        "-i",
        "--iface",
        dest="iface",
        default=DEFAULT_IFACE,
        help="select an interface to Enable sniff mode and sniff indicates packets",
        metavar="INTERFACE",
    )
    parser.add_option(
        "-s",
        "--source",
        dest="sourcemac",
        default=DEFAULT_SOURCEMAC,
        help="source MAC address to use",
        metavar="SOURCEMAC",
    )
    parser.add_option(
        "--epoch",
        dest="epoch",
        default=DEFAULT_EPOCH_NB,
        help="epoch number for the experiments",
    )
    parser.add_option(
        "--capture_time",
        dest="capture_time",
        default=DEFAULT_SNIFF_DURATION,
        help="capture time for the experiments",
    )
    parser.add_option(
        "-o",
        "--output_file",
        dest="output_file",
        default=DEFAULT_OUTPUT_FILE,
        help="output file for the devices recorded",
    )

    (options, args) = parser.parse_args()

    # Start the detection
    experiment1(options, False)