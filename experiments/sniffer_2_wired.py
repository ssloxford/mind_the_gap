#!/usr/bin/env python3
# from prettytable import PrettyTable

import statistics
from optparse import OptionParser
import pprint
from sniffing.tools import enable_sniff_mode, disable_sniff_mode, capture_for_distance, statistics_capture_for_distance
from sniffing.constants import DEFAULT_EPOCH_NB, DEFAULT_SNIFF_DURATION, DEFAULT_IFACE, DEFAULT_SOURCEMAC, DEFAULT_OUTPUT_FILE
import os
import json

# Start by doing test with 2 sniffers on the same line
# Then do test with 2 sniffers on different lines

def experiment1(options, world=False):
    # Start detection for distance
    print(f"- EXPERIMENT SETUP 1 - WIRED SNIFFER - NOT PART OF AVLN -")
    # TODO: change for simple setup
    # folder_name = "exp1/wired" if not world else "world_exp1/wired"
    folder_name = "simple_setup_exp/passive/wired"
    distances = []

    # Enable sniff mode
    enable_sniff_mode(options.sourcemac, options.iface)

    # Capture for each distance
    while True:
        distance = input("Enter distance (in meters) to sniff for (q to stop): ")
        if distance == "q":
            break
        else:
            distances.append(distance)
            capture_for_distance(distance, options, folder_name)
    
    # Disable sniff mode at the end of the experiments
    disable_sniff_mode(options.sourcemac, options.iface)

    # Statistics capture for each distance
    # distance_data = dict()
    # for i in range(len(distances)):
    #     distance_data = statistics_capture_for_distance(distances[i], distance_data, options, folder_name)
    # pprint.pprint(distance_data)

    # Save the results
    # if options.output_file:
    #     if world:
    #         with open(os.getcwd() + f"/experiments/data/{folder_name}/wired_sniffer_" + options.output_file + ".json", "w") as f:
    #             json.dump(distance_data, f)
    #     else:
    #         with open(os.getcwd() + f"/experiments/data/{folder_name}/wired_sniffer_" + options.output_file + ".json", "w") as f:
    #             json.dump(distance_data, f)

def experiment2(options, world=False):
    # timeout 60 ping ip-to-specify
    # Start detection for distance
    print(f"- EXPERIMENT SETUP 2 (our device is pinging both machines) - WIRELESS SNIFFER - NOT PART OF AVLN -")
    # TODO: Change
    # folder_name = "exp2/wired" if not world else "world_exp2/wired"
    folder_name = "simple_setup_exp/active/wired"
    distances = []

    # Enable sniff mode
    enable_sniff_mode(options.sourcemac, options.iface)

    # Capture for each distance
    while True:
        distance = input("Enter distance (in meters) to sniff for (q to stop): ")
        if distance == "q":
            break
        else:
            distances.append(distance)
            capture_for_distance(distance, options, folder_name)
    
    # Disable sniff mode at the end of the experiments
    disable_sniff_mode(options.sourcemac, options.iface)

    # Statistics capture for each distance
    # distance_data = dict()
    # for i in range(len(distances)):
    #     distance_data = statistics_capture_for_distance(distances[i], distance_data, options, folder_name)
    # pprint.pprint(distance_data)

    # # Save the results
    # if options.output_file:
    #     if world:
    #         with open(os.getcwd() + f"/experiments/data/{folder_name}/wired_sniffer_" + options.output_file + ".json", "w") as f:
    #             json.dump(distance_data, f)
    #     else:
    #         with open(os.getcwd() + f"/experiments/data/{folder_name}/wired_sniffer_" + options.output_file + ".json", "w") as f:
    #             json.dump(distance_data, f)

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
    experiment2(options, False)