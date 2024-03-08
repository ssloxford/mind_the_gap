# CONSTANTS


################### CONSTANTS ###################

# HomePlugAV Specification
MAC_ADDRESS_BENTRY_HEADER = "03"
MAC_ADDRESS_BENTRY_LENGTH = "06"
DELIMETER_TYPES = {
    "0x00": "BEACON",
    "0x01": "SOF",
    "0x02": "SACK",
    "0x04": "SOUND",
    "0x05": "REVERSE_SOF",
    "0x03": "RTS_CTS"
}


BEACON_DELIMITER_TYPE = "0x00"
SOF_DELIMITER_TYPE = "0x01"
DEFAULT_NIDs = {"0x00b0f2e695666b03": "HomePlugAV", "0x00026bcba5354e08": "HomePlugAV0123"}

# Default interface and source MAC address
DEFAULT_IFACE = "eth0"
DEFAULT_SOURCEMAC = "BC:F2:AF:F1:CC:32"

#### Experiments Options ####
DEFAULT_EPOCH_NB = 10

# Mapping between entry headers and their corresponding descriptions
HEADER_MAPPING = {
    "00": "Non-Persistent Schedule BENTRY",
    "01": "Persistent Schedule BENTRY",
    "02": "Regions BENTRY",
    "03": "MAC Address BENTRY",
    "04": "Discover BENTRY",
    "05": "Discovered Info BENTRY",
    "06": "Beacon Period Start Time Offset BENTRY",
    "07": "Encryption Key Change BENTRY",
    "08": "CCo Handover BENTRY",
    "09": "Beacon Relocation BENTRY",
    "0A": "AC Line Sync Countdown BENTRY",
    "0B": "Change NumSlots BENTRY",
    "0C": "Change HM BENTRY",
    "0D": "Change SNID BENTRY",
    "0E": "RSN Information Element BENTRY (Reserved for IEEE 1901)",
    "0F": "ISP BENTRY (Reserved for IEEE 1901)",
    "10": "Extended Band Stay Out BENTRY (Reserved for IEEE 1901)",
    "11": "AG Assignment BENTRY (Reserved for IEEE 1901)",
    "12": "Extended Carriers Support BENTRY (Reserved for IEEE 1901)",
    "13": "Power Save BENTRY",
    "14-F7": "Reserved for future use",
    "F8": "Vendor-Specific BENTRY",
    "F9": "Vendor-Specific BENTRY",
    "FA": "Vendor-Specific BENTRY",
    "FB": "Vendor-Specific BENTRY",
    "FC": "Vendor-Specific BENTRY",
    "FD": "Vendor-Specific BENTRY",
    "FE": "Vendor-Specific BENTRY",
    "FF": "Vendor-Specific BENTRY",
}

#### Capture Options ####
DEFAULT_NO_GPS = False
DEFAULT_VERBOSE = 0

# Time delta for network ID encounters (in seconds)
DEFAULT_ENCOUNTER_DELTA = 1

# Time allowed for sniffing (in seconds)
DEFAULT_SNIFF_DURATION = 300

# Output file of device recording
DEFAULT_OUTPUT_FILE = None
