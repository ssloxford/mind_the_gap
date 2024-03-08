# Mind The Gap: Investigating the Security of HomePlug Power-Line Communication against Wireless Attacks

In this project, we want to analyse the scale of current PLC deployments, understand the attack surface and evaluate the impact of potential attacks. We create a wireless detector for PLC devices and their deployments, similarly to wardriving in the context of WiFi.

## Installation

For the installation, one must make sure that they have installed the requirements. This can be done by running:

```bash
pip install -r requirements.txt
```

Also, `tshark` is necessary to run the packet capture functions. On Debian-based distributions, it can easily be installed by running:

```bash
sudo apt install tshark
```

## Usage

When running the following commands, make sure to use the python binary from the correct virtual environment (with the correct imports) and that you are in the root directory of the repository.

We collected data and analyzed it using the script `experiments/sniffer_1_wireless.py` for the wireless sniffer, and the script `experiments/sniffer_2_wired.py` for the wired sniffer. One can specify the number of epochs for which the evaluation should be run with `--epoch` and can choose for how much time (in seconds) to run these evaluations with `--capture_time`. Finally, the output file where the results should be saved can be given with `-o` (it automatically saves into a `json` file). Here is an example of the command that can be used (same command for the wireless sniffer with `sniffer_2_wired.py`):
```bash
sudo python experiments/sniffer_1_wireless.py -i eth1 --epoch 5 --capture_time 60 -o file
```

## Extra Tool
For any device that is paired with the sniffer, it is possible to get further information about the device type, MAC address, NMK used... To do this, you can run the following command:
```bash
sudo ./plc_utils_homeplug.sh -i eth1
```