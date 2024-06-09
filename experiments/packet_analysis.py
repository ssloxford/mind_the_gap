from sniffing.tools import statistics_capture_for_distance
import pprint

# Statistics capture for each distance
distances = [1, 2, 3, 4, 5]
distance_data = dict()
for i in range(len(distances)):
    distance_data = statistics_capture_for_distance(distances[i], distance_data, 10, "simple_setup_exp/passive/wireless/c3m","c3m_a1m")
pprint.pprint(distance_data)