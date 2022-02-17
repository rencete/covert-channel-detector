import scapy.all as scapy
import pandas as pd
from os import access, R_OK
from os.path import isfile
from lib.feature_engineering import extract_feature
from sklearn.model_selection import train_test_split


def check_file_readable(*filenames_lists, verbosity=0):
    errors = 0
    for pcap_files in filenames_lists:
        for pcap_file in pcap_files:
            if not (isfile(pcap_file) and access(pcap_file, R_OK)):
                errors += 1
                print(
                    "Error: pcap file '{}' is not a file or is not readable".format(pcap_file)
                )
        if errors > 0:
            if verbosity >= 1:
                print("Program cannot proceed, please check pcap file(s) specified.")
                print("Exiting...")
            exit()
    return 0 if errors == 0 else 1


def read_pcap_packets(pcap_filename, packet_count=-1):
    packets = scapy.rdpcap(pcap_filename, count=packet_count)
    return packets


def get_read_count(current_count, maximum=-1, file_count=-1):
    result = file_count
    if maximum >= 0:
        if current_count >= maximum:
            result = 0
        else:
            result = maximum - current_count

        if file_count >= 0 and result > file_count:
             result = file_count

    return result


def read_data(pcap_files, maximum_count=-1, file_count=-1, verbosity=0, covert=0, test_size=0.0):
    train = pd.DataFrame()
    test = pd.DataFrame()

    for file in pcap_files:
        read_count = get_read_count(len(train) + len(test), maximum=maximum_count, file_count=file_count)
        packets = read_pcap_packets(file, read_count)

        if verbosity >= 2:
            print("File {} processed, read {} packets".format(file, len(packets)))

        # Convert to DataFrame
        df = packets_to_dataframe(packets, covert)

        # Split into train and test
        train_split, test_split = train_test_split(df, test_size=test_size)
        train = pd.concat([train, train_split], axis=0, ignore_index=True)
        test = pd.concat([test, test_split], axis=0, ignore_index=True)

    return (train, test)


def read_pcap_files(pcap_files, maximum_count=-1, file_count=-1, verbosity=0):
    all_packets = []
    for file in pcap_files:
        read_count = get_read_count(len(all_packets), maximum=maximum_count, file_count=file_count)
        packets = read_pcap_packets(file, read_count)

        if verbosity >= 2:
            print("File {} processed, read {} packets".format(file, len(packets)))

        all_packets += packets
    return all_packets


def packets_to_dicts(packets: scapy.PacketList):
    results = []
    if len(packets) > 0:
        results = [extract_feature(packet) for packet in packets]
    return results


def add_column_to_dataframe(df, col_name, col_value):
    result = df
    result[col_name] = col_value
    return result


def add_cols_to_dataframe(df, covert_value):
    add_column_to_dataframe(df, "is_covert", covert_value)


def packets_to_dataframe(packets, covert_value=0):
    dataframe = pd.DataFrame(packets_to_dicts(packets))
    add_cols_to_dataframe(dataframe, covert_value)
    return dataframe


def randomize_dataframe(dataframe):
    randomized = pd.concat(dataframe, ignore_index=True).sample(frac=1)
    return randomized