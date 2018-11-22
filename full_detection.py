# Copyright 2018 @ Agathe Blaise.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import ipaddress

from settings import *
from features import Feature, FEATURES
import timeit

def find_subnets(row):
    # if row['port_dst'] == 2323:
    #     ip_dst = int(ipaddress.ip_address(row['IP_dst']))
    #     seq = int(row['seq'])
    #     print(ip_dst, seq, row['IP_dst'], ipaddress.ip_address(seq).__str__())
    if row['port_src'] == 2323:
        ip_dst = int(ipaddress.ip_address(row['IP_src']))
        ack = int(row['ack'])
        print(ip_dst, ack, row['IP_src'], ipaddress.ip_address(ack).__str__())

def check_orphans(row, daily_subnets):
    """Check which packets do not belong to any identified MAWI subnetwork
    (neither source IP nor destination IP)."""
    found = False
    ip_src = ipaddress.IPv4Address(row['IP_src'])
    ip_dst = ipaddress.IPv4Address(row['IP_dst'])

    for key in daily_subnets:
        if str(key) != 'nan':
            for k in key.split('|'):
                if (ip_src in ipaddress.IPv4Network(k, strict=False)
                        or ip_dst in ipaddress.IPv4Network(k, strict=False)):
                    found = True
                    break
    if not found:
        if row['port_src'] == 2323:
            print(row['IP_src'], ipaddress.ip_address(row['ack']).__str__())
        elif row['port_dst'] == 2323:
            print(row['IP_dst'], ipaddress.ip_address(row['seq']).__str__())

def keep_wide(ip_dst, original_subnets, daily_subnets):
    """Associate the destination IP address with its desanonymized subnetwork."""
    for i, key in enumerate(daily_subnets):
        if str(key) != 'nan':
            for k in key.split('|'):
                if ipaddress.IPv4Address(ip_dst) in ipaddress.IPv4Network(k, strict=False):
                    return original_subnets[i]
    return np.nan

def retrieve_subnets(original_subnets, sub_df):
    for date in DATES:
        period = PERIOD
        # 1001 = first of October. From October to December -> 2017
        if PERIOD == 2016 and int(date) > 1000:
            period = 2015
        if PERIOD == 2017 and int(date) > 1000:
            period = 2016
        if PERIOD == 2018 and int(date) > 1000:
            period = 2017
        daily_subnets = sub_df[sub_df.date == date].iloc[0, 1:].tolist()
        chunks = pd.read_csv(path_join(PATH_CSVS, 'data', str(period) + str(date), 'csv'),
                             chunksize=N_BATCH,
                             dtype={'IP_src': object, 'IP_dst': object, 'port_src': int,
                                    'port_dst': int, 'SYN+ACK': int, 'RST+ACK': int, 'FIN+ACK': int,
                                    'SYN': int, 'ACK': int, 'RST': int, 'size': int})

        for chunk in chunks:
            print(date)
            # chunk.apply(find_subnets, axis=1)
            chunk.apply(check_orphans, args=(daily_subnets,), axis=1)
            break

def compute_metrics(files, dataframe, date, sub):
    temp_df = dataframe.groupby(['port_dst'])
    counts_dst = temp_df.size().to_frame(name='nb_packets')
    c_dst = (counts_dst
             .join(temp_df.agg({'IP_src': 'nunique'}).rename(columns={'IP_src': 'nb_src'}))
             .join(temp_df.agg({'IP_dst': 'nunique'}).rename(columns={'IP_dst': 'nb_dst'}))
             .join(temp_df.agg({'port_src': 'nunique'}))
             .join(temp_df.agg({'SYN+ACK': 'sum'}))
             .join(temp_df.agg({'RST+ACK': 'sum'}))
             .join(temp_df.agg({'FIN+ACK': 'sum'}))
             .join(temp_df.agg({'SYN': 'sum'}))
             .join(temp_df.agg({'ACK': 'sum'}))
             .join(temp_df.agg({'RST': 'sum'}))
             .join(temp_df.agg({'ttl': 'mean'}).rename(columns={'ttl': 'mean_ttl'}))
             .join(temp_df.agg({'size': 'mean'}).rename(columns={'size': 'mean_size'}))
             .join(temp_df.agg({'size': 'std'}).rename(columns={'size': 'std_size'}))
             .reset_index())

    for col in c_dst:
        if col in ['SYN+ACK', 'RST+ACK', 'FIN+ACK', 'SYN', 'ACK', 'RST']:
            c_dst[col] = c_dst[col] / c_dst['nb_packets'] * 100

    c_dst['src_div_index'] = c_dst['nb_src'] / c_dst['nb_packets'] * 100
    c_dst['dst_div_index'] = c_dst['nb_dst'] / c_dst['nb_packets'] * 100
    c_dst['port_div_index'] = c_dst['port_src'] / c_dst['nb_packets'] * 100

    # c_dst = c_dst.drop(['SYN+ACK', 'RST+ACK', 'FIN+ACK', 'ACK', 'RST', 'nb_src', 'nb_dst'], axis=1)
    c_dst = c_dst.round(2)
    c_dst.insert(0, 'date', date)
    c_dst = c_dst.rename(index=str, columns={'port_dst': 'port'})
    if sub:
        c_dst.insert(1, 'key', sub)
    file = files[1] if sub else files[0]
    c_dst.to_csv(path_or_buf=file, index=False, header=False, mode='a')

def compute_subnets(original_subnets, sub_df):
    """
    Get all traffic from a given period (2016 or 2018), divide it between subnetworks,
    then aggregate packets by port and compute feature time-series for each port in each subnetwork.
    """
    if not os.path.exists(PATH_PACKETS):
        os.mkdir(PATH_PACKETS)

    # Create one file for the whole dataset (subnets aggregated)
    # and one for subnets not aggregated (separated)
    files = [open(path_join(PATH_PACKETS, 'packets_subnets', method, PERIOD, 'csv'), 'a') for method in METHODS]
    elements = ['date', 'port', 'nb_packets', 'nb_src', 'nb_dst,' 'port_src', 'SYN+ACK', 'RST+ACK', 'FIN+ACK', 'SYN', 'ACK', 'RST', 'mean_ttl', 'mean_size', 'std_size',
                'src_div_index', 'dst_div_index', 'port_div_index']

    for file in files:
        if 'separated' in file.name:
            duplicate = elements[:]
            duplicate.insert(1, 'key')
            file.write(','.join(duplicate))
        else:
            file.write(','.join(elements))
        file.write('\n')

    for date in DATES:
        period = PERIOD
        # 1001 = first of October. From October to December -> 2017
        if PERIOD == 2016 and int(date) > 1000:
            period = 2015
        if PERIOD == 2017 and int(date) > 1000:
            period = 2016
        if PERIOD == 2018 and int(date) > 1000:
            period = 2017
        chunks = pd.read_csv(path_join(PATH_CSVS, 'data', str(period) + str(date), 'csv'),
                             chunksize=N_BATCH,
                             dtype={'IP_src': object, 'IP_dst': object, 'port_src': int,
                                    'port_dst': int, 'SYN+ACK': int, 'RST+ACK': int, 'FIN+ACK': int,
                                    'SYN': int, 'ACK': int, 'RST': int, 'size': int})

        # Find subnets of the day and put them on a list
        daily_subnets = sub_df[sub_df.date == date].iloc[0, 1:].tolist()

        for chunk in chunks:
            for method in METHODS:
                if method == 'agg':
                    packets = chunk.copy()
                    packets['IP_dst'] = chunk['IP_dst'].apply(keep_wide, args=(original_subnets,
                                                                               daily_subnets))
                    packets = packets.dropna(how='any', subset=['IP_dst'])
                    compute_metrics(files, packets, date, None)
                else:
                    # Permit to see which IP addresses do not belong to a MAWI subnetwork.
                    # chunk.apply(check_orphans, args=(daily_subnets,), axis=1)
                    chunk['subnet'] = chunk['IP_dst'].apply(keep_wide, args=(original_subnets,
                                                                             daily_subnets))
                    chunk = chunk.dropna(subset=['subnet'])
                    for sub in chunk['subnet'].unique():
                        packets = chunk.loc[chunk['subnet'] == sub]
                        compute_metrics(files, packets, date, sub)
            break

def evaluation_ports(original_subnets):
    """
    Given the port-centric features time-series, launch anomaly detection module in each subnetwork.
    Generate an evaluation file named eval_*feature* with the results.
    """

    for method in METHODS:
        packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets', method, PERIOD, 'csv'),
                              dtype={'nb_packets': int})
        packets = packets[packets.nb_packets > N_MIN]
        subnets = original_subnets if method == 'separated' else ['all']

        for feat in FEATURES:
            feat.to_write = 'port;' + ';'.join(DATES[N_DAYS:]) + '\n'

        if not os.path.exists(PATH_EVAL):
            os.mkdir(PATH_EVAL)

        ports = packets.port.unique()
        batch_size = 50

        evaluations = {}
        for ind_port, port in enumerate(ports):
            if ind_port % batch_size == 0:
                for feat in FEATURES:
                    if ind_port != 0:
                        evaluations[feat.attribute].to_csv(path_join(PATH_EVAL, 'eval', feat.attribute, method, PERIOD, T,
                                                             N_MIN, N_DAYS, 'test2', 'csv'), sep=';', mode='a')
                    if len(ports) > (ind_port + 1) * batch_size:
                        evaluations[feat.attribute] = pd.DataFrame(columns=DATES[N_DAYS:], index=ports[ind_port * batch_size: (ind_port + 1) * batch_size])
                    else:
                        evaluations[feat.attribute] = pd.DataFrame(columns=DATES[N_DAYS:], index=ports[ind_port * batch_size:])
                    evaluations[feat.attribute] = evaluations[feat.attribute].fillna('')

            packets_port = packets[packets.port == port]
            for feat in FEATURES:
                feat.reset_object()
                feat.to_write += str(port) + ';'
                for subnet in subnets:
                    del feat.time_vect[:]
                    packets_sub = (packets_port.copy() if method == 'agg'
                                   else packets_port[packets_port.key == subnet])
                    for i, date in enumerate(DATES):
                        rep = packets_sub[packets_sub.date == int(date)]
                        feat.time_vect.append(rep[feat.attribute].item()
                                              if not rep.empty else np.nan)
                        if i >= N_DAYS:
                            median = np.nanmedian(feat.time_vect[i - N_DAYS:i])
                            mad = np.nanmedian([np.abs(y - median)
                                                for y in feat.time_vect[i - N_DAYS:i]])
                            mzscore = 0.6745 * (feat.time_vect[i] - median) / mad
                            if mzscore > T:
                                evaluations[feat.attribute].loc[port, date] += '+' + subnet + ','
                            elif mzscore < - T:
                                evaluations[feat.attribute].loc[port, date] += '-' + subnet + ','

def get_nb_alarms(x):
    """Lambda function to get the number of anomalies given a list of anomalous subnets"""
    string = str(x)
    if string != 'nan':
        return '+' + str(string.count('+')) + ',-' + str(string.count('-'))
    return np.nan

def eval_scores():
    """ In evaluation ports files: convert anomalous subnets to
    number of anomalous subnets (= number of anomalies)"""
    FEATURES.append(Feature('total'))
    for feat in FEATURES:
        for method in METHODS:
            ports = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute, method, PERIOD,
                                          T, N_MIN, N_DAYS, 'csv'), sep=';', index_col=0)
            ports = ports.applymap(get_nb_alarms).dropna(axis=0, how='all')
            ports.to_csv(path_join(PATH_EVAL, 'eval', feat.attribute, method, PERIOD,
                                   T, N_MIN, N_DAYS, 'score', 'csv'), sep=';')

def main(argv):
    original_subnets, sub_df, subnets = pre_computation()
    # retrieve_subnets(original_subnets, sub_df)

    # compute_subnets(original_subnets, sub_df)
    evaluation_ports(original_subnets)
    # evaluation_ports2(original_subnets)
    # eval_scores()
    return 0

if __name__ == '__main__':
    main(sys.argv)
