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

import sys
import pandas as pd
import ipaddress
import numpy as np
import os
from Settings import *
from Features import Feature, list_features
import matplotlib.pyplot as plt

def path_join(parts, extension):
    return parts[0] + '_'.join(map(str, parts[1:])) + '.' + extension

def check_orphans(row, daily_subnets):
    """Check which packets do not belong to any identified MAWI subnetwork (neither source IP nor destination IP)."""
    found = False
    IP_src = ipaddress.IPv4Address(row['IP_src'])
    IP_dst = ipaddress.IPv4Address(row['IP_dst'])

    for key in daily_subnets:
        if str(key) != 'nan':
            for k in key.split('|'):
                if IP_src in ipaddress.IPv4Network(k, strict=False) or IP_dst in ipaddress.IPv4Network(k, strict=False):
                    found = True
                    break
    if not found:
        print(row['IP_src'], row['IP_dst'], row['port_src'], row['port_dst'])

# dont forget to rollback keep_Wide: this version doesnt work yet
def keep_wide(IP_dst, original_subnets, daily_subnets):
    """Associate the destination IP address with its desanonymized subnetwork."""
    for i, key in enumerate(daily_subnets):
        if str(key) != 'nan':
            for k in key.split('|'):
                if ipaddress.IPv4Address(IP_dst) in ipaddress.IPv4Network(k, strict=False):
                    return original_subnets[i]
    return np.nan

def compute_metrics(files, dataframe, date, sub):
    df = dataframe.groupby(['port_dst'])
    counts_dst = df.size().to_frame(name='nb_packets')
    c_dst = (counts_dst
        .join(df.agg({'IP_src': 'nunique'}).rename(columns={'IP_src': 'nb_src'}))
        .join(df.agg({'IP_dst': 'nunique'}).rename(columns={'IP_dst': 'nb_dst'}))
        .join(df.agg({'port_src': 'nunique'}))
        .join(df.agg({'SYN+ACK': 'sum'}))
        .join(df.agg({'RST+ACK': 'sum'}))
        .join(df.agg({'FIN+ACK': 'sum'}))
        .join(df.agg({'SYN': 'sum'}))
        .join(df.agg({'ACK': 'sum'}))
        .join(df.agg({'RST': 'sum'}))
        .join(df.agg({'size': 'mean'}).rename(columns={'size': 'mean_size'}))
        .join(df.agg({'size': 'std'}).rename(columns={'size': 'std_size'}))
        .reset_index())

    for col in c_dst:
        if col in ['SYN+ACK', 'RST+ACK', 'FIN+ACK', 'SYN', 'ACK', 'RST']:
            c_dst[col] = c_dst[col] / c_dst['nb_packets'] * 100

    c_dst['src_div_index'] = c_dst['nb_src'] / c_dst['nb_packets'] * 100
    c_dst['dst_div_index'] = c_dst['nb_dst'] / c_dst['nb_packets'] * 100
    c_dst['port_div_index'] = c_dst['port_src'] / c_dst['nb_packets'] * 100

    c_dst = c_dst.drop(['SYN+ACK', 'RST+ACK', 'FIN+ACK', 'ACK', 'RST', 'nb_src', 'nb_dst'], axis=1)
    c_dst = c_dst.round(2)
    c_dst.insert(0, 'date', date)
    c_dst = c_dst.rename(index=str, columns={'port_dst': 'port'})
    if sub:
        c_dst.insert(1, 'key', sub)
        file = files[0]    
    else:
        file = files[1]
    c_dst.to_csv(path_or_buf=file, index=False, header=False, mode='a')

def compute_subnets(original_subnets, sub_df):
    """
    Get all traffic from a given period (2016 or 2018), divide it between subnetworks,
    then aggregate packets by port and compute feature time-series for each port in each subnetwork.
    """
    if not os.path.exists(PATH_PACKETS): os.mkdir(PATH_PACKETS)

    # Create one file for the whole dataset (subnets aggregated) and one for subnets not aggregated (separated)
    files = [open(path_join([PATH_PACKETS, 'packets_subnets', method, PERIOD, 'test'], 'csv'), 'a') for method in METHODS]
    elements = ['date', 'port', 'nb_packets', 'port_src', 'SYN', 'mean_size', 'std_size', 'src_div_index', 'dst_div_index', 'port_div_index']
    
    for file in files:
        if 'separated' in file.name:
            duplicate = elements[:]
            duplicate.insert(1, 'key')
            file.write(','.join(duplicate))
        else:
            file.write(','.join(elements))

    types = {'IP_src': object, 'IP_dst': object, 'port_src': int, 'port_dst': int, 'SYN+ACK': int, 'RST+ACK': int, 'FIN+ACK': int,
        'SYN': int, 'ACK': int, 'RST': int, 'size': int}

    for date in dates:
        if PERIOD == 2018 and int(date) > 1000: # 1001 = first of October. From October to December -> 2017
            chunks = pd.read_csv(path_join([PATH_CSVS, 'data_2017' + str(date)], 'csv'), chunksize = N_BATCH, dtype = types)
        else:
            chunks = pd.read_csv(path_join([PATH_CSVS, 'data', str(PERIOD) + str(date)], 'csv'), chunksize = N_BATCH, dtype = types)
        
        # Find subnets of the day and put them on a list
        daily_subnets = sub_df[sub_df.date == date].iloc[0, 1:].tolist()

        for chunk in chunks:
            # for both approaches: subnets aggregated and separated
            for method in METHODS:
                if method == 'aggregated':
                    packets = chunk.copy()
                    packets['IP_dst'] = chunk['IP_dst'].apply(keep_wide, args=(original_subnets, daily_subnets))
                    packets = packets.dropna(how='any', subset=['IP_dst'])
                    compute_metrics(files, packets, date, None)
                else:
                    # Facultative line: permits to see which IP addresses do not belong to a desanonymised MAWI subnetwork.
                    # chunk.apply(check_orphans, args=(daily_subnets,), axis=1)
                    chunk['subnet'] = chunk['IP_dst'].apply(keep_wide, args=(original_subnets, daily_subnets))
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
        packets = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets', method, PERIOD], 'csv'), dtype = {'nb_packets': int})
        packets = packets[packets.nb_packets > N_MIN]

        if method == 'aggregated':
            subnets = ['all']
        else:
            subnets = original_subnets

        for feat in list_features:
            feat.to_write = 'port;' + ';'.join(dates[N_DAYS:]) + '\n'

        # if not os.path.exists(PATH_EVAL): os.mkdir(PATH_EVAL)
        # with open(path_join([PATH_EVAL, 'eval_total', method, PERIOD, T, N_MIN, N_DAYS], 'csv'), 'a') as file:
        #     file.write('port;' + ';'.join(dates[N_DAYS:]) + '\n')

        ports = packets.port.unique()
        for p in ports:
            mzscores_total = dict.fromkeys(dates[N_DAYS:], '')
            packets_port = packets[packets.port == p]
            
            for feat in list_features:
                feat.reset_object()
                feat.to_write += str(p) + ';'
                for subnet in subnets:
                    del feat.time_vect[:]
                    if method == 'aggregated':
                        packets_sub = packets_port.copy()
                    else:
                        packets_sub = packets_port[packets_port.key == subnet]
                    for i, date in enumerate(dates):
                        rep = packets_sub[packets_sub.date == int(date)]
                        if not rep.empty:
                            feat.time_vect.append(rep[feat.attribute].item())
                        else:
                            feat.time_vect.append(np.nan)
                        if i > N_DAYS:
                            if feat.attribute == 'nb_packets':
                                if np.isnan(np.sum(feat.time_vect[i - N_DAYS:i])):
                                    feat.mzscores[date] += '+' + subnet + ','
                            else:
                                median = np.nanmedian(feat.time_vect[i - N_DAYS:i])
                                median_absolute_deviation = np.nanmedian([np.abs(y - median) for y in feat.time_vect[i - N_DAYS:i]])
                                mzscore = 0.6745 * (feat.time_vect[i] - median) / median_absolute_deviation
                                if mzscore > T:
                                    feat.mzscores[date] += '+' + subnet + ','
                                elif mzscore < - T:
                                    feat.mzscores[date] += '-' + subnet + ','
                        if method != 'aggregated' and feat.attribute != 'nb_packets':
                            mzscores_total[date] += feat.mzscores[date]
                feat.to_write = feat.to_write + ';'.join([el[:-1] for el in feat.mzscores.values()]) + '\n'

        # for feat in list_features:
        #     with open(path_join([PATH_EVAL, 'eval', feat.attribute, method, PERIOD, T, N_MIN, N_DAYS], 'csv'), 'a') as file_feature:
        #         file_feature.write(feat.to_write)
        #         file_feature.close()

def get_nb_alarms(x):
    """Lambda function to get the number of anomalies given a list of anomalous subnets"""
    string = str(x)
    if string != 'nan':
        return '+' + str(string.count('+')) + ',-' + str(string.count('-'))
    return np.nan

def eval_scores():
    """ In evaluation ports files: convert anomalous subnets to number of anomalous subnets (= number of anomalies)"""
    list_features.append(Feature('total'))
    for feat, method in zip(list_features, METHODS):
        ports = pd.read_csv(path_join([PATH_EVAL, 'eval', feat.attribute, method, PERIOD, T, N_MIN, N_DAYS], 'csv'), sep=';', index_col=0)
        ports = ports.applymap(get_nb_alarms).dropna(axis=0, how='all')
        ports.to_csv(path_join([PATH_EVAL, 'eval', feat.attribute, method, PERIOD, T, N_MIN, N_DAYS, 'score'], 'csv'), sep=';')

def main(argv):
    sub_df = pd.read_csv(path_join([PATH_SUBNETS, 'subnets', PERIOD], 'csv'), dtype={'date': str})
    original_subnets = sub_df.columns[1:].tolist()

    if PERIOD == 2018:
        sub_df = sub_df.append(pd.read_csv(path_join([PATH_SUBNETS, 'subnets_2017'], 'csv'), dtype={'date': str})) # add last months of 2017 if 2018 period

    subnets = dict.fromkeys(original_subnets, {})
    for subnet, date in zip(original_subnets, sub_df['date']):
        new_subnet = sub_df[sub_df.date == date][subnet].item()
        subnets[subnet][str(new_subnet) + '-' + date] = pd.DataFrame()

    compute_subnets(original_subnets, sub_df)
    # evaluation_ports(original_subnets)
    # eval_scores()
    # compute_mse_feature(original_subnets)
    return 0

if __name__ == '__main__':
    main(sys.argv)