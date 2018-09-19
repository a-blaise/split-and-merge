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
import math
import os
from Settings import *
from Features import Feature, list_features

def check_orphans(row, daily_subnets):
    """Check which packets do not belong to any identified MAWI subnetwork (neither source IP nor destination IP)."""
    found = False
    IP_src = ipaddress.IPv4Address(row['IP_src'])
    IP_dst = ipaddress.IPv4Address(row['IP_dst'])

    for key in daily_subnets:
        if key != '':
            keys = key.split('|')
            for k in keys:
                if IP_src in ipaddress.IPv4Network(k, strict=False) or IP_dst in ipaddress.IPv4Network(k, strict=False):
                    found = True
                    break
    if found == False:
        print(row['IP_src'], row['IP_dst'], row['port_src'], row['port_dst'])

def keep_wide(IP_dst, original_subnets, daily_subnets):
    """Associate the destination IP address with its desanonymized subnetwork."""
    rep = np.nan
    for i, key in enumerate(daily_subnets):
        if key != '':
            keys = key.split('|')
            for k in keys:
                if ipaddress.IPv4Address(IP_dst) in ipaddress.IPv4Network(k, strict=False):
                    rep = original_subnets[i]
                    break
    return rep

def compute_subnets(subnets, original_subnets):
    """
    Get all traffic from a given period (2016 or 2018), divide it between subnetworks,
    then aggregate packets by port and compute feature time-series for each port in each subnetwork.
    """
    if not os.path.exists(PATH_PACKETS): os.mkdir(PATH_PACKETS)
    for AGG in AGGs:
        if AGG:
            with open(PATH_PACKETS + 'packets_subnets_agg_' + str(PERIOD) + '.csv', 'a') as file:
                file.write('date,port,nb_packets,port_src,SYN,mean_size,std_size,src_div_index,dst_div_index,port_div_index\n')
                file.close()
        else:
            with open(PATH_PACKETS + 'packets_subnets_separated_' + str(PERIOD) + '.csv', 'a') as file:
                file.write('date,key,port,nb_packets,port_src,SYN,mean_size,std_size,src_div_index,dst_div_index,port_div_index\n')
                file.close()

    for date in dates:
        if PERIOD == 2018 and int(date) > 1000: # 1001 = first of October. From October to December -> 2017
                chunks = pd.read_csv(PATH_CSVS + 'data_2017' + str(date) + '.csv', chunksize = N_BATCH, dtype = {'IP_src': object, 
                    'IP_dst': object, 'port_src': int, 'port_dst': int, 'SYN+ACK': int, 'RST+ACK': int, 'FIN+ACK': int, 
                    'SYN': int, 'ACK': int, 'RST': int, 'size': int})
        else:
            chunks = pd.read_csv(PATH_CSVS + 'data_' + str(PERIOD) + str(date) + '.csv', chunksize = N_BATCH, dtype = {'IP_src': object, 
                'IP_dst': object, 'port_src': int, 'port_dst': int, 'SYN+ACK': int, 'RST+ACK': int, 'FIN+ACK': int, 
                'SYN': int, 'ACK': int, 'RST': int, 'size': int})
        
        # Find subnets of the day and put them on a list
        daily_subnets = []

        for k in subnets.values():
            l = list(k.keys())
            for el in l:
                if date in el:
                    day_subnets.append(el.split('-')[0])

        tab_columns = [['IP_src', 'nunique', 'nb_src'], ['IP_dst', 'nunique', 'nb_dst'], ['port_src', 'nunique'],
            ['SYN+ACK', 'sum'], ['RST+ACK', 'sum'], ['FIN+ACK', 'sum'], ['SYN', 'sum'], ['ACK', 'sum'], ['RST', 'sum'],
            ['size', 'mean', 'mean_size'], ['size', 'std', 'sts_size']]

        for chunk in chunks:
            for AGG in AGGs:
                if AGG:
                    value = chunk.copy()
                    value['IP_dst'] = value['IP_dst'].apply(keep_wide, args=(original_subnets, daily_subnets))
                    value = value.dropna(how='any', subset=['IP_dst'])
                    if value.empty == False:
                        dataset_agg_dst = value.groupby(['port_dst'])
                        counts_dst = dataset_agg_dst.size().to_frame(name='nb_packets')
                        c_dst = (counts_dst
                            .join(dataset_agg_dst.agg({'IP_src': 'nunique'}).rename(columns={'IP_src': 'nb_src'}))
                            .join(dataset_agg_dst.agg({'IP_dst': 'nunique'}).rename(columns={'IP_dst': 'nb_dst'}))
                            .join(dataset_agg_dst.agg({'port_src': 'nunique'}))
                            .join(dataset_agg_dst.agg({'SYN+ACK': 'sum'}))
                            .join(dataset_agg_dst.agg({'RST+ACK': 'sum'}))
                            .join(dataset_agg_dst.agg({'FIN+ACK': 'sum'}))
                            .join(dataset_agg_dst.agg({'SYN': 'sum'}))
                            .join(dataset_agg_dst.agg({'ACK': 'sum'}))
                            .join(dataset_agg_dst.agg({'RST': 'sum'}))
                            .join(dataset_agg_dst.agg({'size': 'mean'}).rename(columns={'size': 'mean_size'}))
                            .join(dataset_agg_dst.agg({'size': 'std'}).rename(columns={'size': 'std_size'}))
                            .reset_index())
                    for col in c_dst:
                        if col in ['SYN+ACK', 'RST+ACK', 'FIN+ACK', 'SYN', 'ACK', 'RST']:
                            c_dst[col] = c_dst[col] / c_dst['nb_packets'] * 100
                    
                    c_dst['src_div_index'] = c_dst['nb_src'] / c_dst['nb_packets'] * 100
                    c_dst['dst_div_index'] = c_dst['nb_dst'] / c_dst['nb_packets'] * 100
                    c_dst['port_div_index'] = c_dst['port_src'] / c_dst['nb_packets'] * 100

                    c_dst = c_dst.round(2)
                    c_dst.insert(0, 'date', date)
                    c_dst = c_dst.drop(['SYN+ACK', 'RST+ACK', 'FIN+ACK', 'ACK', 'RST', 'nb_src', 'nb_dst'], axis=1)
                    c_dst = c_dst.rename(index=str, columns={'port_dst': 'port'})
                    c_dst.to_csv(path_or_buf=PATH_PACKETS + 'packets_subnets_agg_' + str(PERIOD) + '.csv', index=False, header=False, mode='a')
                else:
                    # Facultative line: permits to see which IP addresses do not belong to a desanonymised MAWI subnetwork.
                    # chunk.apply(check_orphans, args=(daily_subnets,), axis=1)
                    chunk['sub'] = chunk['IP_dst'].apply(keep_wide, args=(original_subnets, daily_subnets))
                    chunk = chunk.dropna(subset=['sub'])
                    for sub in chunk['sub'].unique():
                        df = chunk.loc[chunk['sub'] == sub]
                        df = df.groupby(['port_dst'])
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
                        c_dst.insert(1, 'key', sub)
                        c_dst = c_dst.rename(index=str, columns={'port_dst': 'port'})
                        c_dst.to_csv(path_or_buf=PATH_PACKETS + 'packets_subnets_separated_' + str(PERIOD) + '.csv', index=False, header=False, mode='a')
            break

def evaluation_ports(original_subnets):
    """
    Given the port-centric features time-series, launch anomaly detection module in each subnetwork.
    Generate an evaluation file named eval_*feature* with the results.
    """
    value = pd.DataFrame()

    for AGG in AGGs:
        for feat in list_features:
            feat.reset_object()
        if AGG:
            prefix = '_agg'
        else:            
            prefix = '_separated'
        value = pd.read_csv(PATH_PACKETS + 'packets_subnets' + prefix + '_' + str(PERIOD) + '.csv', dtype = {'nb_packets': int})
        value = value[value.nb_packets > N_MIN]

        for feat in list_features:
            feat.to_write = 'port;' + ';'.join(dates[N_DAYS:]) + '\n'

        if not os.path.exists(PATH_EVAL):
            os.mkdir(PATH_EVAL)
        with open(PATH_EVAL + 'eval_total' + prefix + '_' + str(PERIOD) + '_' + str(T) + '_' + str(N_MIN) + '.csv', 'a') as file:
            file.write('port;' + ';'.join(dates[N_DAYS:]) + '\n')

        ports = set(value.port.tolist())
        string_total = ''
        for p in list(ports):
            for feat in list_features:
                feat.reset_object()
            if AGG:
                for date in dates:
                    rep = value[(value.date == int(date)) & (value.port == p)]
                    for feat in list_features:
                        if rep.empty == False:
                            feat.time_vect.append(rep[feat.attribute].item())
                        else:
                            feat.time_vect.append(np.nan)
                for feat in list_features:
                    feat.sub_time_vect['all'] = feat.time_vect[:]
            else:
                for subnet in original_subnets:
                    for date in dates:
                        rep = value[(value.date == int(date)) & (value.key == subnet) & (value.port == p)]
                        for feat in list_features:
                            if rep.empty == False:
                                feat.time_vect.append(rep[feat.attribute].item())
                            else:
                                feat.time_vect.append(np.nan)
                    for feat in list_features:
                        feat.sub_time_vect[subnet] = feat.time_vect[:]
                        del feat.time_vect[:]

            string_total = string_total + str(p) + ';'
            mzscores_total = {}
            for i in range(N_DAYS, len(dates)):
                mzscores_total[dates[i]] = ''
            for feat in list_features:
                feat.to_write = feat.to_write + str(p) + ';'
                for i in range(N_DAYS, len(dates)):
                    for k, v in feat.sub_time_vect.items():
                        if math.isnan(v[i]) == False:
                            # The nb_packets feature is a specific case and enables only to identify emerging ports
                            if feat.attribute == 'nb_packets':
                                if v[i - N_DAYS:i] == [np.nan] * len(v[i - N_DAYS:i]):
                                    feat.mzscores[dates[i]] +='+' + k + ','
                            else:
                                median = np.nanmedian(v[i - N_DAYS:i])
                                median_absolute_deviation = np.nanmedian([np.abs(y - median) for y in v[i - N_DAYS:i]])
                                mzscore = 0.6745 * (v[i] - median) / median_absolute_deviation
                                if mzscore > T:
                                    feat.mzscores[dates[i]] += '+' + k + ','
                                elif mzscore < - T:
                                    feat.mzscores[dates[i]] += '-' + k + ','
                    if feat.attribute != 'nb_packets':
                        mzscores_total[dates[i]] += feat.mzscores[dates[i]]
                feat.to_write = feat.to_write + ';'.join([el[:-1] for el in feat.mzscores.values()]) + '\n'
            string_total = string_total + ';'.join([el[:-1] for el in mzscores_total.values()]) + '\n'

        # Generate one evaluation file per feature.
        for feat in list_features:
            with open(PATH_EVAL + 'eval_' + feat.attribute + prefix + '_' + str(PERIOD) + '_' + str(T) + '_' + str(N_MIN) + '.csv', 'a') as file_feature:
                file_feature.write(feat.to_write)
                file_feature.close()

        # eval_total contains the total of the results for all features.
        with open(PATH_EVAL + 'eval_total' + prefix + '_' + str(PERIOD) + '_' + str(T) + '_' + str(N_MIN) + '.csv', 'a') as file:
            file.write(string_total)
            file.close()

def get_nb_alarms(x):
    """Lambda function to get the number of anomalies given a list of anomalous subnets"""
    if str(x) != 'nan':
        return '+' + str(str(x).count('-')) + ',-' + str(str(x).count('-'))
    return np.nan

def eval_scores():
    """ In evaluation ports files: convert anomalous subnets to number of anomalous subnets (= number of anomalies)"""
    list_features.append(Feature('total'))
    for feat in list_features:
        for AGG in AGGs:
            prefix = '_separated'
            if AGG:
                prefix = '_agg'
            ports = pd.read_csv(PATH_EVAL + 'eval_' + feat.attribute + prefix + '_' + str(PERIOD) + '_' + str(T) + '_' 
                + str(N_MIN) + '.csv', sep=';', index_col=0)
            ports = ports.applymap(get_nb_alarms).dropna(axis=0, how='all')
            ports.to_csv(PATH_EVAL + 'eval_' + feat.attribute + prefix + '_' + str(PERIOD) + '_' + str(T) + '_' 
                + str(N_MIN) + '_score_test2.csv', sep = ';')

def main(argv):
    subnets = {}
    original_subnets = []

    sub_df = pd.read_csv(PATH_SUBNETS + 'subnets_' + str(PERIOD) + '.csv', index_col=0, sep=',')
    if PERIOD == 2018:
        sub_df = sub_df.append(pd.read_csv(PATH_SUBNETS + 'subnets_2017.csv', index_col=0, sep=',')) # add last months of 2017 if 2018 period

    for subnet in sub_df.columns:
        if subnet not in subnets:
            subnets[subnet] = {}
        for date in sub_df.index:
            rep = str(sub_df.loc[date][subnet])
            if len(str(date)) == 3:
                date = '0' + str(date)
            if rep != 'nan':
                subnets[subnet][rep + '-' + str(date)] = pd.DataFrame()
            else:
                subnets[subnet]['-' + str(date)] = pd.DataFrame()

    original_subnets = list(subnets.keys())

    compute_subnets(subnets, original_subnets)
    evaluation_ports(original_subnets)
    eval_scores()
    return 0

if __name__ == "__main__":
    main(sys.argv)