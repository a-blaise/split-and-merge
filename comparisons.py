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
import os
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

from Settings import *
from Features import Feature, list_features
from full_detection import path_join

def anomalies_ndays(subnets, nb_days):
    # regarder pourquoi 15 et 20 jours: exactement les mêmes anomalies?
    packets = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'), dtype = {'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]
    ports = packets.port.unique()

    # Compute anomalies by varying the number of days in the model
    files = {}
    for nb_day in nb_days:
        files[nb_day] = open(path_join([PATH_EVAL, 'anomalies', 'N_DAYS', nb_day, 'full'], 'txt'), 'a')
    ano_per_day = dict.fromkeys(nb_days, {})

    LEN_PERIOD = 10
    # count anomalies by each port / date
    for p in ports:
        packets_port = packets[packets.port == p]
        tmp_anomalies = {} # key = port | date | nb_day ; value = int (nb occurrences)
        for feat in list_features:
            feat.reset_object()
            for subnet in subnets:
                del feat.time_vect[:]
                packets_sub = packets_port[packets_port.key == subnet]
                for i, date in enumerate(dates):
                    rep = packets_sub[packets_sub.date == int(date)]
                    if not rep.empty:
                        feat.time_vect.append(rep[feat.attribute].item())
                    else:
                        feat.time_vect.append(np.nan)

                    if i > len(dates) - LEN_PERIOD:
                        for nb_day in nb_days:
                            median = np.nanmedian(feat.time_vect[i - nb_day:i])
                            median_absolute_deviation = np.nanmedian([np.abs(y - median) for y in feat.time_vect[i - nb_day:i]])
                            mzscore = 0.6745 * (feat.time_vect[i] - median) / median_absolute_deviation
                            if np.abs(mzscore) > T:
                                id_anomaly = '|'.join([str(p), date, str(nb_day)])
                                if id_anomaly in tmp_anomalies:
                                    tmp_anomalies[id_anomaly] += 1
                                else:
                                    tmp_anomalies[id_anomaly] = 1
        for id_anomaly, nb_occur in tmp_anomalies.items():
            if nb_occur > THRESHOLD_ANO:
                n_day = int(id_anomaly.split('|')[-1])
                new_id = '|'.join(id_anomaly.split('|')[:2])
                ano_per_day[n_day][new_id] = nb_occur
                files[n_day].write(new_id + ',')

def anomalies_nmins(subnets, nb_mins):
    files = {}
    for nb_min in nb_mins:
        files[nb_min] = open(path_join([PATH_EVAL, 'anomalies', 'N_MINS', nb_min], 'txt'), 'a')
    ano_per_day = dict.fromkeys(nb_mins, {})

    packets = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'), dtype = {'nb_packets': int})
    for nb_min in nb_mins:
        packets = packets[packets.nb_packets > nb_min]
        ports = packets.port.unique()

        # count anomalies by each port / date
        for p in ports:
            packets_port = packets[pakkmckets.port == p]
            tmp_anomalies = {} # key = port | date | nb_min ; value = int (nb occurrences)
            for feat in list_features:
                feat.reset_object()
                for subnet in subnets:
                    del feat.time_vect[:]
                    packets_sub = packets_port[packets_port.key == subnet]
                    for i, date in enumerate(dates):
                        rep = packets_sub[packets_sub.date == int(date)]
                        if not rep.empty:
                            feat.time_vect.append(rep[feat.attribute].item())
                        else:
                            feat.time_vect.append(np.nan)

                        if i > N_DAYS:
                            median = np.nanmedian(feat.time_vect[i - N_DAYS:i])
                            median_absolute_deviation = np.nanmedian([np.abs(y - median) for y in feat.time_vect[i - N_DAYS:i]])
                            mzscore = 0.6745 * (feat.time_vect[i] - median) / median_absolute_deviation
                            if np.abs(mzscore) > T:
                                id_anomaly = '|'.join([str(p), date, str(nb_min)])
                                if id_anomaly in tmp_anomalies:
                                    tmp_anomalies[id_anomaly] += 1
                                else:
                                    tmp_anomalies[id_anomaly] = 1
            for id_anomaly, nb_occur in tmp_anomalies.items():
                if nb_occur > THRESHOLD_ANO:
                    n_min = int(id_anomaly.split('|')[-1])
                    new_id = '|'.join(id_anomaly.split('|')[:2])
                    ano_per_day[n_min][new_id] = nb_occur
                    files[n_min].write(new_id + ',')

def comparison(type_comparison, baseline, intervals):
    files = {}
    ano = dict.fromkeys(intervals, {})

    for item in intervals:
        files[item] = open(path_join([PATH_EVAL, 'ano_days', item], 'txt'), 'r')
        l = files[item].read()
        ano[item] = l.split(',')

    elements_under = {} # key: item (except 10), value: elements in baseline and not here
    elements_over = {} # same with elements in + compared to baseline

    # Compare anomalies seen for each day with the baseline
    baseline_anomalies = ano[baseline] # list of anomalies
    for interval, anomalies in ano.items():
        if interval != baseline:
            elements_over[interval] = []
            elements_under[interval] = []
            for item in anomalies:
                if item not in baseline_anomalies:
                    elements_over[interval].append(item)
            for item in baseline_anomalies:
                if item not in anomalies:
                    elements_under[interval].append(item)

    list_over = []
    list_under = []

    for interval in intervals:
        if interval in elements_over:
            list_over.append(len(elements_over[interval]))
        else:
            list_over.append(0)
        if interval in elements_under:
            list_under.append(- len(elements_under[interval]))
        else:
            list_under.append(0)

    fig, ax = plt.subplots()
    ax.bar(intervals, list_over)
    ax.bar(intervals, list_under)
    ax.set_xticks(intervals)
    ax.set_xlabel(type_comparison)
    ax.set_ylabel('Number of anomalies in +/- compared to baseline')
    plt.show()
    fig.savefig(path_join([PATH_FIGURES, 'comparison', type_comparison, THRESHOLD_ANO], 'png'), dpi=300)

def main(argv):
    sub_df = pd.read_csv(path_join([PATH_SUBNETS, 'subnets', PERIOD], 'csv'), dtype={'date': str})
    original_subnets = sub_df.columns[1:].tolist()

    if PERIOD == 2018:
        sub_df = sub_df.append(pd.read_csv(path_join([PATH_SUBNETS, 'subnets_2017'], 'csv'), dtype={'date': str})) # add last months of 2017 if 2018 period

    subnets = dict.fromkeys(original_subnets, {})
    for subnet, date in zip(original_subnets, sub_df['date']):
        new_subnet = sub_df[sub_df.date == date][subnet].item()
        subnets[subnet][str(new_subnet) + '-' + date] = pd.DataFrame()

    baseline_day = 10
    nb_days = [3, 5, 8, 10, 13, 15, 18, 20, 23]

    baseline_min = 20
    nb_mins = [20, 35, 50, 65, 80, 100]

    # anomalies_ndays(subnets, nb_days)
    # anomalies_nmins(subnets, nb_mins)

    comparison('N_DAYS', baseline_day, nb_days)
    # comparison('N_MINS', baseline_min, nb_mins)

if __name__ == '__main__':
    main(sys.argv)