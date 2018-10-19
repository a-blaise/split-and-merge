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
from itertools import chain
from matplotlib.ticker import MaxNLocator

from Settings import *
from Features import Feature, list_features
from full_detection import path_join, pre_computation

def anomalies_ndays(subnets, nb_days):
    chunks = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'), dtype = {'nb_packets': int}, chunksize=N_BATCH)
    for chunk in chunks:
        packets = chunk[chunk.nb_packets > N_MIN]
        ports = packets.port.unique()
        break

    # Compute anomalies by varying the number of days in the model
    files = {}
    for nb_day in nb_days:
        files[nb_day] = open(path_join([PATH_EVAL, 'anomalies', 'N_DAYS', nb_day, 'test2'], 'txt'), 'a')

    LEN_PERIOD = 10
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
            n_day = int(id_anomaly.split('|')[-1])
            new_id = '|'.join(id_anomaly.split('|')[:2])
            files[n_day].write(new_id + '|' + str(nb_occur) + ',')

def anomalies_nmins(subnets, nb_mins):
    files = {}
    for nb_min in nb_mins:
        files[nb_min] = open(path_join([PATH_EVAL, 'anomalies', 'N_MINS', nb_min], 'txt'), 'a')

    packets = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'), dtype = {'nb_packets': int})
    for nb_min in nb_mins:
        packets = packets[packets.nb_packets > nb_min]
        ports = packets.port.unique()

        # count anomalies by each port / date
        for p in ports:
            packets_port = packets[packets.port == p]
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
                    files[n_min].write(new_id + ',')

def plot_results(type_comparison, intervals):
    files = {}
    nb_anomalies = dict.fromkeys(intervals, 0)

    for interval in intervals:
        files[interval] = open(path_join([PATH_EVAL, 'ano', type_comparison, interval], 'txt'), 'r')
        elements = files[interval].read()
        files[interval].close()
        nb_anomalies[interval] = len(elements.split(','))

    fig, ax = plt.subplots()
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    BIN_WIDTH = 0.8
    if type_comparison == 'N_MINS':
        BIN_WIDTH = 4
    ax.bar(intervals, list(nb_anomalies.values()), width=BIN_WIDTH)
    ax.set_xticks(intervals)
    if type_comparison == 'N_DAYS':
        ax.set_xlabel('Number of days in the model (N_DAYS)')
    else:
        ax.set_xlabel('Minimum number of packets to keep the port (N_MIN)')
    ax.set_ylabel('Number of anomalies for this parameter')
    fig.savefig(path_join([PATH_FIGURES, 'results', type_comparison, THRESHOLD_ANO], 'png'), dpi=300)

def comparison(type_comparison, baseline, intervals):
    files = {}
    anomalies = dict.fromkeys(intervals, {})

    for interval in intervals:
        files[interval] = open(path_join([PATH_EVAL, 'ano', type_comparison, interval], 'txt'), 'r')
        elements = files[interval].read()
        files[interval].close()
        anomalies[interval] = elements.split(',')

    # Compare anomalies seen for each day with the baseline
    baseline_anomalies = anomalies[baseline] # list of anomalies
    list_over, list_under = ([] for i in range(2))

    for interval, anomalies in anomalies.items():
        if interval != baseline:
            list_over.append(len([item for item in anomalies if item not in baseline_anomalies]))
            list_under.append(- len([item for item in baseline_anomalies if item not in anomalies]))
        else:
            list_over.append(0)
            list_under.append(0)

    fig, ax = plt.subplots()
    BIN_WIDTH = 0.8
    if type_comparison == 'N_MINS':
        BIN_WIDTH = 4
    ax.bar(intervals, list_over, width=BIN_WIDTH)
    ax.bar(intervals, list_under, width=BIN_WIDTH)
    ax.set_xticks(intervals)
    if type_comparison == 'N_DAYS':
        ax.set_xlabel('Number of days in the model (N_DAYS)')
    else:
        ax.set_xlabel('Minimum number of packets to keep the port (N_MIN)')
    ax.set_ylabel('Number of anomalies in +/- compared to baseline')
    fig.savefig(path_join([PATH_FIGURES, 'comparison', type_comparison, THRESHOLD_ANO], 'png'), dpi=300)

def accurate_comparison(type_comparison, baseline, intervals):
    files = {}
    all_anomalies = dict.fromkeys(intervals, []) # contain all anomalies
    threshold_anomalies = dict.fromkeys(intervals, []) # contains anomalies whose nb_occur is over the threshold

    for interval in intervals:
        files[interval] = open(path_join([PATH_EVAL, 'ano', type_comparison, interval], 'txt'), 'r')
        elements = files[interval].read()
        files[interval].close()
        anomalies = elements.split(',')
        all_anomalies[interval] = anomalies
        threshold_anomalies = list(filter(lambda a: a.split('|')[2] > THRESHOLD_ANO, anomalies))

    unique_anomalies = set(chain(threshold_anomalies.values()))
    final_array = np.empty([len(unique_anomalies), len(intervals)], dtype=int)
    for row, value in enumerate(unique_anomalies):
        for col, interval in enumerate(intervals):
            anomalies = all_anomalies[interval]
            for anomaly in anomalies:
                if value in anomaly:
                    final_array[row, col] = anomaly.split('|')[2]
                    break
            else:
                final_array[row, col] = 0

    print(final_array)

def main(argv):
    original_subnets, sub_df, subnets = pre_computation()

    nb_days = [8, 10, 13, 15, 18, 20]
    nb_mins = [20, 35, 50, 65, 80, 100]

    # anomalies_ndays(subnets, nb_days)
    # anomalies_nmins(subnets, nb_mins)

    baseline_day = 10
    baseline_min = 20

    plot_results('N_DAYS', nb_days)
    # comparison('N_DAYS', baseline_day, nb_days)
    # comparison('N_MINS', baseline_min, nb_mins)
    # accurate_comparison('N_DAYS', baseline_day, nb_days)

if __name__ == '__main__':
    main(sys.argv)