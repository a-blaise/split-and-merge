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
from collections import OrderedDict
from matplotlib.backends.backend_pdf import PdfPages

from Settings import *
from Features import Feature, Figure, list_features, list_figures
from full_detection import path_join
from sklearn.metrics import mean_squared_error

def plot_time_series(original_subnets):
    """Plot feature time series and modified Z-score evolution for each port."""
    if not os.path.exists(PATH_FIGURES): os.mkdir(PATH_FIGURES)
    pdf = PdfPages(path_join([PATH_FIGURES, 'time_series'], 'pdf'))

    for method in METHODS:
        packets = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets', method, PERIOD], 'csv'), dtype={'date': int, 'port': int, 
            'nb_packets': int, 'nb_src': int, 'nb_dst':int, 'div_index_src': float, 'div_index_dst': float, 'SYN': float, 
            'mean_size': float, 'std_size': float})
        packets = packets[packets.nb_packets > N_MIN]
        ports = packets.port.unique()

        # Plot only the results for the 10 first ports
        for p in ports[:10]:
            packets_port = packets[packets.port == p]
            for fig in list_figures:
                if method == 'aggregated':
                    fig.reset_object()
                    for date in dates:
                        rep = packets_port[packets_port.date == int(date)]
                        if not rep.empty:
                            fig.time_vect.append(rep[fig.attribute].item())
                        else:
                            if fig.attribute == 'nb_packets':
                                fig.time_vect.append(0)
                            else:
                                fig.time_vect.append(np.nan)
                    fig.init_figs()
                    fig.sub_time_vect['Whole network'] = fig.time_vect
                    fig.ax_a.plot(x, fig.time_vect, '-', label = 'Whole network')
                    fig.ax_a.set_xlabel('Time')
                    fig.ax_a.set_ylabel(' '.join([fig.legend, 'on port', str(p), 'aggregated']))
                    fig.ax_a.set_xticks(x)
                    fig.ax_a.set_xticklabels(map(lambda x: x[0:2] + '/' + x[2:], dates))
                    plt.setp(fig.ax_a.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor')
                    lgd = fig.ax_a.legend()
                    fig.fig_a.savefig(pdf, format = 'pdf', dpi=600, bbox_extra_artists=(lgd,), bbox_inches='tight')
                    ax_totake = fig.ax_z_a
                    fig_totake = fig.fig_z_a
                else:
                    for subnet in original_subnets:
                        fig.time_vect = []
                        for date in dates:
                            rep = packets_port[(packets_port.date == int(date)) & (packets_port.key == subnet)]
                            if not rep.empty:
                                fig.time_vect.append(rep[fig.attribute].item())
                            else:
                                if fig.attribute == 'nb_packets':
                                    fig.time_vect.append(0)
                                else:
                                    fig.time_vect.append(np.nan)
                        fig.sub_time_vect[subnet] = fig.time_vect
                        fig.ax.plot(x, fig.time_vect, '-', label = str(subnet))
                    fig.ax.set_xlabel('Time')
                    fig.ax.set_ylabel(' '.join([fig.legend, 'on port', str(p), 'not aggregated']))
                    fig.ax.set_xticks(x)
                    fig.ax.set_xticklabels(map(lambda x: x[0:2] + '/' + x[2:], dates))
                    plt.setp(fig.ax.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor')
                    lgd = fig.ax.legend(handletextpad=0.1, labelspacing=0.24, loc='upper center', bbox_to_anchor=(0.48, 1.27),
                        fancybox=True, shadow=True, ncol=2)
                    fig.fig.savefig(pdf, format = 'pdf', dpi=600, bbox_extra_artists=(lgd,), bbox_inches='tight')
                    ax_totake = fig.ax_z
                    fig_totake = fig.fig_z

                for subnet, values in fig.sub_time_vect.items():
                    for i in range(N_DAYS, len(values)):
                        median = np.nanmedian(values[i - N_DAYS:i-1])
                        median_absolute_deviation = np.nanmedian([np.abs(y - median) for y in values[i - N_DAYS:i-1]])
                        fig.mzscores[dates[i]] = [0.6745 * (values[i] - median) / median_absolute_deviation]
                    ax_totake.plot(y, fig.mzscores.values(), label = subnet)
                ax_totake.set_xlabel('Time')
                ax_totake.set_ylabel(' '.join(['Moving Z-score for', fig.legend, 'on port', str(p), 'not aggregated']))
                ax_totake.set_xticks(y)
                ax_totake.set_xticklabels(map(lambda x: x[0:2] + '/' + x[2:], dates[N_DAYS:]))
                ax_totake.axhline(y=T, color='r')
                ax_totake.axhline(y=-T, color='r')
                ax_totake.text(18, T+0.1, 'T=' + str(T), color= 'r')
                ax_totake.text(18, -T+0.1, 'T=-' + str(T), color= 'r')
                plt.setp(ax_totake.get_xticklabels(), rotation=45, ha='right', rotation_mode='anchor')
                lgd = ax_totake.legend(handletextpad=0.1, labelspacing=0.24, loc='upper center', bbox_to_anchor=(0.48, 1.27),
                    fancybox=True, shadow=True, ncol=2)
                fig_totake.savefig(pdf, format = 'pdf', dpi=600, bbox_extra_artists=(lgd,), bbox_inches='tight')
    pdf.close()

def get_frequency_anomalies():
    """Pick a date and observe the frequency of anomalies for all features this given day."""
    date = '0804'
    list_features.append(Feature('total'))
    for method, feat in zip(METHODS, list_features):
        ports = pd.read_csv(path_join([PATH_EVAL, 'eval', feat.attribute, method, PERIOD, T, N_MIN], 'csv'), sep = ';')
        result = ports[date].value_counts(dropna=False).to_dict()
        for k, v in result.items():
            if str(k) != 'nan':
                nb_el = len(k.split(','))
                if nb_el not in result_agg_2.keys():
                    result[nb_el] = v
                else:
                    result[nb_el] += v
            else:
                result[0] = v
        od = OrderedDict(sorted(result.items()))
        for i, nb in enumerate(od.keys()):
            print(nb, round(sum(list(od.values())[i:]), 2))

def compute_mse_feature(original_subnets):
    packets = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'), dtype = {'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]
    for subnet in original_subnets:
        packets_subnet = packets[packets.key == subnet]
        ports = packets_subnet.port.unique()
        for p in ports:
            packets_port = packets_subnet[packets_subnet.port == p]
            for date in dates[:2 * N_DAYS]:
                rep = packets_port[packets_port.date == int(date)]
                for feat in list_features:
                    if not rep.empty:
                        feat.time_vect.append(rep[feat.attribute].item())
                    else:
                        feat.time_vect.append(np.nan)
            for feat in list_features:
                vector = [feat.time_vect[i] for i in range(N_DAYS, 2 * N_DAYS) if not np.isnan(feat.time_vect[i])]
                mu = np.nanmean(vector)
                sigma = np.nanstd(vector)
                n_vector = [(v - mu) / sigma for v in vector]
                if len(vector) > 3 and sigma != 0:
                    mu = 0
                    sigma = 1
                    count, bins = np.histogram(n_vector, BINS_SIZE, density=1)
                    regression = [1 / (sigma * np.sqrt(2 * np.pi)) * np.exp(- (b - mu)**2 / (2 * sigma**2)) for b in bins]
                    error = mean_squared_error(count, regression[:-1])
                    # fig, ax = plt.subplots()
                    # ax.set_title('port ' + str(p) + ' feature ' + feat.attribute)
                    # ax.bar(bins[:-1] + np.diff(bins) / 2, count, np.diff(bins))
                    # ax.plot(bins, regression, linewidth=2, color='r')

                    # error = sum(np.subtract(regression[:-1], count)**2) / BINS_SIZE * sigma
                    # if error > 10:
                    #     ax.set_title('port ' + str(p) + ' feature ' + feat.attribute + ' ' + str(error))
                    if not np.isnan(error):
                        feat.mse.append(error)
                feat.reset_object()
        break
    for feat in list_features:
        if len(feat.mse) > 0:
            print(feat.attribute, np.nanmedian(feat.mse), len(feat.mse))
            x, y = ecdf(feat.mse)
            fig1, ax1 = plt.subplots()
            ax1.plot(x, y)
            ax1.set_title('feature ' + feat.attribute)
            ax1.set_xlim(0, 1)
            fig1.savefig(path_join([PATH_FIGURES, 'ecdf', feat.attribute, N_MIN, 'upto1'], 'png'), dpi=300)
        else:
            print(feat.attribute, '0 in vect')
    # plt.show()

def ecdf(data):
    raw_data = np.array(data)
    cdfx = np.sort(np.unique(raw_data))
    x_values = np.linspace(start=min(cdfx), stop=max(cdfx),num=len(cdfx))
    
    size_data = raw_data.size
    y_values = []
    for i in x_values:
        temp = raw_data[raw_data <= i] # all the values in raw data less than the ith value in x_values
        y_values.append(temp.size / size_data) # fraction of that value with respect to the size of the x_values
    return x_values, y_values

def anomalies_ndays(subnets):
    # regarder pourquoi 15 et 20 jours: exactement les mêmes anomalies?
    packets = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'), dtype = {'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]
    ports = packets.port.unique()

    # Compute anomalies by varying the number of days in the model
    # nb_days = np.arange(start=5, stop=25, step=5) # 5, 10, 15, 20
    nb_days = [3, 5, 8, 10, 13, 15, 18, 20, 23]
    files = {}
    for nb_day in nb_days:
        files[nb_day] = open(path_join([PATH_EVAL, 'ano_days', nb_day, 'full'], 'txt'), 'a')
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

def comparison_ndays():
    files = {}
    # nb_days = np.arange(start=5, stop=25, step=5)
    nb_days = [3, 8, 13, 18, 23]
    ano_per_day = dict.fromkeys(nb_days, {})

    for nb_day in nb_days:
        files[nb_day] = open(path_join([PATH_EVAL, 'ano_days', nb_day], 'txt'), 'r')
        l = files[nb_day].read()
        ano_per_day[nb_day] = l.split(',')

    elements_under = {} # key: nb_day (except 10), value: elements in baseline and not here
    elements_over = {} # same with elements in + compared to baseline

    # Compare anomalies seen for each day with the baseline
    baseline = 10
    baseline_anomalies = ano_per_day[baseline] # list of anomalies
    for nb_day, anomalies in ano_per_day.items():
        if nb_day != baseline:
            elements_over[nb_day] = []
            elements_under[nb_day] = []
            for item in anomalies:
                if item not in baseline_anomalies:
                    elements_over[nb_day].append(item)
            for item in baseline_anomalies:
                if item not in anomalies:
                    elements_under[nb_day].append(item)
            print('nb_day', nb_day)
            print(elements_over[nb_day])
            print(elements_under[nb_day])

    list_over = []
    list_under = []

    for nb_day in nb_days:
        if nb_day in elements_over:
            list_over.append(len(elements_over[nb_day]))
        else:
            list_over.append(0)
        if nb_day in elements_under:
            list_under.append(- len(elements_under[nb_day]))
        else:
            list_under.append(0)
        print(nb_day, list_under, list_over)

    fig, ax = plt.subplots()
    ax.bar(nb_days, list_over)
    ax.bar(nb_days, list_under)
    ax.set_xticks(nb_days)
    ax.set_xlabel('N_DAYS')
    ax.set_ylabel('Number of anomalies in +/- compared to baseline')
    plt.show()
    fig.savefig(path_join([PATH_FIGURES, 'comparison_ndays', THRESHOLD_ANO], 'png'), dpi=300)

def anomalies_nmins(subnets):
    nb_mins = [20, 35, 50, 65, 80, 100]

    files = {}
    for nb_min in nb_mins:
        files[nb_min] = open(path_join([PATH_EVAL, 'ano_mins', nb_min], 'txt'), 'a')
    ano_per_day = dict.fromkeys(nb_mins, {})

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
                    ano_per_day[n_min][new_id] = nb_occur
                    files[n_min].write(new_id + ',')

def main(argv):
    sub_df = pd.read_csv(path_join([PATH_SUBNETS, 'subnets', PERIOD], 'csv'), dtype={'date': str})
    original_subnets = sub_df.columns[1:].tolist()

    if PERIOD == 2018:
        sub_df = sub_df.append(pd.read_csv(path_join([PATH_SUBNETS, 'subnets_2017'], 'csv'), dtype={'date': str})) # add last months of 2017 if 2018 period

    subnets = dict.fromkeys(original_subnets, {})
    for subnet, date in zip(original_subnets, sub_df['date']):
        new_subnet = sub_df[sub_df.date == date][subnet].item()
        subnets[subnet][str(new_subnet) + '-' + date] = pd.DataFrame()

    # plot_time_series(original_subnets)
    # get_frequency_anomalies()
    # compute_mse_feature(original_subnets)
    anomalies_ndays(subnets)
    # comparison_ndays()
    # anomalies_nmins(subnets)
    return 0

if __name__ == '__main__':
    main(sys.argv)