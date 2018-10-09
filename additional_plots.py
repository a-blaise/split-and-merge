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
import math
from collections import OrderedDict
from matplotlib.backends.backend_pdf import PdfPages

from Settings import *
from Features import Feature, Figure, list_features, list_figures
from full_detection import path_join

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
            for fig in list_figures:
                if method == 'aggregated':
                    fig.reset_object()
                    for date in dates:
                        rep = packets[(packets.date == int(date)) & (packets.port == p)]
                        if not rep.empty:
                            fig.time_vect.append(rep[fig.attribute].item())
                        else:
                            if fig.attribute == 'nb_packets':
                                fig.time_vect.append(0)
                            else:
                                fig.time_vect.append(np.nan)
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
                            rep = packets[(packets.date == int(date)) & (packets.key == subnet) & (packets.port == p)]
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
                vector = [feat.time_vect[i] for i in range(N_DAYS, 2 * N_DAYS) if not math.isnan(feat.time_vect[i])]
                if len(vector) > 3:
                    mu = np.nanmean(vector)
                    sigma = np.nanstd(vector)
                    count, bins = np.histogram(vector, BINS_SIZE, density=1)
                    regression = [1 / (sigma * np.sqrt(2 * np.pi)) * np.exp(- (b - mu)**2 / (2 * sigma**2)) for b in bins]
                    # fig, ax = plt.subplots()
                    # ax.set_title('port ' + str(p) + ' feature ' + feat.attribute)
                    # ax.bar(bins[:-1] + np.diff(bins) / 2, count, np.diff(bins))
                    # ax.plot(bins, regression, linewidth=2, color='r')
                    # if sum(np.subtract(regression[:-1], count)**2) / BINS_SIZE > 100:
                    #     ax.set_title('port ' + str(p) + ' feature ' + feat.attribute + ' ' + str(sum(np.subtract(regression[:-1], count)**2) / BINS_SIZE))
                    error = sum(np.subtract(regression[:-1], count)**2) / BINS_SIZE
                    if not np.isnan(error):
                        feat.mse.append(error)
                feat.reset_object()
    for feat in list_features:
        if len(feat.mse) > 0:
            x, y = ecdf(feat.mse)
            fig1, ax1 = plt.subplots()
            ax1.plot(x, y)
            ax1.set_title('feature ' + feat.attribute)
            ax1.set_xlim(0, 1)
            fig1.savefig(path_join([PATH_FIGURES, 'ecdf', feat.attribute, 'N_MIN', 'upto1'], 'png'), dpi=300)
        else:
            print(feat.attribute, '0 in vect')

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

def comparison_ndays(subnets):
    # baseline: N_DAYS = 10
    packets = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'), dtype = {'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]
    ports = packets.port.unique()

    ano_per_day = dict.fromkeys(np.arange(start=5, stop=30, step=5), [])
    for p in ports:
        packets_port = packets[packets.port == p]
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
                    for nb_day, anomalies in ano_per_day.items():
                        if i > nb_day:
                            median = np.nanmedian(feat.time_vect[i - nb_day:i])
                            median_absolute_deviation = np.nanmedian([np.abs(y - median) for y in feat.time_vect[i - nb_day:i]])
                            mzscore = 0.6745 * (feat.time_vect[i] - median) / median_absolute_deviation
                            if np.abs(mzscore) > T:
                                anomalies.append('|'.join([feat.attribute, str(p), date]))
            feat.to_write = feat.to_write + ';'.join([el[:-1] for el in feat.mzscores.values()]) + '\n'

    print(ano_per_day.items())
    list_under = []
    list_over = []
         
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
    comparison_ndays(subnets)
    return 0

if __name__ == '__main__':
    main(sys.argv)