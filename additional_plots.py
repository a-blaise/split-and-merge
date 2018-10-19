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
from matplotlib.backends.backend_pdf import PdfPages

from Settings import *
from Features import Feature, Figure, list_features, list_figures
from full_detection import path_join, pre_computation
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

        # Plot only the results for the first ten ports
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

def gauss(b, mu, sigma): return 1 / (sigma * np.sqrt(2 * np.pi)) * np.exp(- ((b - mu) / (2 * sigma))**2)

def compute_mse_feature(original_subnets):
    packets = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'), dtype = {'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]

    for subnet in original_subnets[:2]:
        packets_subnet = packets[packets.key == subnet]
        ports = packets_subnet.port.unique()
        for p in ports[:5]:
            packets_port = packets_subnet[packets_subnet.port == p]
            for date in dates[:N_DAYS]:
                rep = packets_port[packets_port.date == int(date)]
                for feat in list_features:
                    if not rep.empty:
                        feat.time_vect.append(rep[feat.attribute].item())
                    else:
                        feat.time_vect.append(np.nan)
            for feat in list_features:
                vector = [feat.time_vect[i] for i in range(N_DAYS) if not np.isnan(feat.time_vect[i])]
                mu = np.nanmean(vector)
                sigma = np.nanstd(vector)
                n_vector = [(v - mu) / sigma for v in vector]
                if len(vector) > 3 and sigma != 0:
                    mu = 0
                    sigma = 1
                    count, bins = np.histogram(n_vector, BINS_SIZE, density=1)
                    regression = [] # value of Gaussian function in the middle of the interval
                    for i, b in enumerate(bins):
                        value = gauss(b, mu, sigma)
                        if i != 0:
                            regression.append(temp + value)
                        temp = value
                    error = mean_squared_error(count, regression)

                    fig, ax = plt.subplots()
                    ax.set_title('port ' + str(p) + ' feature ' + feat.attribute)
                    ax.bar(bins[:-1] + np.diff(bins) / 2, count)
                    ax.plot(bins[:-1] + np.diff(bins) / 2, regression, linewidth=2, color='r')
                    if error > 10:
                        ax.set_title('port ' + str(p) + ' feature ' + feat.attribute + ' ' + str(error))
                    if not np.isnan(error):
                        feat.mse.append(error)
                    print(p, feat.attribute, bins, count, regression, error)

                feat.reset_object()

    # fig_mse, ax_mse = plt.subplots()
    # for feat in list_features:
    #     x, y = ecdf(feat.mse)
    #     ax_mse.plot(x, y, label=feat.attribute + ' ' + str(np.round(np.nanmedian(feat.mse), 2)))

    # ax_mse.set_title('CDF MSE per feature ')
    # ax_mse.set_xlabel('Mean Squared Error')
    # ax_mse.set_ylabel('Probability to have this MSE')
    # legend = ax_mse.legend(loc='lower right', shadow=True)
    # ax_mse.grid(True)

    # fig_mse.savefig(path_join([PATH_FIGURES, 'ecdf', N_MIN, BINS_SIZE, 'limited'], 'png'), dpi=300)

def ecdf(data):
    raw_data = np.array(data)
    cdfx = np.sort(np.unique(raw_data))
    x_values = np.linspace(start=min(cdfx), stop=max(cdfx), num=len(cdfx))
    
    size_data = raw_data.size
    y_values = []
    for i in x_values:
        temp = raw_data[raw_data <= i] # all the values in raw data less than the ith value in x_values
        y_values.append(temp.size / size_data) # fraction of that value with respect to the size of the x_values
    return x_values, y_values

# def features_correlation():


def main(argv):
    original_subnets, sub_df, subnets = pre_computation()

    # plot_time_series(original_subnets)
    # get_frequency_anomalies()
    compute_mse_feature(original_subnets)
    return 0

if __name__ == '__main__':
    main(sys.argv)