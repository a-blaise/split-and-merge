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

def plot_time_series():
    """Plot feature time series and modified Z-score evolution for each port."""
    subnets = {}
    original_subnets = []

    if not os.path.exists(PATH_FIGURES):
        os.mkdir(PATH_FIGURES)
    pdf = PdfPages(PATH_FIGURES + 'time_series.pdf')

    for AGG in AGGs:
        prefix = '_separated'
        if AGG:
            prefix = '_agg'
        values = pd.read_csv(PATH_PACKETS + 'packets_subnets' + prefix + '_' + str(PERIOD) + '.csv', dtype={'date': int, 'port': int, 
            'nb_packets': int, 'nb_src': int, 'nb_dst':int, 'div_index_src': float, 'div_index_dst': float, 'SYN': float, 
            'mean_size': float, 'std_size': float})
        values = values[values.nb_packets > N_MIN]
        ports = sorted(list(set(values.port.tolist())))

        sub_df = pd.read_csv(PATH_SUBNETS + 'subnets_' + str(PERIOD) + '.csv', index_col=0, sep=',')
        if PERIOD == 2018:
            sub_df = sub_df.append(pd.read_csv(PATH_SUBNETS + 'subnets_2017.csv', index_col=0, sep=',')) # add last months of 2017 if 2018 period

        for subnet in sub_df.columns:
            if subnet not in subnets.keys():
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
        
        # Plot only the results for the 10 first ports
        for p in ports[:1]:
            for fig in list_figures:
                if AGG:
                    fig.reset_object()
                    for date in dates:
                        rep = values[(values.date == int(date)) & (values.port == p)]
                        if rep.empty == False:
                            fig.time_vect.append(rep[fig.attribute].item())
                        else:
                            if fig.attribute == 'nb_packets':
                                fig.time_vect.append(0)
                            else:
                                fig.time_vect.append(np.nan)
                    fig.sub_time_vect['all'] = fig.time_vect
                    fig.ax_a.plot(x, fig.time_vect, '-', label = 'Whole network')
                    fig.ax_a.set_xlabel('Time')
                    fig.ax_a.set_ylabel(fig.legend + ' on port ' + str(p) + ' aggregated')
                    fig.ax_a.set_xticks(x)
                    fig.ax_a.set_xticklabels(map(lambda x: x[0:2] + '/' + x[2:], dates))
                    plt.setp(fig.ax_a.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
                    lgd = fig.ax_a.legend()
                    fig.fig_a.savefig(pdf, format = 'pdf', dpi=600, bbox_extra_artists=(lgd,), bbox_inches='tight')
                else:
                    for subnet in original_subnets:
                        fig.time_vect = []
                        for date in dates:
                            rep = values[(values.date == int(date)) & (values.key == subnet) & (values.port == p)]
                            if rep.empty == False:
                                fig.time_vect.append(rep[fig.attribute].item())
                            else:
                                if fig.attribute == 'nb_packets':
                                    fig.time_vect.append(0)
                                else:
                                    fig.time_vect.append(np.nan)
                        fig.sub_time_vect[subnet] = fig.time_vect
                        fig.ax.plot(x, fig.time_vect, '-', label = str(subnet))
                    fig.ax.set_xlabel('Time')
                    fig.ax.set_ylabel(fig.legend + ' on port ' + str(p) + ' not aggregated')
                    fig.ax.set_xticks(x)
                    fig.ax.set_xticklabels(map(lambda x: x[0:2] + '/' + x[2:], dates))
                    plt.setp(fig.ax.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
                    lgd = fig.ax.legend(handletextpad=0.1, labelspacing=0.24, loc='upper center', bbox_to_anchor=(0.48, 1.27),
                        fancybox=True, shadow=True, ncol=2)
                    fig.fig.savefig(pdf, format = 'pdf', dpi=600, bbox_extra_artists=(lgd,), bbox_inches='tight')

                if AGG:
                    ax_totake = fig.ax_z_a
                    fig_totake = fig.fig_z_a
                else:
                    ax_totake = fig.ax_z
                    fig_totake = fig.fig_z
                for k, v in fig.sub_time_vect.items():
                    for i in range(N_DAYS, len(v)):
                        mean = np.nanmean(v[i - N_DAYS:i-1])
                        std = np.nanstd(v[i - N_DAYS:i-1])
                        median = np.nanmedian(v[i - N_DAYS:i-1])
                        median_absolute_deviation = np.nanmedian([np.abs(y - median) for y in v[i - N_DAYS:i-1]])
                        fig.mzscores[dates[i]] = [0.6745 * (v[i] - median) / median_absolute_deviation]
                    if AGG:
                        ax_totake.plot(y, fig.mzscores.values(), label = 'Whole network')
                    else:
                        ax_totake.plot(y, fig.mzscores.values(), label = str(k))
                ax_totake.set_xlabel('Time')
                ax_totake.set_ylabel('Moving Z-score for ' + fig.legend + ' on port ' + str(p) + ' not aggregated')
                ax_totake.set_xticks(y)
                ax_totake.set_xticklabels(map(lambda x: x[0:2] + '/' + x[2:], dates[N_DAYS:]))
                ax_totake.axhline(y=T, color='r')
                ax_totake.axhline(y=-T, color='r')
                ax_totake.text(18, T+0.1, 'T=' + str(T), color= 'r')
                ax_totake.text(18, -T+0.1, 'T=-' + str(T), color= 'r')
                plt.setp(ax_totake.get_xticklabels(), rotation=45, ha="right", rotation_mode="anchor")
                lgd = ax_totake.legend(handletextpad=0.1, labelspacing=0.24, loc='upper center', bbox_to_anchor=(0.48, 1.27),
                    fancybox=True, shadow=True, ncol=2)
                fig_totake.savefig(pdf, format = 'pdf', dpi=600, bbox_extra_artists=(lgd,), bbox_inches='tight')
    pdf.close()

def get_frequency_anomalies():
    """Pick a date and observe the frequency of anomalies for all features this given day."""
    date = '0804'
    list_features.append(Feature('total'))
    for AGG in AGGs:
        prefix = '_separated'
        if AGG:
            prefix = '_agg'
        for feat in list_features:
            ports = pd.read_csv(PATH_EVAL + 'eval_' + feat.attribute + '_' + prefix + '_' + str(PERIOD) + '_' + str(T) + '_' + str(N_MIN) + '.csv', sep = ';')
            ports = ports[date]
            result = ports.value_counts(dropna=False).to_dict()
            result = {}
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
    value = pd.read_csv(PATH_PACKETS + 'packets_subnets_separated_' + str(PERIOD) + '.csv', dtype = {'nb_packets': int})
    value = value[value.nb_packets > N_MIN]

    for subnet in original_subnets:
        rep = value[value.key == subnet]
        ports = set(rep.port.tolist())
        for p in list(ports):
            for feat in list_features:
                feat.reset_object()
            for date in dates[:2 * N_DAYS]:
                val = rep[(rep.date == int(date)) & (rep.port == p)]
                for feat in list_features:
                    if val.empty == False:
                        feat.time_vect.append(val[feat.attribute].item())
                    else:
                        feat.time_vect.append(np.nan)
            for feat in list_features:
                vector = [feat.time_vect[i] for i in range(N_DAYS, 2 * N_DAYS) if math.isnan(feat.time_vect[i]) == False]
                if len(vector) > 3:
                    if p != 3128 and p != 2323 and p != 23:
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
                        if str(error) != 'nan':
                            feat.mse.append(error)
                            if error > 5:
                                print('port', p, 'feature', feat.attribute, 'error', error, 'vector', vector, 'subnet', subnet)
    for feat in list_features:
        if len(feat.mse) > 0:
            x, y = ecdf(feat.mse)
            fig1, ax1 = plt.subplots()
            ax1.plot(x, y)
            ax1.set_title('feature ' + feat.attribute)
            ax1.set_xlim(0, 1)
            fig1.savefig(PATH_FIGURES + 'ecdf_' + feat.attribute + '_' + str(N_MIN) + '_upto1.png', dpi=300)
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

def gauss(bin, mu, sigma):
    return 1 / (sigma * np.sqrt(2 * np.pi)) * np.exp(- (bin - mu)**2 / (2 * sigma**2))

def main(argv):
    subnets = {}
    sub_df = pd.read_csv(PATH_SUBNETS + 'subnets_' + str(PERIOD) + '.csv', dtype={'date': str})
    original_subnets = sub_df.columns[1:].tolist()

    if PERIOD == 2018:
        sub_df = sub_df.append(pd.read_csv(PATH_SUBNETS + 'subnets_2017.csv', dtype={'date': str})) # add last months of 2017 if 2018 period

    for subnet in original_subnets:
        subnets[subnet] = {}
        for date in sub_df['date']:
            rep = sub_df[sub_df.date == date][subnet].item()
            subnets[subnet][str(rep) + '-' + date] = pd.DataFrame()

    # plot_time_series()
    # get_frequency_anomalies()
    compute_mse_feature(original_subnets)
    return 0

if __name__ == "__main__":
    main(sys.argv)