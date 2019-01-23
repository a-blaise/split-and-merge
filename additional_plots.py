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

from itertools import combinations
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from scipy.stats import spearmanr, pearsonr
from sklearn.metrics import mean_squared_error
from sklearn.feature_selection import f_regression
import matplotlib.ticker as plticker

from settings import *
from features import FEATURES, FIGURES
from full_detection import path_join, pre_computation, sign_to_score
from matplotlib import rcParams

def plot_time_series(original_subnets):
    """Plot feature time series and modified Z-score evolution for each port."""
    subnets_names = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K']
    if not os.path.exists(PATH_FIGURES):
        os.mkdir(PATH_FIGURES)
    # pdf = PdfPages(path_join(PATH_FIGURES, 'time_series', 'pdf'))

    for method in METHODS:
        packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets', method, PERIOD, 'csv'),
                              dtype={'date': int, 'port': int, 'nb_packets': int, 'nb_src': int,
                                     'nb_dst': int, 'div_index_src': float, 'div_index_dst': float,
                                     'SYN': float, 'mean_size': float, 'std_size': float})
        packets = packets[packets.nb_packets > N_MIN]
        # ports = packets.port.unique()
        ports = [3389]

        # Plot only the results for the first ten ports
        for port in ports:
            packets_port = packets[packets.port == port]
            for fig in FIGURES:
                if method == 'agg':
                    fig.reset_object()
                    for date in DATES:
                        rep = packets_port[packets_port.date == int(date)]
                        fig.time_vect.append(rep[fig.attribute].item() if not rep.empty else np.nan)
                    if fig.attribute == 'nb_packets':
                        fig.time_vect = fig.time_vect.fillna(0)
                    fig.init_figs()
                    fig.sub_time_vect['Whole network'] = fig.time_vect
                    fig.ax_a.plot(DATES, fig.time_vect, '-', label='Whole network')
                    fig.ax_a.set_xlabel('Time')
                    fig.ax_a.set_ylabel(' '.join([fig.legend, 'on port', str(port), 'aggregated']))
                    fig.ax_a.set_xticks(DATES)
                    fig.ax_a.set_xticklabels(map(lambda x: '/'.join([x[0:2], x[2:]]), DATES))
                    plt.setp(fig.ax_a.get_xticklabels(), rotation=45, ha='right',
                             rotation_mode='anchor')
                    lgd = fig.ax_a.legend()
                    # fig.fig_a.savefig(pdf, format='pdf', dpi=600, bbox_extra_artists=(lgd,),
                    #                   bbox_inches='tight')
                    ax_totake = fig.ax_z_a
                    fig_totake = fig.fig_z_a
                else:
                    for subnet in original_subnets:
                        fig.init_figs()
                        fig.time_vect = []
                        for date in DATES:
                            rep = packets_port[(packets_port.date == int(date))
                                               & (packets_port.key == subnet)]
                            fig.time_vect.append(rep[fig.attribute].item() if not rep.empty
                                                 else np.nan)
                        if fig.attribute == 'nb_packets':
                            fig.time_vect = fig.time_vect.fillna(0)
                        fig.sub_time_vect[subnet] = fig.time_vect
                        fig.ax.plot(DATES, fig.time_vect, '-', label=str(subnet))
                    fig.ax.set_xlabel('Time')
                    fig.ax.set_ylabel(' '.join([fig.legend, 'on port', str(port),
                                                'not aggregated']))
                    fig.ax.set_xticks(DATES)
                    fig.ax.set_xticklabels(map(lambda x: '/'.join([x[0:2], x[2:]]), DATES))
                    plt.setp(fig.ax.get_xticklabels(), rotation=45, ha='right',
                             rotation_mode='anchor')
                    lgd = fig.ax.legend(handletextpad=0.1, labelspacing=0.24, loc='upper center',
                                        bbox_to_anchor=(0.48, 1.27),
                                        fancybox=True, shadow=True, ncol=2)
                    # fig.fig.savefig(pdf, format='pdf', dpi=600, bbox_extra_artists=(lgd,),
                    #                 bbox_inches='tight')
                    ax_totake = fig.ax_z
                    fig_totake = fig.fig_z

                # for feat in FEATURES:
                #     feat.reset_object()
                #     feat.to_write += str(port) + ';'
                #     for subnet in subnets:
                #         del feat.time_vect[:]
                #         packets_sub = (packets_port.copy() if method == 'agg'
                #                        else packets_port[packets_port.key == subnet])
                #         for i, date in enumerate(DATES):
                #             rep = packets_sub[packets_sub.date == int(date)]
                #             feat.time_vect.append(rep[feat.attribute].item()
                #                                   if not rep.empty else np.nan)
                #             if i >= N_DAYS:
                #                 median = np.nanmedian(feat.time_vect[i - N_DAYS:i])
                #                 mad = np.nanmedian([np.abs(y - median)
                #                                     for y in feat.time_vect[i - N_DAYS:i]])
                #                 mzscore = 0.6745 * (feat.time_vect[i] - median) / mad
                #                 if mzscore > T:
                #                     evaluations[feat.attribute].loc[port, date] += '+' + subnet + ','
                #                 elif mzscore < - T:
                #                     evaluations[feat.attribute].loc[port, date] += '-' + subnet + ','

                ind = 0
                for subnet, values in fig.sub_time_vect.items():
                    for i in range(N_DAYS, len(values)):
                        median = np.nanmedian(values[i - N_DAYS:i])
                        mad = np.nanmedian([np.abs(y - median) for y in values[i - N_DAYS:i]])
                        fig.mzscores[DATES[i]] = [0.6745 * (values[i] - median) / mad]
                    ax_totake.plot(DATES[N_DAYS:], [0] * 46, label='subnet ' + subnets_names[ind], marker=MARKERS[ind%len(MARKERS)])
                    ind += 1
                ax_totake.set_xlabel('Time')
                ax_totake.set_ylabel(' '.join(['Moving Z-score for', fig.legend, 'on port',
                                               str(port), 'not aggregated']))
                ax_totake.set_xticks(DATES[N_DAYS:])    
                ax_totake.set_xticklabels(map(lambda x: x[0:2] + '/' + x[2:], DATES[N_DAYS:]))
                # ax_totake.axhline(y=T, color='r')
                # ax_totake.axhline(y=-T, color='r')
                # ax_totake.text(18, T+0.1, 'T=' + str(T), color='r')
                # ax_totake.text(18, -T+0.1, 'T=-' + str(T), color='r')
                plt.setp(ax_totake.get_xticklabels(), rotation=45, ha='right',
                         rotation_mode='anchor')
                # lgd = ax_totake.legend(handletextpad=0.1, labelspacing=0.24, loc='upper center',
                #                        bbox_to_anchor=(3, 3),
                #                        fancybox=True, shadow=True, ncol=3)
                lgd = ax_totake.legend(loc='upper center', ncol=3, prop={'size': 21})
                # fig_totake.savefig(pdf, format='pdf', dpi=600, bbox_extra_artists=(lgd,),
                #                    bbox_inches='tight')
                plt.show()
    # pdf.close()

def nb_ports_nmin(original_subnets):
    fig, ax = plt.subplots(figsize=(5, 3.5))
    method = 'separated'
    subnets = original_subnets if method == 'separated' else ['all']

    subnets_names = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I']
    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets', method, PERIOD, 'csv'),
                                  dtype={'nb_packets': int})
    
    for i, subnet in enumerate(subnets):
        packets_sub = (packets[packets.key == subnet])
        l_packets = []
        for nb_min in NB_MINS:
            packets_sub = packets_sub[packets_sub.nb_packets > nb_min]
            l_packets.append(len(packets_sub))
        ax.plot(NB_MINS, l_packets, label='subnet ' + subnets_names[i], marker=MARKERS[i%len(MARKERS)])

    ax.set_xticks(NB_MINS)
    ax.set_xlabel(r'$N_{min}$', fontsize=12)
    ax.set_xticklabels(NB_MINS)
    ax.set_ylabel('Number of ports to analyze', fontsize=12)
    legend = ax.legend(prop={'size':'7'})
    fig.tight_layout()
    fig.savefig(path_join(PATH_FIGURES, 'nmin_nbports', PERIOD, 'png'), label=legend, dpi=1000)

def gauss(h_bin):
    return 1 / np.sqrt(2 * np.pi) * np.exp(- (h_bin / 2)**2)

def compute_mse_feature(original_subnets):
    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]
    rcParams.update({'figure.autolayout': True})

    for subnet in original_subnets:
        packets_subnet = packets[packets.key == subnet]
        ports = packets_subnet.port.unique()
        for port in ports:
            packets_port = packets_subnet[packets_subnet.port == port]
            for date in DATES[:N_DAYS]:
                rep = packets_port[packets_port.date == int(date)]
                for feat in FEATURES:
                    feat.time_vect.append(rep[feat.attribute].item() if not rep.empty else np.nan)
            for feat in FEATURES:
                vector = [feat.time_vect[i] for i in range(N_DAYS)
                          if not np.isnan(feat.time_vect[i])]
                mu = np.nanmean(vector)
                sigma = np.nanstd(vector)
                median = np.nanmedian(vector)
                mad = np.nanmedian([np.abs(y - median) for y in vector])
                vector_mean = [(v - mu) / sigma for v in vector]
                vector_median = [(v - median) / mad for v in vector]
                if len(vector) > 3 and mad != 0:
                    mu = 0
                    sigma = 1
                    median = 0
                    mad = 1
                    count_mean, bins_mean = np.histogram(vector_mean, BINS_SIZE, density=1)
                    regression_mean = [gauss(b) for b in bins_mean[:-1] + np.diff(bins_mean) / 2]
                    error_mean = mean_squared_error(count_mean, regression_mean)

                    count_median, bins_median = np.histogram(vector_median, BINS_SIZE, density=1)
                    regression_median = [0.6745 * gauss(b) for b in bins_median[:-1] + np.diff(bins_median) / 2]
                    error_median = mean_squared_error(count_median, regression_median)

                    if not np.isnan(error_mean):
                        feat.mse_mean.append(error_mean)
                    if not np.isnan(error_median):
                        feat.mse_median.append(error_median)
                feat.reset_object()

    fig_mse_mean, ax_mse_mean = plt.subplots(figsize=(5, 3.5))
    fig_mse_mean.tight_layout()
    for i, feat in enumerate(FEATURES):
        if feat.mse_mean:
            x_coordinates, y_coordinates = ecdf(feat.mse_mean)
            legend = ''
            if feat.attribute == 'src_div_index':
                legend = 'srcDivIndex'
            elif feat.attribute == 'dst_div_index':
                legend = 'destDivIndex'
            elif feat.attribute == 'port_div_index':
                legend = 'portDivIndex'
            elif feat.attribute == 'mean_size':
                legend = 'meanSize'
            elif feat.attribute == 'std_size':
                legend = 'stdSize'
            elif feat.attribute == 'nb_packets':
                legend = 'nbPackets'
            elif feat.attribute == 'mean_ttl':
                legend = 'meanTTL'
            elif feat.attribute == 'SYN':
                legend = 'perSYN'
            ax_mse_mean.plot(x_coordinates, y_coordinates, label=legend, linestyle=LINESTYLES[i % 4])

    ax_mse_mean.set_xlabel('Mean Squared Error', fontsize=12)
    ax_mse_mean.set_ylabel('Cumulative probability', fontsize=12)
    legend = ax_mse_mean.legend(loc='lower right', shadow=True, prop={'size':'10'})
    ax_mse_mean.grid(True)
    fig_mse_mean.savefig(path_join(PATH_FIGURES, 'ecdf_mean', PERIOD, BINS_SIZE, N_DAYS, 'png'), dpi=800)

    fig_mse_median, ax_mse_median = plt.subplots(figsize=(5, 3.5))
    fig_mse_median.tight_layout()
    for i, feat in enumerate(FEATURES):
        if feat.mse_median:
            x_coordinates, y_coordinates = ecdf(feat.mse_median)
            legend = ''
            if feat.attribute == 'src_div_index':
                legend = 'srcDivIndex'
            elif feat.attribute == 'dst_div_index':
                legend = 'destDivIndex'
            elif feat.attribute == 'port_div_index':
                legend = 'portDivIndex'
            elif feat.attribute == 'mean_size':
                legend = 'meanSize'
            elif feat.attribute == 'std_size':
                legend = 'stdSize'
            elif feat.attribute == 'nb_packets':
                legend = 'nbPackets'
            elif feat.attribute == 'mean_ttl':
                legend = 'meanTTL'
            elif feat.attribute == 'SYN':
                legend = 'perSYN'
            ax_mse_median.plot(x_coordinates, y_coordinates, label=legend, linestyle=LINESTYLES[i % 4])

    ax_mse_median.set_xlabel('Mean Squared Error', fontsize=12)
    ax_mse_median.set_ylabel('Cumulative probability', fontsize=12)
    legend = ax_mse_median.legend(loc='lower right', shadow=True, prop={'size':'10'})
    ax_mse_median.grid(True)
    fig_mse_median.savefig(path_join(PATH_FIGURES, 'ecdf_median', PERIOD, BINS_SIZE, N_DAYS, 'png'), dpi=800)

def ecdf(data):
    raw_data = np.array(data)
    cdfx = np.sort(np.unique(raw_data))
    x_values = np.linspace(start=min(cdfx), stop=max(cdfx), num=len(cdfx))

    size_data = raw_data.size
    y_values = []
    for i in x_values:
        temp = raw_data[raw_data <= i]
        y_values.append(temp.size / size_data)
    return x_values, y_values

def mse_ndays(subnets):
    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]

    file = open(path_join(PATH_EVAL, 'mse_ndays', PERIOD, 'csv'), 'w')

    for nb_day in NB_DAYS:
        for subnet in subnets:
            packets_subnet = packets[packets.key == subnet]
            ports = packets_subnet.port.unique()
            for port in ports:
                packets_port = packets_subnet[packets_subnet.port == port]
                for feat in FEATURES:
                    feat.reset_object()
                    for i, date in enumerate(DATES):
                        rep = packets_port[packets_port.date == int(date)]
                        feat.time_vect.append(rep[feat.attribute].item() if not rep.empty else np.nan)
                        if i > len(DATES) - LEN_PERIOD:
                            vector = [feat.time_vect[j] for j in range(i - nb_day, i) if not np.isnan(feat.time_vect[j])]
                            mean = np.nanmean(vector)
                            std = np.nanmean([np.abs(y - mean) for y in vector])
                            median = np.nanmedian(vector)
                            mad = np.nanmedian([np.abs(y - median) for y in vector])
                            vector_mean = [(v - mean) / std for v in vector]
                            vector_median = [(v - median) / mad for v in vector]
                            if len(vector) > 3 and mad != 0:
                                mean = 0
                                std = 1
                                median = 0
                                mad = 1
                                count_mean, bins_mean = np.histogram(vector_mean, BINS_SIZE, density=1)
                                count_median, bins_median = np.histogram(vector_median, BINS_SIZE, density=1)
                                regression_mean = [gauss(b) for b in bins_mean[:-1] + np.diff(bins_mean) / 2]
                                regression_median = [gauss(b) for b in bins_median[:-1] + np.diff(bins_median) / 2]
                                error_mean = mean_squared_error(count_mean, regression_mean)
                                error_median = mean_squared_error(count_median, regression_median)
                                if not np.isnan(error_mean):
                                    feat.mse_mean.append(np.round(error_mean, 3))
                                if not np.isnan(error_median):
                                    feat.mse_median.append(np.round(error_median, 3))
        for feat in FEATURES:
            value1 = round(np.nanmedian(feat.mse_mean), 3)
            value2 = round(np.nanmedian(feat.mse_median), 3)
            file.write(','.join((str(nb_day), str(feat.attribute), str(value1), str(value2))) + '\n')
            del feat.mse_mean[:]
            del feat.mse_median[:]

# 1 courbe / feature
def plot_mse_ndays():
    mse = pd.read_csv(path_join(PATH_EVAL, 'mse_ndays', PERIOD, 'csv'),
                      dtype={'nb_packets': int}, names=['nb_day', 'feature', 'mean', 'median'])

    tools = ['median', 'mean']
    for tool in tools:
        fig_mse, ax_mse = plt.subplots(figsize=(5, 3.5))
        fig_mse.tight_layout()
        for i, feat in enumerate(FEATURES):
            value = mse[mse.feature == feat.attribute]
            results = value[tool].tolist()
            results = list(map(lambda x: round(x, 3), results))
            print(feat.attribute)
            legend = ''
            if feat.attribute == 'src_div_index':
                legend = 'srcDivIndex'
            elif feat.attribute == 'dst_div_index':
                legend = 'destDivIndex'
            elif feat.attribute == 'port_div_index':
                legend = 'portDivIndex'
            elif feat.attribute == 'mean_size':
                legend = 'meanSize'
            elif feat.attribute == 'std_size':
                legend = 'stdSize'
            elif feat.attribute == 'SYN':
                legend = 'perSYN'
            ax_mse.plot(NB_DAYS, results, label=legend, marker=MARKERS[i], linestyle=LINESTYLES[i % 4])

        ax_mse.set_xlabel(r'$N_{days}$', fontsize=12)
        ax_mse.set_ylabel('Median MSE', fontsize=12)
        ax_mse.set_xticks(NB_DAYS)
        ax_mse.set_xticklabels(NB_DAYS)
        ax_mse.legend()
        fig_mse.tight_layout()
        fig_mse.savefig(path_join(PATH_FIGURES, tool + '_mse_feature', 'png'), dpi=300)

def correlation_features():
    list_annotations = []
    test = pd.read_csv(path_join(PATH_EVAL, 'eval', FEATURES[0].attribute,
                              'separated', PERIOD, T, N_MIN,
                               N_DAYS, 'score', 'csv'), sep=';', index_col=0)

    ports = pd.DataFrame(columns=list(test.columns))
    for feat in FEATURES:
        feat_df = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                              'separated', PERIOD, T, N_MIN,
                               N_DAYS, 'score', 'csv'), sep=';', index_col=0)
        feat_df = feat_df.applymap(sign_to_score)
        ports = ports.add(feat_df, fill_value=0)

    ports = ports.loc[(ports > T_ANO).any(axis=1)]

    for port, row in ports.iterrows():
        for i, date in enumerate(DATES[N_DAYS:]):
            if row[i] > T_ANO:
                annotations = []
                for feat in FEATURES:
                    evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                'separated', PERIOD, T, N_MIN, N_DAYS, 'score', 'csv'), sep=';', index_col=0)
                    if port in list(evaluation.index):
                        rep = evaluation.loc[port, date]
                        if rep:
                            if str(rep) != 'nan':
                                annotations.extend([int(rep.split(',')[sign]) for sign in range(2)])
                            else:
                                annotations.extend([0, 0])
                    else:
                        annotations.extend([0, 0])
                list_annotations.append(annotations)

    heatmap = pd.DataFrame(list_annotations, columns=[sign + feat.attribute for sign in SIGNS
                                                      for feat in FEATURES])

    for feat_1, feat_2 in list(combinations([feat.attribute for feat in FEATURES], 2)):
        for sign_1 in SIGNS:
            for sign_2 in SIGNS:
                rho_s, p_s = spearmanr(heatmap[sign_1 + feat_1], heatmap[sign_2 + feat_2])
                rho_p, p_p = pearsonr(heatmap[sign_1 + feat_1], heatmap[sign_2 + feat_2])
                if np.abs(rho_s) > 0.7:
                    print(sign_1 + feat_1, sign_2 + feat_2, round(rho_s * 100, 1))

def cor_features_output():
    feat_df = dict.fromkeys([feat.attribute for feat in FEATURES], pd.DataFrame())
    for feat in FEATURES:
        ports = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute, 'separated', PERIOD,
                                      T, N_MIN, N_DAYS, 'score', 'csv'), sep=';', index_col=0)
        feat_df[feat.attribute] = ports.applymap(sign_to_score)

    combinations = [FEATURES]
    labels = ['all']
    for feat in FEATURES:
        labels.append(feat.attribute)
        temp = FEATURES[:]
        temp.remove(feat)
        combinations.append(temp)

    threshold_ano, all_ano = (dict.fromkeys([str(l) for l in combinations], []) for i in range(2))
    for l in combinations:
        result = pd.DataFrame()
        for feat in l:
            result = result.add(feat_df[feat.attribute], fill_value=0)
        result = result.astype(int)
        ind_thr, ind_all = ([] for i in range(2))
        for port, row in result.iterrows():
            for i, date in enumerate(DATES[N_DAYS:]):
                ind_all.append('|'.join([str(port), date, str(row[i])]))
                if row[i] > T_ANO:
                    ind_thr.append('|'.join([str(port), date, str(row[i])]))
        threshold_ano[str(l)] = ind_thr
        all_ano[str(l)] = ind_all
    print(threshold_ano.values())

    unique_ano = set(['|'.join(el.split('|')[:-1]) for thr in threshold_ano.values() for el in thr])
    final_array = pd.DataFrame(index=unique_ano, columns=[str(l) for l in combinations],
                               dtype=np.int8)
    for value in unique_ano:
        for l in combinations:
            for anomaly in all_ano[str(l)]:
                if value in anomaly:
                    final_array.loc[value, str(l)] = int(anomaly.split('|')[2])
                    break
            else:
                final_array.loc[value, str(l)] = 0

    fig, axis = plt.subplots()
    final = np.array(final_array, dtype=int)
    image = axis.imshow(final, cmap='YlOrRd')

    axis.set_xticks(np.arange(len(combinations)))
    axis.set_yticks(np.arange(len(unique_ano)))

    axis.set_xticklabels(labels)
    axis.set_yticklabels([an.split('|')[0] + ' - ' + an.split('|')[1][0:2] + '/'
                          + an.split('|')[1][2:] for an in unique_ano])
    axis.tick_params(axis='both', which='major', labelsize=5)
    plt.setp(axis.get_xticklabels(), rotation=35, ha='right',
             rotation_mode='anchor')

    for i in range(len(unique_ano)):
        for j in range(len(combinations)):
            color = 'b' if final[i, j] > T_ANO else 'c'
            text = axis.text(j, i, final[i, j], ha='center', va='center', color=color, size=5)

    axis.set_title('Intensity of anomalies with features varying', size=5)
    fig.savefig(path_join(PATH_FIGURES, 'cor_features', T, N_MIN, N_DAYS, PERIOD, 'png'),
                dpi=600, bbox_inches='tight')

    for i, l in enumerate(combinations[1:]):
        rho_s, p_s = [round(val * 100, 1) for val in spearmanr(final_array.iloc[:, 0], final_array[str(l)])]
        print(labels[i+1], int(sum(np.subtract(final_array.iloc[:, 0], final_array[str(l)]))), rho_s)

def relevant_features():
    list_annot = []
    test = pd.read_csv(path_join(PATH_EVAL, 'eval', FEATURES[0].attribute,
                              'separated', PERIOD, T, N_MIN,
                               N_DAYS, 'score', 'csv'), sep=';', index_col=0)

    ports = pd.DataFrame(columns=list(test.columns))
    for feat in FEATURES:
        feat_df = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                              'separated', PERIOD, T, N_MIN,
                               N_DAYS, 'score', 'csv'), sep=';', index_col=0)
        feat_df = feat_df.applymap(sign_to_score)
        ports = ports.add(feat_df, fill_value=0)

    ports = ports.loc[(ports > T_ANO).any(axis=1)]

    for index, row in ports.iterrows():
        for i, date in enumerate(DATES[N_DAYS:]):
            if row[i] > T_ANO:
                annotations = [index, date]
                for feat in FEATURES:
                    evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                                       'separated', PERIOD, T, N_MIN,
                                                       N_DAYS, 'score', 'csv'), sep=';',
                                                       index_col=0)
                    if index in list(evaluation.index):
                        rep = evaluation.loc[index][date]
                        if rep:
                            if str(rep) != 'nan':
                                annotations.extend([int(rep.split(',')[sign]) for sign in range(2)])
                            else:
                                annotations.extend([0, 0])
                    else:
                        annotations.extend([0, 0])
                list_annot.append(annotations)

    columns = ['port', 'date']
    columns.extend([sign + feat.attribute for feat in FEATURES for sign in SIGNS])
    heatmap = pd.DataFrame(list_annot, columns=columns)
    heatmap = heatmap.rename(index=str, columns={"-src_div_index": "-src", "+src_div_index": "+src",
                                                 "-dst_div_index": "-dst", "+dst_div_index": "+dst",
                                                 "-port_div_index": "-port", "+port_div_index": "+port",
                                                 "-mean_size": "-meanSz", "+mean_size": "+meanSz",
                                                 "-std_size": "-stdSz", "+std_size": "+stdSz"})

    dict_scores = dict.fromkeys([feat.attribute for feat in FEATURES], 0)
    for index, row in heatmap.iterrows():
        for ind_f, feat in enumerate(FEATURES):
            if abs(int(row[2 + ind_f * 2])) > 1 and int(row[2 + ind_f * 2 + 1]) == 0:
                dict_scores[feat.attribute] += 1
            if abs(int(row[2 + ind_f * 2 + 1])) > 1 and int(row[2 + ind_f * 2]) == 0:
                dict_scores[feat.attribute] += 1
    print(dict_scores)

def bars_comparative():
    for feat in FEATURES:
        x_values, y_values = ([] for i in range(2))
        labels = []
        fig, ax = plt.subplots(figsize=(5, 3.5))
        for method in METHODS:
            ports = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                          method, PERIOD, T, N_MIN,
                                          N_DAYS, 'score', 'csv'), sep=';',
                                          index_col=0)
            ports = ports.applymap(sign_to_score)
            results = {}
            for i in range(len(ports.columns)):
                res = ports.iloc[:, i]
                temp = res.value_counts().to_dict()
                results = {k: results.get(k, 0) + temp.get(k, 0) for k in set(results) | set(temp)}
            print(feat.attribute, results)
            if method == 'agg':
                x_values.extend([-3, -2])
                labels.extend(['0', '1'])
            else:
                x_values.extend(results.keys())
                labels.extend([str(x) for x in results.keys()])
            y_values.extend(results.values())
            
        rects = ax.bar(x_values, y_values)
        ax.set_yscale("log")
        ax.xaxis.set_major_locator(plticker.MaxNLocator(integer=True))
        numbers_ports = {}
        for el in results.keys():
            numbers_ports[el] = ports[ports == el].index.tolist()
        for rect in rects:
            height = rect.get_height()
            ax.text(rect.get_x() + rect.get_width()/2., 1.05*height,
                    '%d' % int(height), ha='center', va='bottom', size=8)
        ticketing = [-3, -2]
        ticketing.extend(range(len(labels) - 1))
        ax.set_xticks(ticketing)
        ax.set_xticklabels(labels)
        ax.set_xlabel('Score', fontsize=12)
        ax.set_ylabel('Number of anomalies', fontsize=12)
        ax.set_ylim(-2, 4 * 10**6)
        plt.axvline(x=-1, linestyle='--', color='black', linewidth=0.5)
        fig.text(0.16, 0.9, 'Aggregated view', size=8)
        fig.text(0.59, 0.9, 'Split view', size=8)
        fig.tight_layout()
        fig.savefig(path_join(PATH_FIGURES, feat.attribute, method, N_MIN, N_DAYS, PERIOD, 'png'),
                    dpi=800, bbox_inches='tight')

def feature_selection():
    years = [2016, 2017, 2018]
    list_annot = []
    for year in years:
        print(year)
        test = pd.read_csv(path_join(PATH_EVAL, 'eval', FEATURES[0].attribute,
                                  'separated', year, T, N_MIN,
                                   N_DAYS, 'score', 'csv'), sep=';', index_col=0)

        ports = pd.DataFrame(columns=list(test.columns))
        for feat in FEATURES:
            feat_df = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                  'separated', year, T, N_MIN,
                                   N_DAYS, 'score', 'csv'), sep=';', index_col=0)
            feat_df = feat_df.applymap(sign_to_score)
            ports = ports.add(feat_df, fill_value=0)

        ports = ports.loc[(ports > T_ANO).any(axis=1)]
        for index, row in ports.iterrows():
            if year == 2016:
                dates = ['1210', '1217', '1224', '1231', '0107', '0114', '0121', '0128', '0204', 
                         '0211', '0218', '0225', '0303', '0310', '0317', '0324', '0331', '0407',
                         '0414', '0421', '0428', '0505', '0512', '0519', '0526', '0602', '0609',
                         '0616', '0622', '0630', '0707', '0714', '0721', '0728', '0804', '0811', 
                         '0818', '0825', '0901', '0908', '0915', '0922', '0929', '1006', '1013',
                         '1020', '1027', '1103', '1110', '1117', '1124', '1201', '1208', '1215',
                         '1222', '1229']
            elif year == 2017:
                dates = ['1027', '1103', '1110', '1117', '1124', '1201', '1208', '1215', '1222',
                         '1229', '0105', '0112', '0119', '0126', '0202', '0209', '0216', '0223',
                         '0302', '0309', '0316', '0323', '0330', '0406', '0413', '0420', '0427',
                         '0504', '0511', '0518', '0525', '0601', '0608', '0615', '0622', '0629',
                         '0706', '0713', '0720', '0727', '0803', '0810', '0817', '0824', '0831',
                         '0907', '0914', '0921', '0928', '1005', '1012', '1019', '1026', '1102',
                         '1109', '1116', '1123', '1130', '1207', '1214', '1221', '1228']
            elif year == 2018:
                dates = ['1026', '1102', '1109', '1116', '1123', '1130', '1207', '1214', '1221', '1228',
                         '0104', '0111', '0118', '0125', '0201', '0208', '0215', '0222', '0301', '0308',
                         '0315', '0322', '0329', '0405', '0412', '0419', '0426', '0503', '0510', '0517',
                         '0524', '0531', '0607', '0614', '0621', '0628', '0705', '0712', '0719', '0726',
                         '0802', '0809', '0816', '0823', '0830', '0906', '0913', '0920', '0927', '1004',
                         '1011', '1018', '1025', '1101', '1108', '1115', '1122', '1129', '1206']
            for i, date in enumerate(dates[N_DAYS:]):
                if row[i] > T_ANO:
                    annotations = [index, date]
                    for feat in FEATURES:
                        evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                                           'separated', year, T, N_MIN,
                                                           N_DAYS, 'score', 'csv'), sep=';',
                                                           index_col=0)
                        if index in list(evaluation.index):
                            rep = evaluation.loc[index][date]
                            if rep:
                                if str(rep) != 'nan':
                                    annotations.extend([int(rep.split(',')[sign]) for sign in range(2)])
                                else:
                                    annotations.extend([0, 0])
                        else:
                            annotations.extend([0, 0])
                    list_annot.append(annotations)

    columns = ['port', 'date']
    columns.extend([sign + feat.attribute for feat in FEATURES for sign in SIGNS])
    heatmap = pd.DataFrame(list_annot, columns=columns)
    heatmap = heatmap.iloc[:, 2:].applymap(lambda x: np.abs(x))
    heatmap['sum'] = heatmap.sum(axis=1)
    print(np.array(heatmap.iloc[:, :-1]), heatmap['sum'])

    f_test, _ = f_regression(np.array(heatmap.iloc[:, :-1]), heatmap['sum'])
    f_test /= np.max(f_test)
    print(f_test)

def main(argv):
    original_subnets, sub_df, subnets = pre_computation()

    # plot_time_series(original_subnets)
    # nb_ports_nmin(original_subnets)
    # compute_mse_feature(original_subnets)
    # mse_ndays(subnets)
    # plot_mse_ndays()
    # correlation_features()
    # cor_features_output()
    # relevant_features()
    # bars_comparative()
    feature_selection()
    return 0

if __name__ == '__main__':
    main(sys.argv)
