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

from settings import *
from features import FEATURES, FIGURES

def plot_time_series(original_subnets):
    """Plot feature time series and modified Z-score evolution for each port."""
    if not os.path.exists(PATH_FIGURES):
        os.mkdir(PATH_FIGURES)
    pdf = PdfPages(path_join(PATH_FIGURES, 'time_series', 'pdf'))

    for method in METHODS:
        packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets', method, PERIOD, 'csv'),
                              dtype={'date': int, 'port': int, 'nb_packets': int, 'nb_src': int,
                                     'nb_dst': int, 'div_index_src': float, 'div_index_dst': float,
                                     'SYN': float, 'mean_size': float, 'std_size': float})
        packets = packets[packets.nb_packets > N_MIN]
        ports = packets.port.unique()

        # Plot only the results for the first ten ports
        for port in ports[:10]:
            packets_port = packets[packets.port == port]
            for fig in FIGURES:
                if method == 'aggregated':
                    fig.reset_object()
                    for date in DATES:
                        rep = packets_port[packets_port.date == int(date)]
                        fig.time_vect.append(rep[fig.attribute].item() if not rep.empty else np.nan)
                    if fig.attribute == 'nb_packets':
                        fig.time_vect = fig.time_vect.fillna(0)
                    fig.init_figs()
                    fig.sub_time_vect['Whole network'] = fig.time_vect
                    fig.ax_a.plot(x, fig.time_vect, '-', label='Whole network')
                    fig.ax_a.set_xlabel('Time')
                    fig.ax_a.set_ylabel(' '.join([fig.legend, 'on port', str(port), 'aggregated']))
                    fig.ax_a.set_xticks(x)
                    fig.ax_a.set_xticklabels(map(lambda x: '/'.join([x[0:2], x[2:]]), DATES))
                    plt.setp(fig.ax_a.get_xticklabels(), rotation=45, ha='right',
                             rotation_mode='anchor')
                    lgd = fig.ax_a.legend()
                    fig.fig_a.savefig(pdf, format='pdf', dpi=600, bbox_extra_artists=(lgd,),
                                      bbox_inches='tight')
                    ax_totake = fig.ax_z_a
                    fig_totake = fig.fig_z_a
                else:
                    for subnet in original_subnets:
                        fig.time_vect = []
                        for date in DATES:
                            rep = packets_port[(packets_port.date == int(date))
                                               & (packets_port.key == subnet)]
                            fig.time_vect.append(rep[fig.attribute].item() if not rep.empty
                                                 else np.nan)
                        if fig.attribute == 'nb_packets':
                            fig.time_vect = fig.time_vect.fillna(0)
                        fig.sub_time_vect[subnet] = fig.time_vect
                        fig.ax.plot(x, fig.time_vect, '-', label=str(subnet))
                    fig.ax.set_xlabel('Time')
                    fig.ax.set_ylabel(' '.join([fig.legend, 'on port', str(port),
                                                'not aggregated']))
                    fig.ax.set_xticks(x)
                    fig.ax.set_xticklabels(map(lambda x: '/'.join([x[0:2], x[2:]]), DATES))
                    plt.setp(fig.ax.get_xticklabels(), rotation=45, ha='right',
                             rotation_mode='anchor')
                    lgd = fig.ax.legend(handletextpad=0.1, labelspacing=0.24, loc='upper center',
                                        bbox_to_anchor=(0.48, 1.27),
                                        fancybox=True, shadow=True, ncol=2)
                    fig.fig.savefig(pdf, format='pdf', dpi=600, bbox_extra_artists=(lgd,),
                                    bbox_inches='tight')
                    ax_totake = fig.ax_z
                    fig_totake = fig.fig_z

                for subnet, values in fig.sub_time_vect.items():
                    for i in range(N_DAYS, len(values)):
                        median = np.nanmedian(values[i - N_DAYS:i-1])
                        mad = np.nanmedian([np.abs(y - median) for y in values[i - N_DAYS:i-1]])
                        fig.mzscores[DATES[i]] = [0.6745 * (values[i] - median) / nad]
                    ax_totake.plot(y, fig.mzscores.values(), label=subnet)
                ax_totake.set_xlabel('Time')
                ax_totake.set_ylabel(' '.join(['Moving Z-score for', fig.legend, 'on port',
                                               str(port), 'not aggregated']))
                ax_totake.set_xticks(y)
                ax_totake.set_xticklabels(map(lambda x: x[0:2] + '/' + x[2:], DATES[N_DAYS:]))
                ax_totake.axhline(y=T, color='r')
                ax_totake.axhline(y=-T, color='r')
                ax_totake.text(18, T+0.1, 'T=' + str(T), color='r')
                ax_totake.text(18, -T+0.1, 'T=-' + str(T), color='r')
                plt.setp(ax_totake.get_xticklabels(), rotation=45, ha='right',
                         rotation_mode='anchor')
                lgd = ax_totake.legend(handletextpad=0.1, labelspacing=0.24, loc='upper center',
                                       bbox_to_anchor=(0.48, 1.27),
                                       fancybox=True, shadow=True, ncol=2)
                fig_totake.savefig(pdf, format='pdf', dpi=600, bbox_extra_artists=(lgd,),
                                   bbox_inches='tight')
    pdf.close()

def gauss(h_bin):
    return 1 / np.sqrt(2 * np.pi) * np.exp(- (h_bin / 2)**2)

def compute_mse_feature(original_subnets):
    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]

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
                n_vector = [(v - mu) / sigma for v in vector]
                if len(vector) > 3 and sigma != 0:
                    mu = 0
                    sigma = 1
                    count, bins = np.histogram(n_vector, BINS_SIZE, density=1)
                    regression = [gauss(b) for b in bins[:-1] + np.diff(bins) / 2]
                    error = mean_squared_error(count, regression)

                    fig, ax = plt.subplots()
                    ax.set_title('port ' + str(port) + ' feature ' + feat.attribute)
                    ax.bar(bins[:-1] + np.diff(bins) / 2, count)
                    ax.plot(bins[:-1] + np.diff(bins) / 2, regression, linewidth=2,
                            color='r')
                    if error > 10:
                        ax.set_title(' '. join('port', str(port), 'feature',
                                               feat.attribute, str(error)))
                    if not np.isnan(error):
                        feat.mse.append(error)
                    print(port, feat.attribute, bins, count, regression, error)
                feat.reset_object()

    fig_mse, ax_mse = plt.subplots()
    for feat in FEATURES:
        x_coordinates, y_coordinates = ecdf(feat.mse)
        ax_mse.plot(x_coordinates, y_coordinates, label=feat.attribute + ' ' +
                    str(np.round(np.nanmedian(feat.mse), 2)))

    ax_mse.set_title('CDF MSE per feature ')
    ax_mse.set_xlabel('Mean Squared Error')
    ax_mse.set_ylabel('Probability to have this MSE')
    legend = ax_mse.legend(loc='lower right', shadow=True)
    ax_mse.grid(True)

    fig_mse.savefig(path_join(PATH_FIGURES, 'ecdf', N_MIN, BINS_SIZE, 'limited', 'png'), dpi=300)

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

def correlation_features():
    list_annotations = []
    ports_annot = pd.read_csv(path_join(PATH_EVAL, 'eval_total_separated', PERIOD, T,
                                        N_MIN, N_DAYS, 'score', 'csv'), sep=';', index_col=0)
    ports = ports_annot.applymap(sign_to_score)
    ports = ports.loc[(ports > T_ANO).any(axis=1)]

    for port, row in ports.iterrows():
        for i, date in enumerate(DATES[N_DAYS:]):
            if row[i] > T_ANO:
                annotations = []
                for feat in FEATURES:
                    evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                                       'separated', PERIOD, T, N_MIN,
                                                       N_DAYS, 'score', 'csv'), sep=';')
                    rep = evaluation[evaluation.port == port][date]
                    annotations.extend([int(rep.item().split(',')[sign]) for sign in range(2)]
                                       if not rep.empty and str(rep.item()) != 'nan' else [0, 0])
                list_annotations.append(annotations)

    heatmap = pd.DataFrame(list_annotations, columns=[sign + feat.attribute for sign in SIGNS
                                                      for feat in FEATURES])

    comb_features = list(combinations([feat.attribute for feat in FEATURES], 2))
    for feat_1, feat_2 in comb_features:
        for sign_1 in SIGNS:
            for sign_2 in SIGNS:
                rho_s, p_s = spearmanr(heatmap[sign_1 + feat_1], heatmap[sign_2 + feat_2])
                rho_p, p_p = pearsonr(heatmap[sign_1 + feat_1], heatmap[sign_2 + feat_2])
                if rho_s > 0.5:
                    print(sign_1 + feat_1, sign_2 + feat_2, rho_s)

def cor_features_output():
    feat_df = dict.fromkeys([feat.attribute for feat in FEATURES], pd.DataFrame())
    for feat in FEATURES:
        ports = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute, 'separated', PERIOD,
                                      T, N_MIN, N_DAYS, 'score', 'csv'), sep=';', index_col=0)
        feat_df[feat.attribute] = ports.applymap(sign_to_score)

    list_combinations = [FEATURES]
    for feat in FEATURES:
        temp = FEATURES[:]
        temp.remove(feat)
        list_combinations.append(temp)

    threshold_anomalies = dict.fromkeys([str(l) for l in list_combinations], [])
    all_anomalies = dict.fromkeys([str(l) for l in list_combinations], [])

    for l in list_combinations:
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
        threshold_anomalies[str(l)] = ind_thr
        all_anomalies[str(l)] = ind_all

    unique_anomalies = set(['|'.join(el.split('|')[:-1]) for threshold
                            in threshold_anomalies.values() for el in threshold])

    final_array = pd.DataFrame(index=unique_anomalies, columns=[str(l) for l in list_combinations],
                               dtype=np.int8)
    for value in unique_anomalies:
        for l in list_combinations:
            for anomaly in all_anomalies[str(l)]:
                if value in anomaly:
                    final_array.loc[value, str(l)] = int(anomaly.split('|')[2])
                    break
            else:
                final_array.loc[value, str(l)] = 0

    fig, axis = plt.subplots()
    final = np.array(final_array, dtype=int)
    image = axis.imshow(final, cmap='YlOrRd')

    axis.set_xticks(np.arange(len(list_combinations)))
    axis.set_yticks(np.arange(len(unique_anomalies)))

    labels = ['all']
    labels.extend([feat.attribute for feat in FEATURES])
    axis.set_xticklabels(labels)
    axis.set_yticklabels([an.split('|')[0] + ' - ' + an.split('|')[1][0:2] + '/'
                          + an.split('|')[1][2:] for an in unique_anomalies])
    axis.tick_params(axis='both', which='major', labelsize=7)
    plt.setp(axis.get_xticklabels(), rotation=35, ha='right',
             rotation_mode='anchor')

    for i in range(len(unique_anomalies)):
        for j in range(len(list_combinations)):
            color = 'b' if final[i, j] > T_ANO else 'c'
            text = axis.text(j, i, final[i, j], ha='center', va='center', color=color, size=7)

    axis.set_title('Intensity of anomalies with features varying', size=9)
    fig.savefig(path_join(PATH_FIGURES, 'cor_features', T, N_MIN, N_DAYS, PERIOD, 'png'),
                dpi=600, bbox_inches='tight')

    for i, l in enumerate(list_combinations[1:]):
        rho_s, p_s = [round(val * 100, 1) for val in spearmanr(final_array.iloc[:, 0], final_array[str(l)])]
        print(labels[i+1], rho_s)

def main(argv):
    # original_subnets, sub_df, subnets = pre_computation()

    # plot_time_series(original_subnets)
    # compute_mse_feature(original_subnets)
    correlation_features()
    # cor_features_output()
    return 0

if __name__ == '__main__':
    main(sys.argv)
