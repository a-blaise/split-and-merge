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

import matplotlib.pyplot as plt
from matplotlib.ticker import MaxNLocator

from settings import *
from features import FEATURES

class Anomaly:
    def __init__(self, port, date):
        self.port = port
        self.date = date

def anomalies_ndays(subnets):
    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]  
    ports = packets.port.unique()
  
    # Compute anomalies by varying the number of days in the model
    # files = dict.fromkeys(NB_DAYS, [open(path_join(PATH_EVAL, 'anomalies', 'N_DAYS', PERIOD,
    #                                      nb_day, 'txt'), 'a') for nb_day in NB_DAYS])
    files = {}
    for nb_day in NB_DAYS:
        files[nb_day] = open(path_join(PATH_EVAL, 'anomalies', 'N_DAYS', PERIOD, nb_day,
                            'txt'), 'a')

    for port in ports:
        packets_port = packets[packets.port == port]
        tmp_anomalies = {} # key = port | date | nb_day ; value = int (nb occurrences)
        for feat in FEATURES:
            feat.reset_object()
            for subnet in subnets:
                del feat.time_vect[:]
                packets_sub = packets_port[packets_port.key == subnet]
                for i, date in enumerate(DATES):
                    rep = packets_sub[packets_sub.date == int(date)]
                    feat.time_vect.append(rep[feat.attribute].item() if not rep.empty else np.nan)
                    if i > len(DATES) - LEN_PERIOD:
                        for nb_day in NB_DAYS:
                            median = np.nanmedian(feat.time_vect[i - nb_day:i])
                            mad = np.nanmedian([np.abs(y - median)
                                                for y in feat.time_vect[i - nb_day:i]])
                            mzscore = 0.6745 * (feat.time_vect[i] - median) / mad
                            if np.abs(mzscore) > T:
                                id_anomaly = '|'.join([str(port), date, str(nb_day)])
                                if id_anomaly in tmp_anomalies:
                                    tmp_anomalies[id_anomaly] += 1
                                else:
                                    tmp_anomalies[id_anomaly] = 1

        for id_anomaly, nb_occur in tmp_anomalies.items():
            n_day = int(id_anomaly.split('|')[-1])
            new_id = '|'.join(id_anomaly.split('|')[:2])
            files[n_day].write(new_id + '|' + str(nb_occur) + ',')

def anomalies_nmins(subnets):
    files = dict.fromkeys(NB_MINS, [open(path_join(PATH_EVAL, 'anomalies', 'N_MIN', PERIOD,
                                         nb_min, 'txt'), 'a') for nb_min in NB_MINS])

    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    for nb_min in NB_MINS:
        packets = packets[packets.nb_packets > nb_min]
        ports = packets.port.unique()

        # count anomalies by each port / date
        for port in ports:
            packets_port = packets[packets.port == port]
            tmp_anomalies = {} # key = port | date | nb_min ; value = int (nb occurrences)
            for feat in FEATURES:
                feat.reset_object()
                for subnet in subnets:
                    del feat.time_vect[:]
                    packets_sub = packets_port[packets_port.key == subnet]
                    for i, date in enumerate(DATES):
                        rep = packets_sub[packets_sub.date == int(date)]
                        feat.time_vect.append(rep[feat.attribute].item()
                                              if not rep.empty else np.nan)
                        if i > N_DAYS:
                            median = np.nanmedian(feat.time_vect[i - N_DAYS:i])
                            mad = np.nanmedian([np.abs(y - median)
                                                for y in feat.time_vect[i - N_DAYS:i]])
                            mzscore = 0.6745 * (feat.time_vect[i] - median) / mad
                            if np.abs(mzscore) > T:
                                id_anomaly = '|'.join([str(port), date, str(nb_min)])
                                if id_anomaly in tmp_anomalies:
                                    tmp_anomalies[id_anomaly] += 1
                                else:
                                    tmp_anomalies[id_anomaly] = 1
            
            for id_anomaly, nb_occur in tmp_anomalies.items():
                n_min = int(id_anomaly.split('|')[-1])
                new_id = '|'.join(id_anomaly.split('|')[:2])
                files[n_min].write(new_id + '|' + str(nb_occur) + ',')

def plot_results(type_comparison):
    intervals = NB_MINS if type_comparison == 'N_MIN' else NB_DAYS

    files = {}
    nb_anomalies = dict.fromkeys(intervals, {})

    for interval in intervals:
        files[interval] = open(path_join(PATH_EVAL, 'anomalies', type_comparison, PERIOD, interval, 'txt'), 'r')
        elements = files[interval].read().split(',')[:-1]
        files[interval].close()
        nb_anomalies[interval] = {}
        for threshold in THRESHOLDS:
            elements = list(filter(lambda an: int(an.split('|')[2]) > threshold, elements)) 
            nb_anomalies[interval][threshold] = len(list(set(elements)))

    fig, axis = plt.subplots()
    bin_width = 1 if type_comparison == 'N_MIN' else 0.2
    widths = np.arange((-len(THRESHOLDS) + 1) / 2, (len(THRESHOLDS) + 1) / 2, bin_width)

    for i, threshold in enumerate(THRESHOLDS):
        points = []
        for interval in intervals:
            points.append(nb_anomalies[interval][threshold])
        axis.bar([inter + widths[i] for inter in intervals], points, width=bin_width, label='threshold = ' + str(threshold))
    
    axis.set_xticks([inter - 4 for inter in intervals])
    axis.set_xticklabels(intervals)

    axis.set_xlabel(r'$N_{days}$' if type_comparison == 'N_DAYS'
                    else r'$N_{min}$')
    axis.set_ylabel('Number of anomalies')
    axis.legend()

    fig.savefig(path_join(PATH_FIGURES, 'thresholds', type_comparison, 'png'), dpi=800)


def plot_results_2(type_comparison):
    intervals = NB_MINS if type_comparison == 'N_MIN' else NB_DAYS

    files = {}
    nb_anomalies = dict.fromkeys(intervals, {})

    for interval in intervals:
        files[interval] = open(path_join(PATH_EVAL, 'anomalies', type_comparison, PERIOD, interval, 'txt'), 'r')
        elements = files[interval].read().split(',')[:-1]
        files[interval].close()
        nb_anomalies[interval] = {}
        for threshold in THRESHOLDS:
            elements = list(filter(lambda an: int(an.split('|')[2]) > threshold, elements)) 
            nb_anomalies[interval][threshold] = len(list(set(elements)))

    fig, axis = plt.subplots()
    bin_width = 0.2
    widths = np.arange((-len(THRESHOLDS) + 1) / 2, (len(THRESHOLDS) + 1) / 2, bin_width)

    for i, interval in enumerate(intervals):
        points = []
        for threshold in THRESHOLDS:
            points.append(nb_anomalies[interval][threshold])
        axis.bar([threshold + widths[i] for threshold in THRESHOLDS], points, width=bin_width, label=r'$N_{days}$ = ' + str(interval))

    # axis.set_xticks([inter - 4 for inter in intervals])
    # axis.set_xticklabels(intervals)

    axis.set_xticks([threshold - 4 for threshold in THRESHOLDS])
    # axis.set_xticklabels(intervals)

    axis.set_xlabel('Threshold')
    axis.set_ylabel('Number of anomalies')
    axis.legend()

    fig.savefig(path_join(PATH_FIGURES, 'thresholds_2', type_comparison, 'png'), dpi=300)

def comparison(type_comparison, baseline, intervals):
    files = {}
    anomalies = dict.fromkeys(intervals, {})

    for interval in intervals:
        files[interval] = open(path_join(PATH_EVAL, 'anomalies', type_comparison, PERIOD, interval, 'txt'), 'r')
        elements = files[interval].read().split(',')[:-1]
        files[interval].close()
        anomalies[interval] = list(set(list(filter(lambda an: int(an.split('|')[2]) > T_ANO, elements))))
        print(interval, anomalies)

    # Compare anomalies seen for each day with the baseline
    baseline_anomalies = anomalies[baseline] # list of anomalies
    list_over, list_under = ([] for i in range(2))

    for interval, anomalies in anomalies.items():
        list_over.append(len([item for item in anomalies if item not in baseline_anomalies])
                         if interval != baseline else 0)
        list_under.append(- len([item for item in baseline_anomalies if item not in anomalies])
                          if interval != baseline else 0)

    fig, axis = plt.subplots()
    bin_width = 4 if type_comparison == 'N_MIN' else 0.8
    axis.bar(intervals, list_over, width=bin_width)
    axis.bar(intervals, list_under, width=bin_width)
    axis.set_xticks(intervals)
    axis.set_xlabel(r'N_DAYS' if type_comparison == 'N_DAYS' else r'N_MIN')
    axis.set_ylabel('Number of anomalies in +/- compared to baseline')
    fig.savefig(path_join(PATH_FIGURES, 'comparison', type_comparison,
                          T_ANO, 'png'), dpi=300)

def comparison_threshold(type_comparison, baseline, intervals):
    files = {}
    anomalies = dict.fromkeys(intervals, {})

    for interval in intervals:
        files[interval] = open(path_join(PATH_EVAL, 'anomalies', type_comparison, PERIOD, interval, 'txt'), 'r')
        elements = files[interval].read().split(',')[:-1]
        files[interval].close()
        anomalies[interval] = {}
        for threshold in THRESHOLDS:
            anomalies[interval][threshold] = list(set(list(filter(lambda an: int(an.split('|')[2]) > threshold, elements))))

    # Compare anomalies seen for each day with the baseline
    baseline_anomalies = anomalies[baseline] # list of anomalies
    list_over, list_under = ({} for i in range(2))

    for threshold in THRESHOLDS:
        list_over[threshold], list_under[threshold] = ([] for i in range(2))
        for interval, anos in anomalies.items():
            list_over[threshold].append(len([item for item in anos[threshold] if item not in baseline_anomalies[threshold]])
                             if interval != baseline else 0)
            list_under[threshold].append(- len([item for item in baseline_anomalies[threshold] if item not in anos[threshold]])
                              if interval != baseline else 0)

    fig, axis = plt.subplots()
    bin_width = 2 if type_comparison == 'N_MIN' else 0.3
    widths = np.arange((-len(THRESHOLDS) + 1) / 2, (len(THRESHOLDS) + 1) / 2, bin_width)

    for i, threshold in enumerate(THRESHOLDS):
        if i < 4:
            axis.bar([inter + widths[i] for inter in intervals], list_over[threshold], width=bin_width, label='threshold = ' + str(threshold))
            axis.bar([inter + widths[i] for inter in intervals], list_under[threshold], width=bin_width)
    axis.set_xticks(intervals)
    axis.set_xlabel('Number of days in the model (N_DAYS)' if type_comparison == 'N_DAYS'
                    else 'Minimum number of packets to keep the port (N_MIN)')
    axis.set_ylabel('Number of anomalies in +/- compared to baseline')
    axis.legend()
    plt.show()
    # fig.savefig(path_join(PATH_FIGURES, 'comparison', type_comparison,
    #                       T_ANO, 'png'), dpi=300)

def accurate_comparison(type_comparison):
    intervals = NB_MINS if type_comparison == 'N_MIN' else NB_DAYS
    all_anomalies = dict.fromkeys(intervals, [])
    threshold_anomalies = dict.fromkeys(intervals, [])

    for interval in intervals:
        file = open(path_join(PATH_EVAL, 'anomalies', type_comparison, PERIOD, 
                              interval, 'txt'), 'r')
        anomalies = file.read().split(',')[:-1]
        anomalies = list(filter(lambda a: DATES.index(a.split('|')[1]) > len(DATES) - LEN_PERIOD, anomalies))
        file.close()
        all_anomalies[interval] = anomalies
        threshold_anomalies[interval] = list(filter(lambda a: int(a.split('|')[2]) > T_ANO,
                                                    anomalies))

    unique_anomalies = set(['|'.join(el.split('|')[:-1]) for threshold
                            in threshold_anomalies.values() for el in threshold])

    final_array = pd.DataFrame(index=unique_anomalies, columns=intervals, dtype=np.int8)
    for value in unique_anomalies:
        for interval in intervals:
            anomalies = all_anomalies[interval]
            for anomaly in anomalies:
                if value in anomaly:
                    final_array.loc[value, interval] = int(anomaly.split('|')[2])
                    break
            else:
                final_array.loc[value, interval] = 0

    final = np.array(final_array, dtype=int)

    fig, axis = plt.subplots()
    image = axis.imshow(final, cmap='YlOrRd')

    axis.set_xticks(np.arange(len(intervals)))
    axis.set_yticks(np.arange(len(unique_anomalies)))

    axis.set_xticklabels(intervals)
    axis.set_yticklabels([an.split('|')[0] + ' - ' + an.split('|')[1][0:2] + '/'
                          + an.split('|')[1][2:] for an in unique_anomalies])
    axis.tick_params(axis='both', which='major', labelsize=5)

    for i in range(len(unique_anomalies)):
        for j in range(len(intervals)):
            color = 'b' if final[i, j] > T_ANO else 'c'
            text = axis.text(j, i, final[i, j], ha='center', va='center', color=color, size=5)

    axis.set_title('Intensity of anomalies with ' + type_comparison + ' varying', size=7)
    fig.savefig(path_join(PATH_FIGURES, 'comparison', type_comparison, PERIOD, T_ANO, 'png'), dpi=600)

def additional_infos(subnets):
    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]
    
    anomalies = [Anomaly(21, '0908'), Anomaly(21, '0922'), Anomaly(22, '0825'), Anomaly(22, '0908'), Anomaly(22, '0915'),
                 Anomaly(23, '0825'), Anomaly(23, '0922'), Anomaly(23, '1006'), Anomaly(25, '0901'), Anomaly(25, '0908'),
                 Anomaly(25, '0825'), Anomaly(80, '1006'), Anomaly(80, '0825'), Anomaly(443, '1006'), Anomaly(443, '0901'),
                 Anomaly(443, '0908'), Anomaly(443, '0929'), Anomaly(587, '1020'), Anomaly(2323, '0916'),
                 Anomaly(3389, '0929'), Anomaly(8000, '0922')]

    for an in anomalies:
        port = an.port
        date_an = an.date
        each(lambda x: x.reset_object(), FEATURES)
        for subnet in subnets:
            for date in DATES:
                rep = packets[(packets.date == int(date)) & (packets.key == subnet) & (packets.port == port)]
                each(lambda x: x.time_vect.append(rep[x.attribute].item() if not rep.empty else np.nan), FEATURES)

            for feat in FEATURES:
                feat.sub_time_vect[subnet] = feat.time_vect[:]
                del feat.time_vect[:]

        for i, date in enumerate(DATES):
            if date == date_an:
                print('Anomaly', port, date_an)
            for feat in FEATURES:
                if date == date_an and feat.attribute != 'nb_packets':
                    print('Feature', feat.attribute)
                for k, v in feat.sub_time_vect.items():
                    if i > len(DATES) - LEN_PERIOD:
                        if not np.isnan(v[i]):
                            if feat.attribute != 'nb_packets' and date == date_an:
                                print('Subnet', k)
                                if DATES[i] == date_an:
                                    for nb_day in NB_DAYS:
                                        median = np.nanmedian(v[i - nb_day:i])
                                        mad = np.nanmedian([np.abs(y - median)
                                                            for y in v[i - nb_day:i]])
                                        mzscore = 0.6745 * (v[i] - median) / mad
                                        print(nb_day, v[i - nb_day:i], 'new', v[i], 'median', round(median, 2), 'mad', round(mad, 2), 'm-zscore', round(mzscore, 2))

def main(argv):
    original_subnets, sub_df, subnets = pre_computation()

    # anomalies_ndays(subnets)
    # anomalies_nmins(subnets)

    baseline_day = 10
    baseline_min = 20

    # plot_results('N_DAYS')
    # plot_results('N_MIN')

    plot_results_2('N_DAYS')
    plot_results_2('N_MIN')

    # comparison('N_DAYS', baseline_day)
    # comparison_threshold('N_DAYS', baseline_day)
    # comparison_threshold('N_MIN', baseline_min)

    # comparison('N_DAYS', baseline_day)
    # comparison('N_MIN', baseline_min)
    # accurate_comparison('N_MIN')
    # additional_infos(subnets)

if __name__ == '__main__':
    main(sys.argv)
