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
from full_detection import path_join, pre_computation

class Anomaly:
    def __init__(self, port, date):
        self.port = port
        self.date = date

def anomalies_ndays(subnets, nb_days):
    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]  
    ports = packets.port.unique()
  
    # Compute anomalies by varying the number of days in the model
    files = {}
    for nb_day in nb_days:
        files[nb_day] = open(path_join(PATH_EVAL, 'anomalies', 'N_DAYS', PERIOD, nb_day, 'txt'), 'a')

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
                        for nb_day in nb_days:
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

def anomalies_nmins(subnets, nb_mins):
    files = {}
    for nb_min in nb_mins:
        files[nb_min] = open(path_join(PATH_EVAL, 'anomalies', 'N_MINS', PERIOD, nb_min, 'txt'), 'a')

    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    for nb_min in nb_mins:
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

def plot_results(type_comparison, intervals):
    files = {}
    nb_anomalies = dict.fromkeys(intervals, 0)

    for interval in intervals:
        files[interval] = open(path_join(PATH_EVAL, 'anomalies', PERIOD, type_comparison, interval, 'txt'), 'r')
        elements = files[interval].read()
        files[interval].close()
        nb_anomalies[interval] = len(elements.split(','))

    fig, axis = plt.subplots()
    axis.yaxis.set_major_locator(MaxNLocator(integer=True))
    bin_width = 4 if type_comparison == 'N_MINS' else 0.8
    axis.bar(intervals, list(nb_anomalies.values()), width=bin_width)
    axis.set_xticks(intervals)
    axis.set_xlabel('Number of days in the model (N_DAYS)' if type_comparison == 'N_DAYS'
                    else 'Minimum number of packets to keep the port (N_MIN)')
    axis.set_ylabel('Number of anomalies for this parameter')
    fig.savefig(path_join(PATH_FIGURES, 'results', type_comparison, T_ANO, 'png'), dpi=300)

def comparison(type_comparison, baseline, intervals):
    files = {}
    anomalies = dict.fromkeys(intervals, {})

    for interval in intervals:
        files[interval] = open(path_join(PATH_EVAL, 'anomalies', PERIOD, type_comparison, interval, 'txt'), 'r')
        elements = files[interval].read()
        files[interval].close()
        anomalies[interval] = elements.split(',')

    # Compare anomalies seen for each day with the baseline
    baseline_anomalies = anomalies[baseline] # list of anomalies
    list_over, list_under = ([] for i in range(2))

    for interval, anomalies in anomalies.items():
        list_over.append(len([item for item in anomalies if item not in baseline_anomalies])
                         if interval != baseline else 0)
        list_under.append(- len([item for item in baseline_anomalies if item not in anomalies])
                          if interval != baseline else 0)

    fig, axis = plt.subplots()
    bin_width = 4 if type_comparison == 'N_MINS' else 0.8
    axis.bar(intervals, list_over, width=bin_width)
    axis.bar(intervals, list_under, width=bin_width)
    axis.set_xticks(intervals)
    axis.set_xlabel('Number of days in the model (N_DAYS)' if type_comparison == 'N_DAYS'
                    else 'Minimum number of packets to keep the port (N_MIN)')
    axis.set_ylabel('Number of anomalies in +/- compared to baseline')
    fig.savefig(path_join(PATH_FIGURES, 'comparison', type_comparison,
                          T_ANO, 'png'), dpi=300)

def accurate_comparison(type_comparison, intervals):
    all_anomalies = dict.fromkeys(intervals, [])
    threshold_anomalies = dict.fromkeys(intervals, [])

    for interval in intervals:
        file = open(path_join(PATH_EVAL, 'anomalies', PERIOD, type_comparison, interval,
                              T_ANO, 'txt'), 'r')
        anomalies = file.read().split(',')[:-1]
        file.close()
        all_anomalies[interval] = anomalies
        threshold_anomalies[interval] = list(filter(lambda a: int(a.split('|')[2]) > T_ANO,
                                                    anomalies))

    unique_anomalies = []
    for threshold in threshold_anomalies.values():
        unique_anomalies.extend('|'.join(el.split('|')[:-1]) for el in threshold)
    unique_anomalies = set(unique_anomalies)

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
    axis.tick_params(axis='both', which='major', labelsize=7)

    for i in range(len(unique_anomalies)):
        for j in range(len(intervals)):
            if final[i, j] > T_ANO:
                color = "b"
            else:
                color = "c"
            text = axis.text(j, i, final[i, j], ha="center", va="center", color=color, size=7)

    axis.set_title('Intensity of anomalies with N_DAYS varying', size=9)
    fig.savefig(path_join(PATH_FIGURES, 'comparison', T, N_MIN, N_DAYS, PERIOD, 'png'),
                dpi=600, bbox_inches='tight')

def additional_infos(subnets, nb_days):
    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]
    
    anomalies = [Anomaly(21, '0908'), Anomaly(21, '0922'), Anomaly(22, '0825'), Anomaly(22, '0908'), Anomaly(22, '0915'),
                 Anomaly(23, '0825'), Anomaly(23, '0922'), Anomaly(23, '1006'), Anomaly(25, '0901'), Anomaly(25, '0908'),
                 Anomaly(25, '0825'), Anomaly(80, '1006'), Anomaly(80, '0825'), Anomaly(443, '1006'), Anomaly(443, '0901'),
                 Anomaly(443, '0908'), Anomaly(443, '0929'), Anomaly(587, '1020'), Anomaly(2323, '0916'),
                 Anomaly(3389, '0929'), Anomaly(8000, '0922')]

    # anomalies = [Anomaly(2323, '0901'), Anomaly(2323, '0908'), Anomaly(2323, '0915')]
    for an in anomalies:
        port = an.port
        date_an = an.date
        for feat in FEATURES:
            feat.reset_object()
        for subnet in subnets:
            for date in DATES:
                rep = packets[(packets.date == int(date)) & (packets.key == subnet) & (packets.port == port)]
                for feat in FEATURES:
                    feat.time_vect.append(rep[feat.attribute].item() if not rep.empty else np.nan)

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
                                    for nb_day in nb_days:
                                        median = np.nanmedian(v[i - nb_day:i])
                                        mad = np.nanmedian([np.abs(y - median)
                                                            for y in v[i - nb_day:i]])
                                        mzscore = 0.6745 * (v[i] - median) / mad
                                        print(nb_day, v[i - nb_day:i], 'new', v[i], 'median', round(median, 2), 'mad', round(mad, 2), 'm-zscore', round(mzscore, 2))

def main(argv):
    original_subnets, sub_df, subnets = pre_computation()

    nb_days = [8, 10, 13, 15, 18, 20]
    nb_mins = [20, 35, 50, 65, 80, 100]

    # anomalies_ndays(subnets, nb_days)
    anomalies_nmins(subnets, nb_mins)

    baseline_day = 10
    baseline_min = 20

    # plot_results('N_DAYS', nb_days)
    # comparison('N_DAYS', baseline_day, nb_days)
    # comparison('N_MINS', baseline_min, nb_mins)
    # accurate_comparison('N_DAYS', nb_days)
    # additional_infos(subnets, nb_days)

if __name__ == '__main__':
    main(sys.argv)
