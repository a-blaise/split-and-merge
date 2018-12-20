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

def value_to_yaxis(value):
    """Lambda function to replace each non-zero value by its y-number."""
    new_vector = value
    for i, element in enumerate(value):
        if element > 0:
            new_vector[i] = int(value.name)
    return new_vector

def heatmap_scores():
    """Draw a panorama of the occurrences of anomaly score
    (corresponds to the number of anomalies on one port for all features in all subnetworks)."""
    dict_font = dict(ha='center', va='center', size=4)
    test = pd.read_csv(path_join(PATH_EVAL, 'eval', FEATURES[0].attribute,
                              'separated', PERIOD, T, N_MIN,
                               N_DAYS, 'score', 'csv'), sep=';', index_col=0)

    dataset_sum = pd.DataFrame(columns=list(test.columns))
    for feat in FEATURES:
        feat_df = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                              'separated', PERIOD, T, N_MIN,
                               N_DAYS, 'score', 'csv'), sep=';', index_col=0)
        feat_df = feat_df.applymap(sign_to_score)
        dataset_sum = dataset_sum.add(feat_df, fill_value=0)

    result = dataset_sum.apply(pd.Series.value_counts)
    result = result.iloc[1:]
    annot_matrix = result.copy(deep=True)
    result.apply(value_to_yaxis, axis=1)
    data_annot = np.array(annot_matrix)
    data = np.array(result)

    fig, axis = plt.subplots()
    image = axis.imshow(data, cmap='YlOrRd', aspect=.7)

    axis.set_ylabel('Anomaly score', size=5)
    axis.set_xlabel('Time', size=5)

    axis.set_yticks(np.arange(data.shape[0]))
    axis.set_xticks(np.arange(data.shape[1]))

    axis.set_yticklabels([int(res) for res in result.index.values], size=4)
    dates = []
    axis.set_xticklabels(x[0:2] + '/' + x[2:] for i, x in enumerate(result.columns.values))

    axis.tick_params(width=0.5)

    # Rotate the tick labels and set their alignment.
    plt.setp(axis.get_xticklabels(), rotation=40, ha='right', rotation_mode='anchor', size=4)
    axis.spines['bottom'].set_linewidth(0.5)
    axis.spines['top'].set_linewidth(0.5)
    axis.spines['left'].set_linewidth(0.5)
    axis.spines['right'].set_linewidth(0.5)

    value = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_agg', PERIOD, 'csv'))

    # Loop over data dimensions and create text annotations.
    for i in range(0, data.shape[0]):
        for j in range(0, data.shape[1]):
            if not np.isnan(data_annot[i, j]):
                color = 'white' if i > 14 else 'black'
                text = axis.text(j, i, int(data_annot[i, j]), fontdict=dict_font, color=color)
                arrow_properties = dict(arrowstyle="->", lw=0.4)
                SIZE = 3.5

                if i > 10:
                    score = result.iloc[i,j]
                    df = dataset_sum.iloc[:, j]
                    port = df[df == score].index[0]
                    per = value[(value.date == int(DATES[N_DAYS + j])) & (value.port == int(port))]['nb_packets'] / 10 ** 6 * 1000
                    if len(list(per.to_dict().values())) > 0:
                        print(round(list(per.to_dict().values())[0], 2), int(port), int(DATES[N_DAYS + j]))
                    per = round(per, 2)

                # 2016
                # axis.annotate('DROWN attack', size=SIZE, xy=(0.5, 17), xytext=(2, 16), arrowprops=arrow_properties, )
                # text = axis.text(2, 16.7, 'port 993 - 0.4 %', color='black', size=SIZE)
                # axis.annotate('Abnormal activity', size=SIZE, xy=(13, 16.5), xytext=(8, 19), arrowprops=arrow_properties, )
                # text = axis.text(8, 19.7, 'port 6379 - 0.8 %', color='black', size=SIZE)
                # axis.annotate('Infiltration attempt', size=SIZE, xy=(19, 17.5), xytext=(16.5, 14), arrowprops=arrow_properties, )
                # text = axis.text(16.5, 14.7, 'port 6379 - 1.4 %', color='black', size=SIZE)
                # axis.annotate('Mirai scan', size=SIZE, xy=(24, 18.5), xytext=(25, 17), arrowprops=arrow_properties, )
                # text = axis.text(25, 17.7, 'port 23 - 39.4 %', color='black', size=SIZE)
                # axis.annotate('Mirai scan', size=SIZE, xy=(30.5, 20), xytext=(31.5, 19), arrowprops=arrow_properties, )
                # text = axis.text(31.5, 19.7, 'port 2323 - 5.0 %', color='black', size=SIZE)
                # axis.annotate('Mirai variant', size=SIZE, xy=(42, 20.5), xytext=(37, 18.5), arrowprops=arrow_properties, )
                # text = axis.text(37, 19.2, 'port 7547 - 4.5 %', color='black', size=SIZE)
                # axis.annotate('Mirai variant', size=SIZE, xy=(44, 17.5), xytext=(37, 15), arrowprops=arrow_properties, )
                # text = axis.text(37, 15.7, 'port 23231 - 8.9 %', color='black', size=SIZE)
                # axis.annotate('Mirai variant', size=SIZE, xy=(45, 17.5), xytext=(39, 13), arrowprops=arrow_properties, )
                # text = axis.text(39, 13.7, 'port 6789 - 10.2 %', color='black', size=SIZE)

                # 2017
                # axis.annotate('Hajime scan', size=SIZE, xy=(0.5, 17), xytext=(2, 16), arrowprops=arrow_properties)
                # text = axis.text(2, 16.8, 'port 5358 - 2.0 %', color='black', size=SIZE)
                # axis.annotate('Unindentified scan', size=SIZE, xy=(10, 16.5), xytext=(9, 19), arrowprops=arrow_properties)
                # text = axis.text(9, 19.8, 'port 993 - 0.8 %', color='black', size=SIZE)
                # axis.annotate('IOT botnet', size=SIZE, xy=(21, 17.5), xytext=(20, 20), arrowprops=arrow_properties)
                # text = axis.text(20, 20.8, 'port 81 - <0.1 %', color='black', size=SIZE)
                # axis.annotate('Scan drop', size=SIZE, xy=(30, 20.5), xytext=(25, 15), arrowprops=arrow_properties)
                # text = axis.text(25, 15.8, 'port 23 - 25.8 %', color='black', size=SIZE)
                # axis.annotate('Scan drop', size=SIZE, xy=(31, 18.5), xytext=(25, 15), arrowprops=arrow_properties)
                # axis.annotate('Scan drop', size=SIZE, xy=(32, 17.5), xytext=(25, 15), arrowprops=arrow_properties)
                # axis.annotate('Satori botnet', size=SIZE, xy=(50, 19.5), xytext=(44, 16), arrowprops=arrow_properties)
                # axis.annotate('Satori botnet', size=SIZE, xy=(50.5, 16), xytext=(44, 16), arrowprops=arrow_properties)
                # text = axis.text(44, 16.8, 'port 37215 - <0.1 %', color='black', size=SIZE)
                # axis.annotate('Satori botnet', size=SIZE, xy=(50.5, 15), xytext=(45, 13.5), arrowprops=arrow_properties)
                # text = axis.text(45, 14.3, 'port 52869 - <0.1 %', color='black', size=SIZE)

                # 2018
                axis.annotate('Massive scan', size=SIZE, xy=(5, 14.5), xytext=(5, 13), arrowprops=arrow_properties)
                axis.annotate('Massive scan', size=SIZE, xy=(9, 15.5), xytext=(5, 13), arrowprops=arrow_properties)
                text = axis.text(5, 13.8, 'port 81 - 0.5 %', color='black', size=SIZE)
                axis.annotate('Memcached', size=SIZE, xy=(7.8, 11.8), xytext=(9.1, 12.3), arrowprops=arrow_properties)
                text = axis.text(9.1, 13, 'port 11211 - 0.2%', color='black', size=SIZE)
                axis.annotate('ADB.Miner', size=SIZE, xy=(6.2, 15.5), xytext=(2.5, 16.5), arrowprops=arrow_properties)
                text = axis.text(2.5, 17.3, 'port 5555 - 0.6 %', color='black', size=SIZE)
                axis.annotate('Massive scan', size=SIZE, xy=(13, 16.5), xytext=(11.5, 14.5), arrowprops=arrow_properties)
                text = axis.text(11.5, 15.3, 'port 2000 - 2.8 %', color='black', size=SIZE)
                axis.annotate('Hajime scan', size=SIZE, xy=(12.5, 18), xytext=(8, 17.5), arrowprops=arrow_properties)
                text = axis.text(8, 18.3, 'port 8291 - 0.3 %', color='black', size=SIZE)
                axis.annotate('Scan break', size=SIZE, xy=(17, 15.5), xytext=(18, 17), arrowprops=arrow_properties)
                axis.annotate('Scan break', size=SIZE, xy=(16, 16.5), xytext=(18, 17), arrowprops=arrow_properties)
                text = axis.text(18, 17.8, 'port 23 - 23.7 %', color='black', size=SIZE)
                axis.annotate('Exploit', size=SIZE, xy=(25, 15.5), xytext=(26, 17), arrowprops=arrow_properties)
                text = axis.text(26, 17.8, 'port 60001 - 0.2 %', color='black', size=SIZE)
                axis.annotate('Credential leak (Netwave)', size=SIZE, xy=(35, 15.5), xytext=(37, 17), arrowprops=arrow_properties)
                text = axis.text(37, 17.8, 'port 8000 - 0.3 %', color='black', size=SIZE)

    if not os.path.exists(PATH_FIGURES):
        os.mkdir(PATH_FIGURES)
    fig.savefig(path_join(PATH_FIGURES, 'heatmap', N_MIN, N_DAYS, PERIOD, 'png'),
                dpi=1000, bbox_inches='tight')

def get_sum_string(element):
    """Lambda function to sum two given scores, e.g., '+5, -4' becomes 9."""
    total = 0
    for char in list(str(element)):
        if char.isdigit():
            total += int(char)
    return total

def heatmap_anomalies():
    """Draw a better characterization of each major anomaly
    by providing the change in features this day."""
    l_anomalies, l_annot, labels = ([] for i in range(3))
    ports_annot = pd.read_csv(path_join(PATH_EVAL, 'eval_total_separated', PERIOD,
                                        T, N_MIN, N_DAYS, 'score', 'csv'), sep=';', index_col=0)
    ports = ports_annot.applymap(sign_to_score)
    ports = ports.loc[(ports > T_ANO).any(axis=1)]

    for index, row in ports.iterrows():
        for i, date in enumerate(DATES[N_DAYS:]):
            if row[i] > T_ANO:
                anomalies, annot = ([] for j in range(2))
                labels.append('port ' + str(index) + '\non ' + date[0:2] + '/' + date[2:])
                for feat in FEATURES:
                    if feat.attribute != 'nb_packets':
                        evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                                           'separated', PERIOD, T, N_MIN, N_DAYS,
                                                           'score', 'csv'), sep=';')
                        rep = evaluation[evaluation.port == index].loc[:, date]
                        anomalies.append(get_sum_string(rep.item()) if not rep.empty
                                         and str(rep.item() != 'nan') else 0)
                        annot.append(rep.item() if not rep.empty
                                           and str(rep.item() != 'nan') else 0)
                l_anomalies.append(anomalies)
                l_annot.append(annot)

    col = [feat.attribute for feat in FEATURES if feat.attribute != 'nb_packets']
    heatmap, heatmap_annot = [pd.DataFrame(l, columns=col, index=labels) for l in [l_anomalies, l_annot]]
    data, data_annot = [np.array(hm) for hm in [heatmap, heatmap_annot]]

    fig, axis = plt.subplots()
    image = axis.imshow(data, cmap='YlOrRd', aspect=.45)

    axis.set_ylabel('Anomaly ID')
    axis.set_xlabel('Feature')

    axis.set_xticks(np.arange(data.shape[1]))
    axis.set_yticks(np.arange(data.shape[0]))
    axis.set_yticklabels(labels)
    axis.set_xticklabels(['srcDivInd', 'dstDivInd', 'portDivInd', 'meanSize', 'stdSize', 'perSyn'])

    plt.setp(axis.get_xticklabels(), rotation=20, ha='right', rotation_mode='anchor')

    for edge, spine in axis.spines.items():
        spine.set_visible(False)
    axis.set_xticks(np.arange(data.shape[1]+1)-.5, minor=True)
    axis.set_yticks(np.arange(data.shape[0]+1)-.5, minor=True)
    axis.grid(which='minor', color='w', linestyle='-', linewidth=3)
    axis.tick_params(which='minor', bottom=False, left=False)

    axis.set_yticklabels(labels)
    axis.set_xticklabels(col)

    dict_font = dict(ha='center', va='center', size=10)
    for i in range(data.shape[0]):
        for j in range(data.shape[1]):
            annot = str(data_annot[i, j]).split(',')
            if len(annot) == 1:
                text = axis.text(j, i, '0', color='black', fontdict=dict_font)
            else:
                if '0' in annot[0]:
                    if '0' in annot[1]:
                        text = axis.text(j, i, '0', color='black', fontdict=dict_font)
                    else:
                        text = axis.text(j, i, annot[1], color=color(annot[1]),
                                         fontdict=dict_font)
                else:
                    if '0' in annot[1]:
                        text = axis.text(j, i, annot[0], color=color(annot[0]),
                                         fontdict=dict_font)
                    else:
                        text = axis.text(j, i-0.18, annot[0], color=color(annot[0]),
                                         fontdict=dict_font)
                        text = axis.text(j, i+0.18, annot[1], color=color(annot[1]),
                                         fontdict=dict_font)

    if not os.path.exists(PATH_FIGURES):
        os.mkdir(PATH_FIGURES)
    plt.show()
    fig.savefig(path_join(PATH_FIGURES, 'heatmap_anomalies', T, N_MIN,
                          N_DAYS, PERIOD, 'png'), dpi=600, bbox_inches='tight')

def color(pos):
    """Choose color of heatmap annotation based on the square color."""
    return 'white' if int(pos[1:]) > 6 else 'black'
    
def main(argv):
    heatmap_scores()
    # print_hm()
    # heatmap_anomalies()
    return 0

if __name__ == '__main__':
    main(sys.argv)
