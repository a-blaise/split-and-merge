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

from settings import *
from features import FEATURES

def value_to_yaxis(value):
    """Lambda function to replace each non-zero value by its y-number."""
    new_vector = value
    for i, element in enumerate(value):
        if element > 0:
            new_vector[i] = int(value.name)
    return new_vector

def heat_map_scores():
    """Draw a panorama of the occurrences of anomaly score
    (corresponds to the number of anomalies on one port for all features in all subnetworks)."""
    dict_font = dict(ha='center', va='center', size=10)
    list_annot = []
    ports_annot = pd.read_csv(path_join(PATH_EVAL, 'eval_total_separated', PERIOD, T, N_MIN,
                                        N_DAYS, 'score', 'csv'), sep=';', index_col=0)
    ports = ports_annot.applymap(sign_to_score)
    # ports = ports.loc[(ports > T_ANO).any(axis=1)]
    ports_sum = pd.DataFrame(0, index=ports.index, columns=ports.columns)

    to_drop = ['nb_packets', 'SYN']
    feats = FEATURES[:]
    for feat in FEATURES:
        for el in to_drop:
            if feat.attribute == el:
                feats.remove(feat)

    for index, row in ports.iterrows():
        for i, date in enumerate(DATES[N_DAYS:]):
            annotations = [index, date]
            for feat in feats:
                evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                                   'separated', PERIOD, T, N_MIN,
                                                   N_DAYS, 'score', 'csv'), sep=';')
                rep = evaluation[evaluation.port == index][date]
                annotations.extend([abs(int(rep.item().split(',')[sign])) for sign in range(2)]
                                   if not rep.empty and str(rep.item()) != 'nan' else [0, 0])
            list_annot.append(annotations)

    columns = ['port', 'date']
    columns.extend([sign + feat.attribute for feat in feats for sign in SIGNS])
    heatmap = pd.DataFrame(list_annot, columns=columns)
    heatmap['AS_1'] = 0
    heatmap['AS_2'] = 0
    heatmap['AS_3'] = 0

    dict_features = dict.fromkeys([sign + feat.attribute for feat in feats for sign in SIGNS], 0)
    dict_max = dict.fromkeys([sign + feat.attribute for feat in feats for sign in SIGNS], 0)

    for index, row in heatmap.iterrows():
        heatmap.iloc[index, 12] = sum(row[2:11])
        for ind_f, feat in enumerate(feats):
            if int(row[2 + ind_f * 2]) > 1 and int(row[3 + ind_f * 2]) == 0:
                    heatmap.iloc[index, 13] += 1
                    dict_features['+' + feat.attribute] += 1
                    if int(row[2 + ind_f * 2]) > dict_max['+' + feat.attribute]:
                        dict_max['+' + feat.attribute] = int(row[2 + ind_f * 2])

            elif int(row[3 + ind_f * 2]) > 1 and int(row[2 + ind_f * 2]) == 0:
                    heatmap.iloc[index, 13] += 1
                    dict_features['-' + feat.attribute] += 1
                    if int(row[3 + ind_f * 2]) > dict_max['-' + feat.attribute]:
                        dict_max['-' + feat.attribute] = int(row[3 + ind_f * 2])

    for index, row in heatmap.iterrows():
        for ind_f, feat in enumerate(feats):
            result = np.abs(int(row[2 + ind_f * 2]) - int(row[3 + ind_f * 2]))
            if int(row[2 + ind_f * 2]) > int(row[3 + ind_f * 2]):
                result = result / (dict_features['+' + feat.attribute])  / (dict_max['+' + feat.attribute])
            else:
                result = result / (dict_features['-' + feat.attribute]) / (dict_max['-' + feat.attribute])
            if not np.isnan(result) and not np.isinf(result):
                heatmap.iloc[index, 14] += np.round(result, 2)
                ports_sum.loc[row[0], row[1]] += np.round(result, 2)
   
    print(heatmap)
    print(dict_features)
    print(dict_max)

    heatmap = heatmap.rename(index=str, columns={'-src_div_index': '-src', '+src_div_index': '+src',
                                                 '-dst_div_index': '-dst', '+dst_div_index': '+dst',
                                                 '-port_div_index': '-port', '+port_div_index': '+port',
                                                 '-mean_size': '-meanSz', '+mean_size': '+meanSz',
                                                 '-std_size': '-stdSz', '+std_size': '+stdSz'})

    print(ports_sum)
    
    # result = ports_sum.apply(pd.Series.value_counts)
    # print(result)

    # result2 = pd.DataFrame(data, columns=DATES[N_DAYS:], dtype=int)
    # annot_matrix = result2.copy(deep=True)
    # result2.apply(value_to_yaxis, axis=1)
    # data_annot = np.array(annot_matrix)
    # data = np.array(result2)

    # fig, axis = plt.subplots()
    # image = axis.imshow(data, cmap='YlOrRd', aspect=.7)

    # axis.set_ylabel('Anomaly score')
    # axis.set_xlabel('Time')

    # axis.set_yticks(np.arange(data.shape[0]))
    # axis.set_xticks(np.arange(data.shape[1]))

    # axis.set_yticklabels(result2.index.values)
    # axis.set_xticklabels([x[0:2] + '/' + x[2:] for x in result2.columns.values])

    # # Rotate the tick labels and set their alignment.
    # plt.setp(axis.get_xticklabels(), rotation=40, ha='right', rotation_mode='anchor')

    # # Loop over data dimensions and create text annotations.
    # for i in range(0, data.shape[0]):
    #     for j in range(0, data.shape[1]):
    #         if not np.isnan(data_annot[i, j]):
    #             color = 'white' if i > 12 else 'black'
    #             text = axis.text(j, i, int(data_annot[i, j]), fontdict=dict_font)

    # if not os.path.exists(PATH_FIGURES):
    #     os.mkdir(PATH_FIGURES)
    # fig.savefig(path_join(PATH_FIGURES, 'heatmap', T, N_MIN, N_DAYS, PERIOD, 'png'),
    #             dpi=600, bbox_inches='tight')

def print_hm():
    dict_font = dict(ha='center', va='center', size=10)
    data_hm = [[1440, 1400, 1445, 1409, 1374, 1412, 1449, 1495, 1523, 1512, 1512, 1500, 1516, 1486, 1493, 1525, 1495, 1490, 1511, 1479],
        [5, 2, 4, 7, 4, 3, 5, 1, 4, 4, 4, 2, 4, 5, 2, 1, 6, 11, 3, 3],
        [2, 6, 2, 1, 2, 5, 2, 3, 2, 4, 6, 6, 6, 4, 6, 7, 4, 2, 5, 4],
        [7, 8, 8, 11, 12, 9, 7, 6, 2, 5, 3, 7, 3, 6, 6, 4, 7, 10, 5, 5],
        [7, 14, 8, 5, 13, 10, 7, 4, 6, 7, 9, 4, 7, 12, 19, 4, 4, 6, 2, 7],
        [3, 5, 5, 7, 3, 8, 1, 2, 1, 6, 2, 4, np.nan, 2, 1, 1, 2, 2, 2, 8],
        [39, 60, 46, 46, 65, 47, 35, 17, 12, 16, 11, 20, 13, 23, 20, 12, 28, 22, 16, 22],
        [np.nan, 3, 5, 2, 1, 5, np.nan, 2, np.nan, 3, np.nan, 3, 3, 2, 2, 1, 1, 1, 2, 3],
        [7, 6, 9, 7, 9, 8, 5, 5, 3, 3, 1, np.nan, 2, 5, 2, 3, 2, 3, 4, 4],
        [3, 2, 3, 4, 1, 5, 4, 1, 4, 1, 3, 2, np.nan, 3, 1, 2, np.nan, 2, 2, 3],
        [1, 1, 1, 4, np.nan, 4, 4, 1, 3, np.nan, 1, 1, np.nan, 2, 1, 1, np.nan, 2, 1, 2],
        [43, 57, 33, 56, 72, 46, 43, 23, 10, 10, 15, 16, 13, 19, 14, 11, 14, 19, 16, 22],
        [np.nan, np.nan, 1, np.nan, 1, np.nan, 1, np.nan, np.nan, 1, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan],
        [13, 9, 9, 14, 12, 10, 7, 10, np.nan, 1, 4, 7, 4, 6, 3, 2, 8, 4, 3, 11],
        [np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, 1, np.nan, np.nan, 1],
        [np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, 1, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan],
        [np.nan, 1, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, 1, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan],
        [np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, 1, 1, np.nan],
        [np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, 1, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan],
        [np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, 1, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan],
        [np.nan, np.nan, np.nan, 1, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan],
        [np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, np.nan, 1, np.nan, 1, np.nan, np.nan, np.nan]]
    index = [0.00, 0.01, 0.02, 0.03, 0.04, 0.05, 0.06, 0.07, 0.08, 0.09, 0.10, 0.11, 0.12, 0.13, 0.14, 0.15, 0.18, 0.18, 0.24, 0.26, 0.28, 0.34]

    result2 = pd.DataFrame(data_hm, columns=DATES[N_DAYS:], index=index, dtype=int)
    result2 = result2.iloc[1:]
    annot_matrix = result2.copy(deep=True)
   
    result3 = result2.copy(deep=True)
    result3 = result3.reset_index()

    result3['index'] = result3['index'].apply(lambda x: 100 * x)
    result3 = result3.set_index('index')
    result3.apply(value_to_yaxis, axis=1)
    print(result3)
    data_annot = np.array(annot_matrix)
    data = np.array(result3)

    fig, axis = plt.subplots()
    image = axis.imshow(data, cmap='YlOrRd', aspect=.7)

    axis.set_ylabel('Anomaly score')
    axis.set_xlabel('Time')

    axis.set_yticks(np.arange(data.shape[0]))
    axis.set_xticks(np.arange(data.shape[1]))

    axis.set_yticklabels(result2.index.values)
    axis.set_xticklabels([x[0:2] + '/' + x[2:] for x in result2.columns.values])

    # Rotate the tick labels and set their alignment.
    plt.setp(axis.get_xticklabels(), rotation=40, ha='right', rotation_mode='anchor')

    # Loop over data dimensions and create text annotations.
    for i in range(0, data.shape[0]):
        for j in range(0, data.shape[1]):
            if not np.isnan(data_annot[i, j]):
                color = 'white' if i > 12 else 'black'
                text = axis.text(j, i, int(data_annot[i, j]), fontdict=dict_font)

    if not os.path.exists(PATH_FIGURES):
        os.mkdir(PATH_FIGURES)
    fig.savefig(path_join(PATH_FIGURES, 'heatmap', T, N_MIN, N_DAYS, PERIOD, 'png'),
                dpi=600, bbox_inches='tight')

# def heat_map_scores():
#     dict_font = dict(ha='center', va='center', size=10)
#     value = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_agg', PERIOD, 'csv'))
#     ports = pd.read_csv(path_join(PATH_EVAL, 'eval_total_separated', PERIOD, T,
#                                   N_MIN, N_DAYS, 'score', 'csv'), sep=';', index_col=0)
#     ports = ports.applymap(sign_to_score)
#     print(ports)
#     result = ports.apply(pd.Series.value_counts).iloc[1:]
#     annot_matrix = result.copy(deep=True)
#     result.apply(value_to_yaxis, axis=1)
#     data_annot = np.array(annot_matrix)
#     data = np.array(result)

#     fig, axis = plt.subplots()
#     image = axis.imshow(data, cmap='YlOrRd', aspect=.7)

#     axis.set_ylabel('Anomaly score')
#     axis.set_xlabel('Time')

#     axis.set_yticks(np.arange(data.shape[0]))
#     axis.set_xticks(np.arange(data.shape[1]))

#     axis.set_yticklabels(result.index.values)
#     axis.set_xticklabels([x[0:2] + '/' + x[2:] for x in result.columns.values])

#     # Rotate the tick labels and set their alignment.
#     plt.setp(axis.get_xticklabels(), rotation=40, ha='right', rotation_mode='anchor')

#     # Loop over data dimensions and create text annotations.
#     for i in range(0, data.shape[0]):
#         for j in range(0, data.shape[1]):
#             if not np.isnan(data_annot[i, j]):
#                 color = 'white' if i > 12 else 'black'
#                 text = axis.text(j, i, int(data_annot[i, j]), fontdict=dict_font)

#     if not os.path.exists(PATH_FIGURES):
#         os.mkdir(PATH_FIGURES)
#     fig.savefig(path_join(PATH_FIGURES, 'heatmap', T, N_MIN, N_DAYS, PERIOD, 'png'),
#                 dpi=600, bbox_inches='tight')

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
    heat_map_scores()
    # print_hm()
    # heatmap_anomalies()
    return 0

if __name__ == '__main__':
    main(sys.argv)
