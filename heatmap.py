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
    dict_font = dict(ha='center', va='center', size=5)
    test = pd.read_csv(path_join(PATH_EVAL, 'eval', FEATURES[0].attribute,
                              'separated', '2017-full', T, N_MIN,
                               N_DAYS, 'score', 'csv'), sep=';', index_col=0)

    dataset_sum = pd.DataFrame(columns=list(test.columns))
    for feat in FEATURES:
        feat_df = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                              'separated', '2017-full', T, N_MIN,
                               N_DAYS, 'score', 'csv'), sep=';', index_col=0)
        feat_df = feat_df.applymap(sign_to_score)
        dataset_sum = dataset_sum.add(feat_df, fill_value=0)

    result = dataset_sum.apply(pd.Series.value_counts)
    print(result)
    result = result.iloc[1:]
    annot_matrix = result.copy(deep=True)
    result.apply(value_to_yaxis, axis=1)
    data_annot = np.array(annot_matrix)
    data = np.array(result)

    fig, axis = plt.subplots()
    image = axis.imshow(data, cmap='YlOrRd', aspect=.7)

    axis.set_ylabel('Anomaly score', size=6)
    axis.set_xlabel('Time', size=6)

    axis.set_yticks(np.arange(data.shape[0]))
    axis.set_xticks(np.arange(data.shape[1]))

    axis.set_yticklabels([int(res) for res in result.index.values], size=5)
    dates = []
    for i, x in enumerate(result.columns.values):
        result = x[0:2] + '/' + x[2:]
        dates.append(result)
    axis.set_xticklabels(dates)

    # Rotate the tick labels and set their alignment.
    plt.setp(axis.get_xticklabels(), rotation=40, ha='right', rotation_mode='anchor', size=5)

    # Loop over data dimensions and create text annotations.
    for i in range(0, data.shape[0]):
        for j in range(0, data.shape[1]):
            if not np.isnan(data_annot[i, j]):
                color = 'white' if i > 15 else 'black'
                text = axis.text(j, i, int(data_annot[i, j]), fontdict=dict_font, color=color)

    if not os.path.exists(PATH_FIGURES):
        os.mkdir(PATH_FIGURES)
    fig.savefig(path_join(PATH_FIGURES, 'heatmap', T, N_MIN, N_DAYS, PERIOD, 'png'),
                dpi=600, bbox_inches='tight')

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
