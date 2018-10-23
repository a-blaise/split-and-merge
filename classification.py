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

from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from settings import *
from features import LIST_FEATURES
from full_detection import path_join, sign_to_score

class Class_anomaly():
    def __init__(self, description, *characs):
        self.description = description
        self.features = list(characs)

def clustering_anomalies():
    list_annot, indexes = ([] for i in range(2))

    ports_annot = pd.read_csv(path_join(PATH_EVAL, 'eval_total_separated', PERIOD, T, N_MIN,
                                        N_DAYS, 'score', 'csv'), sep=';', index_col=0)
    ports = ports_annot.applymap(sign_to_score)
    ports = ports.loc[(ports > T_ANO).any(axis=1)]

    for index, row in ports.iterrows():
        for i, date in enumerate(DATES[N_DAYS:]):
            if row[i] > T_ANO:
                annotations = []
                indexes.append('port ' + str(index) + ' on ' + date[0:2] + '/' + date[2:])
                for feat in LIST_FEATURES:
                    evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                                       'separated', PERIOD, T, N_MIN,
                                                       N_DAYS, 'score', 'csv'), sep=';')
                    rep = evaluation[evaluation.port == index].loc[:, date]
                    annotations.extend([int(rep.item().split(',')[sign]) for sign in range(2)]
                                       if not rep.empty and str(rep.item()) != 'nan' else [0, 0])
                list_annot.append(annotations)

    heatmap = pd.DataFrame(list_annot, columns=[sign + feat.attribute for feat in LIST_FEATURES
                                                for sign in ['+', '-']], index=indexes)

    # to_drop = ['nb_packets', 'SYN', 'port_div_index']
    
    to_drop = ['nb_packets']
    heatmap = heatmap.drop(['+' + feature for feature in to_drop], axis=1)
    heatmap = heatmap.drop(['-' + feature for feature in to_drop], axis=1)

    epsilon = 2.88
    # Set all vectors to the same scale
    heatmap_fit = StandardScaler().fit_transform(heatmap)
    dbscan = DBSCAN(eps=epsilon, min_samples=1).fit(heatmap_fit)
    labels = dbscan.labels_

    # print('Cluster ' + str(i + 1) + ':', [heatmap.iloc[j] for j, label in enumerate(labels)
    #                                       for i in range(len(set(labels))) if label == i])

def classify_anomalies(classes):
    list_annot, indexes = ([] for i in range(2))

    ports_annot = pd.read_csv(path_join(PATH_EVAL, 'eval_total_separated', PERIOD, T, N_MIN,
                                        N_DAYS, 'score', 'csv'), sep=';', index_col=0)
    ports = ports_annot.applymap(sign_to_score)
    ports = ports.loc[(ports > T_ANO).any(axis=1)]

    for index, row in ports.iterrows():
        for i, date in enumerate(DATES[N_DAYS:]):
            if row[i] > T_ANO:
                annotations = []
                indexes.append('port ' + str(index) + ' on ' + date[0:2] + '/' + date[2:])
                for feat in LIST_FEATURES:
                    evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                                       'separated', PERIOD, T, N_MIN,
                                                       N_DAYS, 'score', 'csv'), sep=';')
                    rep = evaluation[evaluation.port == index].loc[:, date]
                    annotations.extend([abs(int(rep.item().split(',')[sign])) for sign in range(2)]
                                       if not rep.empty and str(rep.item()) != 'nan' else [0, 0])
                list_annot.append(annotations)

    heatmap = pd.DataFrame(list_annot, columns=[sign + feat.attribute for feat in LIST_FEATURES
                                                for sign in ['+', '-']], index=indexes)

    to_drop = ['nb_packets']
    heatmap = heatmap.drop(['+' + feature for feature in to_drop], axis=1)
    heatmap = heatmap.drop(['-' + feature for feature in to_drop], axis=1)

    for cl in classes:
        temp = heatmap.copy()
        for feat in cl.features:
            temp = temp.loc[temp[feat] > 0]
        print(cl.description)
        print(temp)
            
def main(argv):
    classes = [Class_anomaly('scan from a single source', '-src_div_index', '+dst_div_index'),
               Class_anomaly('botnet behavior', '+src_div_index', '+dst_div_index'),
               Class_anomaly('botnet behavior', '+src_div_index', '+dst_div_index')]

    # clustering_anomalies()
    classify_anomalies(classes)
    return 0

if __name__ == '__main__':
    main(sys.argv)
