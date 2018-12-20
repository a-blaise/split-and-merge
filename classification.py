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
from features import FEATURES

class Anomaly:
    def __init__(self, port, date):
        self.port = port
        self.date = date

class Class_anomaly():
    def __init__(self, description, characs, *ant):
        self.description = description
        self.features = characs
        self.antecedent = ant if ant else None
        self.anomalies = pd.DataFrame()

def clustering_anomalies():
    list_annot = []
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

    ports = dataset_sum.copy()
    ports = ports.loc[(ports > T_ANO).any(axis=1)]

    for index, row in ports.iterrows():
        for i, date in enumerate(DATES[N_DAYS:]):
            if row[i] > T_ANO:
                annotations = [index, date]
                for feat in FEATURES:
                    evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                                       'separated', PERIOD, T, N_MIN,
                                                       N_DAYS, 'score', 'csv'), sep=';', index_col=0)
                    if index in list(evaluation.index):
                        rep = evaluation.loc[index, date]
                        if str(rep) != 'nan':
                            if rep:
                                annotations.extend([int(rep.split(',')[sign]) for sign in range(2)])
                            else:
                                annotations.extend([0, 0])
                    else:
                        annotations.extend([0, 0])
                list_annot.append(annotations)

    columns = ['port', 'date']
    columns.extend([sign + feat.attribute for feat in FEATURES for sign in SIGNS])
    heatmap = pd.DataFrame(list_annot, columns=columns)

    # to_drop = ['port_div_index']
    # heatmap = heatmap.drop([sign + feature for sign in SIGNS for feature in to_drop], axis=1)

    epsilon = 3.4
    heatmap_fit = StandardScaler().fit_transform(heatmap)
    dbscan = DBSCAN(eps=epsilon, min_samples=1).fit(heatmap_fit)
    labels = dbscan.labels_
    n_clusters_ = len(set(labels))

    for i in range(n_clusters_):
        specs = []
        anomalies = pd.DataFrame(columns=heatmap.columns)
        for j in range(len(labels)):
            if labels[j] == i:
                anomalies = anomalies.append(heatmap.iloc[j])
                
        anomalies = anomalies.rename(index=str, columns={'-src_div_index': '-src', '+src_div_index': '+src',
                                                 '-dst_div_index': '-dst', '+dst_div_index': '+dst',
                                                 '-port_div_index': '-port', '+port_div_index': '+port',
                                                 '-mean_size': '-meanSz', '+mean_size': '+meanSz',
                                                 '-std_size': '-stdSz', '+std_size': '+stdSz'})
        print(anomalies)

def classify_anomalies(classes):
    list_annot = []
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
    dataset_sum.to_csv(path_join(PATH_EVAL, 'eval', 'all', 'separated', PERIOD,
                                 T, N_MIN, N_DAYS, 'score', 'csv'), sep=';')

    ports = dataset_sum.copy()
    ports = ports.loc[(ports > T_ANO).any(axis=1)]

    for index, row in ports.iterrows():
        for i, date in enumerate(DATES[N_DAYS:]):
            if row[i] > T_ANO:
                annotations = [index, date]
                for feat in FEATURES:
                    evaluation = pd.read_csv(path_join(PATH_EVAL, 'eval', feat.attribute,
                                                       'separated', PERIOD, T, N_MIN,
                                                       N_DAYS, 'score', 'csv'), sep=';', index_col=0)
                    if index in list(evaluation.index):
                        rep = evaluation.loc[index, date]
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

    dict_categories = dict.fromkeys(range(len(heatmap.values)), '')
    for cl in classes:
        temp = heatmap.copy()
        for feat in cl.features:
            contrary_feat = SIGNS[(SIGNS.index(feat[0])+1)%2] + feat[1:]
            temp = temp.loc[abs(temp[feat]) > 1]
            temp = temp.loc[temp[contrary_feat] < 2]
        
        ant = [cla.anomalies for cla in classes if cla.description == 'Botnet scan'][0]
        if cl.antecedent:
            for cur_row in temp.iterrows():
                for ant_row in ant.iterrows():
                    if cur_row[1]['port'] == ant_row[1]['port'] and int(cur_row[1]['date']) > int(ant_row[1]['date']):
                        cl.anomalies = cl.anomalies.append(cur_row[1])
            if not cl.anomalies.empty:
                cl.anomalies = cl.anomalies.drop_duplicates()
        else:
            cl.anomalies = temp

        indices = list(cl.anomalies.index)
        if indices:
            for ind in indices:
                new_index = cl.description
                if type(ind) == int and heatmap.iloc[ind]['-port_div_index'] > 1 and heatmap.iloc[ind]['+port_div_index'] == 0:
                    new_index += ';spoofed port'
                dict_categories[ind] = new_index
    for cl in classes:
        heatmap.rename(index=dict_categories, inplace=True)
    heatmap = heatmap.rename(index=str, columns={"-src_div_index": "-src", "+src_div_index": "+src",
                                                 "-dst_div_index": "-dst", "+dst_div_index": "+dst",
                                                 "-port_div_index": "-port", "+port_div_index": "+port",
                                                 "-mean_size": "-meanSz", "+mean_size": "+meanSz",
                                                 "-std_size": "-stdSz", "+std_size": "+stdSz"})
    
    print(heatmap)

def additional_infos(subnets):
    packets = pd.read_csv(path_join(PATH_PACKETS, 'packets_subnets_separated', PERIOD, 'csv'),
                          dtype={'nb_packets': int})
    packets = packets[packets.nb_packets > N_MIN]
    anomalies = [Anomaly(5555, '0215')]

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
                    print(feat.attribute)
                for k, v in feat.sub_time_vect.items():
                    if date == date_an:
                        if not np.isnan(v[i]):
                            if feat.attribute != 'nb_packets':
                                print(k)
                                if DATES[i] == date_an:
                                    median = np.nanmedian(v[i - N_DAYS:i])
                                    mad = np.nanmedian([np.abs(y - median)
                                                        for y in v[i - N_DAYS:i]])
                                    mzscore = 0.6745 * (v[i] - median) / mad
                                    print(v[i - N_DAYS:i], v[i], round(median, 2), round(mad, 2), round(mzscore, 2))

def main(argv):
    original_subnets, sub_df, subnets = pre_computation()
    # peut etre if nb packets, then invert all next day
    
    classes = [Class_anomaly('More normal packets', ['+mean_size', '+std_size']),
               Class_anomaly('More forged packets', ['-mean_size', '-std_size']),
               Class_anomaly('Large scan', ['-src_div_index', '+dst_div_index', '-mean_size']),
               Class_anomaly('DDoS', ['+src_div_index', '-dst_div_index']),
               Class_anomaly('Botnet scan', ['+src_div_index', '+dst_div_index', '-mean_size']),
               Class_anomaly('Botnet expansion', ['+src_div_index', '+dst_div_index', '-std_size']),
               Class_anomaly('Targeted scan', ['-src_div_index', '-dst_div_index']),
               Class_anomaly('Less botnet scan', ['-src_div_index', '-dst_div_index', '+mean_size', '+std_size'])]

    # clustering_anomalies()
    classify_anomalies(classes)
    # additional_infos(subnets)
    return 0

if __name__ == '__main__':
    main(sys.argv)
