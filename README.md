# split-and-merge

This algorithm aims at detecting botnets that go under the radar. Our programs aims at detecting major changes in the usage of ports over time. For this purpose, several features located in the *Features.py* file characterize their usage. Moreover, the detection process is repeated in each subnetwork so that anomalies can then be aggregated to keep only the distributed ones. Thus, each day, for each port and each feature, the new value in the given subnetwork is compared to the *N_days* previous ones through a modified Z-score measure. An anomaly is detected if the modified Z-score exceed a given threshold *T*.

## Put settings

First, you should adjust the settings to your convenience in the *Settings.py* file.
Don't forget to put the folder where you want to save generated files in variable *ROOT_PATH*.
The threshold *T* for an anomaly better vary between 2.5 and 4, and here we chose a value of 3.5.
The period you want to work is either 2016 or 2018.

You also have to put these settings in the *main.cpp* file. Here choose the same period than in *Settings.py* and use the matching list of dates.

## Download MAWI files and generate CSV file based on them

First, ensure that you are connected to the Internet and launch the *get_pcaps.py* script to download the pcap files situated in MAWI website. You can now run the *get_pcaps.py* script.

Then, install the Libtins library as described in http://libtins.github.io/download/, depending on your Operating System. Then, run the C++ file *main.cpp* to convert the pcap files into csv files and keep only the needed packets attributes.
To do that, you can follow the next steps:
```
cd generate_csvs/build-dir/
cmake ..
make
./get_csvs
```

## Launch full detection process

Before launching any Python file, install requirements found in the *requirements.txt* file. Hence you can run:
```
pip install requirements.txt
```

Then you'll be able to run the *full_detection.py* file. This computes features for each port each day in each subnetwork, then launch the anomaly detection process in several subnetworks of MAWI and generates eval_feature files with the results.

## Draw heatmap to show results
The *heatmap.py* file enables to print the results. The first function shows a panorama of the occurrences of the intensity of anomalies for the given period, while the second function shows the main anomalies precisely, providing the evolution of each feature to better characterize the anomalies.