import os

import numpy as np
from ip2geotools.errors import InvalidRequestError
from tensorflow import keras
import pandas as pd
import requests
from IDPBackend.models import Flow
from IDPBackend.models import TrafficStatus
import joblib
from django.core.mail import send_mail
from ip2geotools.databases.noncommercial import DbIpCity


def MachineLearningTesting(flowDataFrame):
    global x, conclusion

    print("It's prediction time.")

    saved_model = keras.models.load_model("model.tf")

    sc = joblib.load("Scaler.bin")
    columns = joblib.load("model-columns.pkl")

    label_encoder = joblib.load("LabelEncoder.pkl")

    try:
        x = pd.get_dummies(flowDataFrame.drop(['forward', 'Label', 'srcIP', 'Origin'], axis=1))
        x = x.reindex(columns=columns, fill_value=0)
    except KeyError:
        print("No flows detected.")
    except ValueError:
        print("Scan more")

    try:
        xTransformed = sc.transform(x)
    except UnboundLocalError:
        return -1

    pred = saved_model.predict(xTransformed.reshape(-1, len(x.columns)))


    pred_class = np.argmax(pred, axis=-1)

    predict = label_encoder.inverse_transform(pred_class)

    anomalyIndexes = np.max(pred, axis=1) < 0.75
    flowDataFrame["Label"] = predict
    flowDataFrame.loc[anomalyIndexes, "Label"] = 'Anomaly'
    print("\n",flowDataFrame["Label"],"\n")
    filteredPredict = predict[predict != 'Normal']

    values, counts = np.unique(filteredPredict, return_counts=True)
    print('counts', values)

    unique = np.count_nonzero(values)

    try:
        mostFrequentIndex = np.argmax(counts)
        conclusion = values[mostFrequentIndex]
    except ValueError:
        conclusion = "Normal"
        print('All normal.')

    print('unique', unique)
    # if unique >= 5:
    # conclusion = "Unique attack (undetermined)"

    # if conclusion != "Normal":
    # send_mail(
    # 'Incident reported',
    # 'Information: {}'.format(conclusion),
    # 'virmanasamp@gmail.com',
    # ['danielmackey13@live.co.uk'],
    # fail_silently=False,
    # )

    print("prediction:", predict)

    file_exists = os.path.isfile('Flow Dataframe.csv')
    flowDataFrame.to_csv('Flow Dataframe.csv', mode='a', header=not file_exists, index=False)

    flowDataFrame = flowDataFrame.reset_index()

    try:
        print(flowDataFrame[['forward', 'Auth Failures', 'Unique Ports', 'Origin']])
    except KeyError:
        print("Missing columns")

    if unique >= 2:
        TrafficStatus.objects.create(status='Multiple Threats')
    elif conclusion == "" or conclusion == "Normal":
        TrafficStatus.objects.create(status="Normal")
    else:
        TrafficStatus.objects.create(status=conclusion)

    Countries = {}

    for index, row in flowDataFrame.iterrows():
        try:
            flowRow = Flow.objects.get(forward=row['forward'])

            if row["Label"] == "Normal":
                flowRow.delete()

            else:
                try:
                    IP = Countries.get(row["srcIP"])

                    if IP is None:
                        geoinfo = DbIpCity.get(row["srcIP"], api_key="free")

                        flowRow.Origin = geoinfo.country
                        Countries[row["srcIP"]] = flowRow.Origin
                    else:
                        flowRow.Origin = Countries[row["srcIP"]]
                        flowRow.Label = row["Label"]

                    print('Label:', row["Label"])
                    flowRow.save()
                except(InvalidRequestError):
                    continue


        except Flow.DoesNotExist:
            print("Flow ID is invalid.")

    return conclusion

    if __name__ == "__main__":
        if not FlowFrame.empty:
            MachineLearningTesting(FlowFrame)
