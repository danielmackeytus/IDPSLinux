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
from geopy.distance import distance


def MachineLearningTesting(flowDataFrame):
    global x
    print("It's prediction time.")

    saved_model = keras.models.load_model("model.tf")

    sc = joblib.load("Scaler.bin")
    columns = joblib.load("model-columns.pkl")

    label_encoder = joblib.load("LabelEncoder.pkl")

    try:
        x = pd.get_dummies(flowDataFrame.drop(['flowID', 'Label', 'srcIP','Origin'], axis=1))
        x = x.reindex(columns=columns, fill_value=0)
    except(KeyError):
        print("No flows detected.")
    except (ValueError):
        print("Scan more")

    try:
        xTranformed = sc.transform(x)
    except(UnboundLocalError):
        return -1

    pred = saved_model.predict(xTranformed.reshape(-1, len(x.columns)))
    pred_class = np.argmax(pred, axis=-1)

    predict = label_encoder.inverse_transform(pred_class)
    flowDataFrame["Label"] = predict

    filteredPredict = predict[predict != 'Normal']

    values, counts = np.unique(filteredPredict, return_counts=True)
    print('counts', values)

    unique = np.count_nonzero(values)

    mostFrequentIndex = np.argmax(counts)
    conclusion = values[mostFrequentIndex]



    print('unique', unique)
    #if unique >= 5:
        #conclusion = "Unique attack (undetermined)"

    #if conclusion != "Normal":
        #send_mail(
           # 'Incident reported',
           # 'Information: {}'.format(conclusion),
           # 'virmanasamp@gmail.com',
           # ['danielmackey13@live.co.uk'],
           # fail_silently=False,
        #)

    print("prediction:", predict)
    #print("Traffic type:", conclusion)

    file_exists = os.path.isfile('myass.csv')
    flowDataFrame.to_csv('myass.csv', mode='a', header=not file_exists, index=False)

    flowDataFrame = flowDataFrame.reset_index()
    print(flowDataFrame[['flowID', 'Auth Failures', 'Unique Ports', 'Origin']])

    if unique >= 2:
        TrafficStatus.objects.create(status='Multiple Anomalies')
    else:
        TrafficStatus.objects.create(status=conclusion)

    for index, row in flowDataFrame.iterrows():
        try:
            flowRow = Flow.objects.get(flowID=row['flowID'])

            if row["Label"] == "Normal":
                flowRow.delete()

            #elif row["Label"] != conclusion and conclusion != "Unique attack (undetermined)":
                #flowRow.delete()

            else:
                try:
                    #geoinfo = DbIpCity.get(row["srcIP"], api_key="free")
                    #print('geoinfo:', geoinfo)
                    geoinfo = "doesn't work."
                    print('Label:', row["Label"])
                    #flowRow.Origin = geoinfo.country
                    flowRow.Origin = geoinfo
                    #flowRow.Label = conclusion
                    flowRow.Label = row["Label"]
                    flowRow.save()
                except(InvalidRequestError):
                    continue


        except Flow.DoesNotExist:
            print("Flow ID is invalid.")


    #response = requests.post(
        #"https://localhost:8000/api/TrafficStatus/", data={"status": conclusion},
        #verify='/home/daniel/anaconda3/lib/python3.11/site-packages/sslserver/certs/development.crt'

    #)
    return conclusion

    if __name__ == "__main__":
        if not FlowFrame.empty:
            MachineLearningTesting(FlowFrame)
