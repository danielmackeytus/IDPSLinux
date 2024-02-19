import numpy as np
from tensorflow import keras
import pandas as pd
import requests
from IDPBackend.models import Flow
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

    values, counts = np.unique(predict, return_counts=True)

    unique = np.count_nonzero(values)

    mostFrequentIndex = np.argmax(counts)
    conclusion = values[mostFrequentIndex]

    # count = np.count_nonzero(predict == "SSH Brute Force")

    # if count >= 3:
    # conclusion = "SSH Brute Force"

    print('unique', unique)
    if unique >= 5:
        conclusion = "Unique attack (undetermined)"

    if conclusion != "Normal":
        send_mail(
            'Incident reported',
            'Information: {}'.format(conclusion),
            'virmanasamp@gmail.com',
            ['danielmackey13@live.co.uk'],
            fail_silently=False,
        )

    print("prediction:", predict)
    print("Traffic type:", conclusion)

    flowDataFrame = flowDataFrame.reset_index()
    print(flowDataFrame[['flowID', 'Auth Failures', 'Unique Ports', 'Origin']])

    for index, row in flowDataFrame.iterrows():
        try:
            flowRow = Flow.objects.get(flowID=row['flowID'])

            if row["Label"] == "Normal":
                flowRow.delete()

            elif row["Label"] != conclusion and conclusion != "Unique attack (undetermined)":
                flowRow.delete()

            else:
                geoinfo = DbIpCity.get(row["srcIP"], api_key="free")

                flowRow.Origin = geoinfo.country
                flowRow.Label = conclusion
                flowRow.save()


        except Flow.DoesNotExist:
            print("Flow ID is invalid.")

    response = requests.post(
        "https://localhost:8000/api/TrafficStatus/", data={"status": conclusion},
        verify=False

    )
    return response

    if __name__ == "__main__":
        if not FlowFrame.empty:
            MachineLearningTesting(FlowFrame)
