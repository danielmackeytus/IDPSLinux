import numpy as np
import tensorflow as tf
from tensorflow import keras
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn import metrics
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense
from sklearn.metrics import accuracy_score
import requests
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
from tensorflow.keras import Input, layers, Model
from IDPBackend.models import Flow
from IDPBackend.views import TrafficStatus
import joblib
from joblib import dump
import os


def MachineLearningTesting(flowDataFrame):

    print("It's prediction time.")

    saved_model = keras.models.load_model("model.tf")

    sc = joblib.load("Scaler.bin")
    columns = joblib.load("model-columns.pkl")

    label_encoder = joblib.load("LabelEncoder.pkl")
    
    try:
        x = pd.get_dummies(flowDataFrame.drop(['flowID','Label','srcIP'],axis=1))
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
    
    #count = np.count_nonzero(predict == "SSH Brute Force")
    
    #if count >= 3:
        #conclusion = "SSH Brute Force"
        
    print('unique',unique)
    if (unique >= 4 ):
       conclusion = "Unique attack (undetermined)"
       
    print("prediction:", predict)
    print("Traffic type:", conclusion)
    flowDataFrame = flowDataFrame.reset_index()
    print(flowDataFrame[['flowID', 'Auth Failures','Unique Ports']])
    for index, row in flowDataFrame.iterrows():
        try:
            flowRow = Flow.objects.get(flowID=row['flowID'])
 
            if row["Label"] == "Normal":
               flowRow.delete()
               
            elif row["Label"] != conclusion and conclusion != "Unique attack (undetermined)":
               flowRow.delete()
               
            else:
               flowRow.Label = conclusion
               flowRow.save()
         
        except Flow.DoesNotExist:
            print("Flow ID is invalid.")


    response = requests.post(
        "https://danielmackey.ie/api/TrafficStatus/", data={"status": conclusion}
    )
    return response

    if __name__ == "__main__":
        if not FlowFrame.empty:
            MachineLearningTesting(FlowFrame)

