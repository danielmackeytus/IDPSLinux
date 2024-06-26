import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.models import Sequential
from tensorflow.keras.callbacks import ModelCheckpoint
from tensorflow.keras.layers import Dense
from sklearn.metrics import accuracy_score
from sklearn import preprocessing
from sklearn.preprocessing import MinMaxScaler
from IDPBackend.models import TFMetrics
import joblib
import os
from joblib import dump
from imblearn.over_sampling import SMOTE


def MachineLearningTraining(Layers, Epochs):
    print('Loading training data directory.')
    file_list = os.listdir('TrainingData/')
    file_list

    TrainingData = pd.DataFrame()
    path = 'TrainingData/'
    print('Concatenating data sets.')
    for file in file_list:
        df_temp = pd.read_csv(path + file, sep=r'\s*,\s*', engine='python')
        TrainingData = pd.concat([TrainingData, df_temp])

    pd.set_option('use_inf_as_na', True)
    TrainingData.dropna(inplace=True)

    label_encoder = preprocessing.LabelEncoder()

    print('Encoding y values.')
    y = label_encoder.fit_transform(TrainingData['Label'])
    dump(label_encoder, 'LabelEncoder.pkl')

    print('Encoding x values.')
    x = pd.get_dummies(TrainingData.drop(['Label', ], axis=1))

    columns = x.columns
    joblib.dump(columns, 'model-columns.pkl')
    sc = MinMaxScaler()

    print('Fit & transform x values.')
    x = sc.fit_transform(x)

    print('Saving scaler.')
    dump(sc, 'Scaler.bin')

    print('Split train - test.')
    x_train, x_test, y_train, y_test = train_test_split(x, y, test_size=0.33, random_state=42)
    x_train, x_val, y_train, y_val = train_test_split(x_train, y_train, test_size=0.15, random_state=42)
    sm = SMOTE()
    x_train, y_train = sm.fit_resample(x_train, y_train)
    X = pd.DataFrame(x_train)

    print('Divising model & layers.')

    model = Sequential()

    activationLayer = Layers[0]['activation']
    nodes = Layers[0]['nodes']
    epoch = Epochs
    print('EPOCH', epoch)
    print('nodes', nodes)
    print('activationLayer', activationLayer)

    model.add(Dense(nodes, activation=activationLayer, input_shape=(len(X.columns),)))


    for x in range(1, len(Layers)):
        activationLayer = Layers[x]['activation']
        nodes = Layers[x]['nodes']
        model.add(Dense(nodes, activation=activationLayer))

    model.add(Dense(len(os.listdir('TrainingData')), activation='softmax'))

    print('Compiling model.')
    model.compile(loss='sparse_categorical_crossentropy', optimizer='adam', metrics='accuracy')

    print('Implementing early stopping.')
    early_stopping = EarlyStopping(monitor='val_loss', min_delta=0, patience=10, verbose=1, mode='auto')
    model_checkpoint = ModelCheckpoint(filepath='model.tf', monitor='val_loss', mode='min', save_best_only=True,
                                       verbose=1)
    print('Fitting x and y to model for training.')
    history = model.fit(x_train, y_train, epochs=int(epoch), batch_size=128, validation_data=(x_val, y_val),
                        callbacks=[early_stopping, model_checkpoint])


    TFMetrics.objects.create(accuracy=history.history['accuracy'][-1],loss=history.history['loss'][-1],
                             val_accuracy=history.history['val_accuracy'][-1],
                             val_loss=history.history['val_loss'][-1])

    print('Prediction vs actual.')
    y_test_pred = model.predict(x_test)

    pred_class = np.argmax(y_test_pred, axis=-1)
    validation_loss, validation_accuracy = model.evaluate(x_val, y_val)
    print("Validation Loss:", validation_loss)
    print("Validation Accuracy:", validation_accuracy)
    print('Accuracy score: ', accuracy_score(y_test, pred_class))

    return 0
    # f1Score = f1_score(y_test,pred_class,average='weighted')
    # print('F1 Score: ',f1Score)

    # if __name__ == "__main__":
    # MachineLearningTraining();
