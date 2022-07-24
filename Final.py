import keras
import subprocess
import pandas as pd
import numpy as np

dataset = pd.read_csv("./predictData2.csv")


columns = list(dataset)
features = columns
#features.remove('label')
features.remove('ip.src')
features.remove('ip.dst')
#features.remove('tcp.flags')
#features.remove('label')


dataset.replace([np.inf, -np.inf], np.nan, inplace=True)
dataset.fillna(dataset.mean(), inplace=True)

X = dataset[features].values
y = dataset.iloc[:, -9].values

from sklearn.preprocessing import StandardScaler
sc = StandardScaler()
X_Scaled = sc.fit_transform(X)


lstm3 = keras.models.load_model('./LSTMwithoutFlags.h5')

#"""Array reshape to 3D"""

#create dataset for LSTM
def create_dataset(X,Y,look_back=1):
	dataX, dataY = [], []
	for i in range(len(X)-look_back-1):
		a = X[i:(i+look_back)+1, :]
		dataX.append(a)
		dataY.append(Y[i + look_back, 0])
	return np.array(dataX), np.array(dataY)

y = y.reshape((len(y), 1))

# X_series, Y = create_dataset(X_Scaled,y, look_back = 30)
X_series, Y = create_dataset(X_Scaled,y, look_back = 30)

#"""#Get Ip src to an array"""

ipSrc = dataset['ip.src'].values

dataset

#"""#Predict using trained model"""

prediction = lstm3.predict(X_series)


#counting how many malicious packets in the dataset
count = 0
for i in range (2053):
  if prediction[i] == 1:
    count = count + 1
    
print("________________________________________________________________\n")
print("WARNING! There are %s malicious records have found!" % count)
print("________________________________________________________________")



ips = []
for i in range (1700):
  if prediction[i] == 1:
    ips.append(ipSrc[i])

    

ipsNew = list(dict.fromkeys(ips))

len(ipsNew)

print("________________________________________________________________\n")

for i in range (len(ipsNew)):
  print("The malicious ip %s will be DROPPED using FIREWALL!" % (ipsNew[i]))
  subprocess.run(["sudo","iptables", "-A", "INPUT", "-i", "enp0s3", "-s", ipsNew[i], "-j", "DROP" ])
  
print("________________________________________________________________")
