# import tensorflow as tf
from tensorflow.keras.models import Sequential, save_model
from tensorflow.keras.layers import Dense, Dropout, BatchNormalization
from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import LabelEncoder, OneHotEncoder, StandardScaler
from tensorflow.keras.callbacks import EarlyStopping
import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from keras.utils import to_categorical


# Загрузка данных из CSV-файла
data = pd.read_csv('learn_data/com_att3.csv')

# Объединение столбцов
def combine_lists(row):
    ethernet_frame = np.array(eval(row['binary_ethernet_frame']))
    ip_packet = np.array(eval(row['binary_ip_packet']))
    transport_frag = np.array(eval(row['binary_transport_layer']))
    combined_list = np.concatenate((ethernet_frame, ip_packet, transport_frag))
    return combined_list


data['combined_list'] = data.apply(combine_lists, axis=1)
X = pd.DataFrame(data['combined_list'].apply(lambda x: [i for i in x]).tolist(), columns=[f'feature_{i}' for i in range(len(data['combined_list'].iloc[0]))])
y = pd.DataFrame(to_categorical(data['attack_type'], num_classes=4, dtype='int'), columns=[f'Class_{i}' for i in range(4)])


# Разделение данных
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Сохранение данных в файл
# X.to_csv('X_train.csv', index=False)
# X_test.to_csv('X_test.csv', index=False)
# pd.DataFrame(y_train, columns=[f'Class_{i}' for i in range(y_train.shape[1])]).to_csv('y_train.csv', index=False)
# pd.DataFrame(y_test, columns=[f'Class_{i}' for i in range(y_test.shape[1])]).to_csv('y_test.csv', index=False)
# print(X_train.shape[1])
# print(X_test.shape[1])
# print(y_train.shape[1])
# print(y_test.shape[1])

# Инициализация модели
model = Sequential()

# Добавление слоев
model.add(Dense(256, input_dim=X_train.shape[1], activation='relu'))
model.add(BatchNormalization())
model.add(Dropout(0.5))

model.add(Dense(256, activation='relu'))
model.add(BatchNormalization())
model.add(Dropout(0.5))

model.add(Dense(84, activation='relu'))
model.add(BatchNormalization())
model.add(Dropout(0.5))

model.add(Dense(y_test.shape[1], activation='softmax'))  # Многоклассовая классификация

# # Компиляция модели
model.compile(loss='categorical_crossentropy', optimizer='adam', metrics=['accuracy'])

# early_stopping = EarlyStopping(monitor='val_loss', patience=5, restore_best_weights=True)
# Обучение модели с использованием ранней остановки
history = model.fit(X_train, y_train, epochs=30, batch_size=32, validation_data=(X_test, y_test))
# , callbacks=[early_stopping]

# График_точности_модели
plt.figure(figsize=(12, 4))

plt.subplot(1, 2, 1)
plt.plot(history.history['accuracy'], label='Точность на обучающем наборе')
plt.plot(history.history['val_accuracy'], label='Точность на тестовом наборе')
plt.title('График точности модели')
plt.xlabel('Эпохи')
plt.ylabel('Точность')
plt.legend()

# График потерь модели
plt.subplot(1, 2, 2)
plt.plot(history.history['loss'], label='Потери на обучающем наборе')
plt.plot(history.history['val_loss'], label='Потери на тестовом наборе')
plt.title('График потерь модели')
plt.xlabel('Эпохи')
plt.ylabel('Потери')
plt.legend()

plt.tight_layout()
plt.show()

# Оценка модели на тестовом наборе данных
loss, accuracy = model.evaluate(X_test, y_test)
print(f"Точность на тестовом наборе данных: {accuracy * 100:.2f}%")
model.save('model1.keras')


