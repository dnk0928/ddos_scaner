import pandas as pd
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from tensorflow.keras.models import load_model
from sklearn.model_selection import train_test_split
import numpy as np


# Загрузка данных из CSV-файла
data = pd.read_csv('learn_data/test_cur2.csv')


def combine_lists(row):
    ethernet_frame = np.array(eval(row['binary_ethernet_frame']))
    ip_packet = np.array(eval(row['binary_ip_packet']))
    transport_frag = np.array(eval(row['binary_transport_layer']))
    combined_list = np.concatenate((ethernet_frame, ip_packet, transport_frag))
    return combined_list


data['combined_list'] = data.apply(combine_lists, axis=1)
X = pd.DataFrame(data['combined_list'].apply(lambda x: [i for i in x]).tolist(), columns=[f'feature_{i}' for i in range(len(data['combined_list'].iloc[0]))])


# Загрузка модели
model = load_model('model1.keras')

# Предсказание результатов
predictions = model.predict(X)

# напечатать и сохранить голый результат
# print(predictions)
# np.savetxt('predictions.txt', predictions)

# Добавьте следующую функцию в ваш код
def get_attack_type_name(attack_type):
    if attack_type == 1:
        return 'SYN flood'
    elif attack_type == 2:
        return 'UDP flood'
    elif attack_type == 3:
        return 'ICMP flood'
    else:
        return 'No attack'  # Или любое другое значение по умолчанию

# Теперь, при выводе результатов предсказания, используйте эту функцию
class_counts = np.argmax(predictions, axis=1)
unique_classes, class_counts = np.unique(class_counts, return_counts=True)

for class_idx, count in zip(unique_classes, class_counts):
    attack_type = get_attack_type_name(class_idx)
    print(f"Количество предсказанных значений в классе {class_idx} ({attack_type}): {count}")
