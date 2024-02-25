import pandas as pd
from sklearn.preprocessing import LabelEncoder, OneHotEncoder
from tensorflow.keras.models import load_model
from sklearn.model_selection import train_test_split
import numpy as np
from tkinter import Tk
from tkinter.filedialog import askopenfilename


def combine_lists(row):
    ethernet_frame = np.array(eval(row['binary_ethernet_frame']))
    ip_packet = np.array(eval(row['binary_ip_packet']))
    transport_frag = np.array(eval(row['binary_transport_layer']))
    combined_list = np.concatenate((ethernet_frame, ip_packet, transport_frag))
    return combined_list


def get_attack_type_name(attack_type):
    if attack_type == 1:
        return 'SYN flood'
    elif attack_type == 2:
        return 'UDP flood'
    elif attack_type == 3:
        return 'ICMP flood'
    else:
        return 'No attack'


def main():
    try:
        # выбор пути к файлу
        print("Пожалуйста, выберите файл, который нужно проанализировать (.csv)\n")
        Tk().withdraw()
        file_path = askopenfilename()  # Открыть диалоговое окно выбора файла

        # Проверка на отмену выбора файла
        if not file_path:
            print("Выбор файла отменён.")
        else:
            print("данные получены")
        # Загрузка данных из CSV-файла
        data = pd.read_csv(file_path)

        data['combined_list'] = data.apply(combine_lists, axis=1)
        X = pd.DataFrame(data['combined_list'].apply(lambda x: [i for i in x]).tolist(),
                         columns=[f'feature_{i}' for i in range(len(data['combined_list'].iloc[0]))])

        # Загрузка модели
        model = load_model('model1.keras')

        # Предсказание результатов
        predictions = model.predict(X)

        class_counts = np.argmax(predictions, axis=1)
        unique_classes, class_counts = np.unique(class_counts, return_counts=True)

        for class_idx, count in zip(unique_classes, class_counts):
            attack_type = get_attack_type_name(class_idx)
            print(f"Количество предсказанных значений в классе {class_idx} ({attack_type}): {count}")

    except FileNotFoundError:
        print("Указанный файл не найден. Пожалуйста, укажите правильный путь к файлу.")
    except Exception as e:
        print(f"Произошла ошибка: {str(e)}")


if __name__ == "__main__":
    main()
