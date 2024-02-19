# ddos_scaner

Проект выполнен в рамках выпускной квалификационной работы (ВКР) на тему "Разработка приложения, основанного на нейросетевых технологиях для классификации сетевого трафика". Вы можете протестировать данное приложение или предложить улучшения модели нейронной сети для дальнейшего улучшения результатов. Кроме того, вы можете предложить свои методы классификации, на основе которых возможно переобучение модели.

КАК НАЧАТЬ:
1. Установите Python версии не ниже 3.10.
2. Затем установите все необходимые зависимости, выполнив команду: `$ pip install -r requirements.txt`.

Примечание: Рекомендуется создать виртуальное окружение для избежания конфликтов версий библиотек:
```bash
$ python3 -m venv . # Создать виртуальное окружение в текущей папке
$ source bin/activate # Активировать виртуальное окружение
$ deactivate # Деактивировать виртуальное окружение
```

Теперь ваше приложение готово к работе! Необходимо собрать дамп, который будет проанализирован. Файл дампа должен быть сохранен в формате .pcap. Как только у вас будет файл захвата, выполните следующие шаги:

1. Запустите первый компонент: `$ python3 appv3.py`.
2. Введите путь к файлу захвата в предложенной строке.
3. Произойдет преобразование данных в битовые значения, и после успешного выполнения файл будет сохранен в папке `learn_data/`.
4. Для анали результатов нейронной сетью запустите `$ python3 result.py` и введите название вашего файла в предложенной строке в формате `<название файла>.csv`

При этом вы будете использовать предварительно подготовленную мной модель `model1.keras/model.keras`. Если вы желаете обучить свою собственную модель, продолжение следует...



PS: если у вас нет файлов захвата, вы можете воспользоваться моими собранными, на которых тестировалось это приложение. Файлы доступны по [ссылке](https://disk.yandex.ru/d/GgRG8n4XiWbPuA)