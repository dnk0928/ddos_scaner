from scapy.all import Ether, IP, TCP, UDP, ICMP, rdpcap
import csv
import os
import sys
import traceback


def is_valid_pcap_file(file_path):
    # Проверка на корректность файла .pcap
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Файл {file_path} не найден.")
    elif os.path.getsize(file_path) == 0:
        raise ValueError(f"Файл {file_path} пуст.")
    return True


def read_pcap(file_path):
    is_valid_pcap_file(file_path)
    return rdpcap(file_path)


def label_packet(packet):
    if IP in packet:
        if packet.haslayer(TCP) and packet[TCP].window == 512 and packet[IP].len == 40:
            attack_type = 1  # 'SYN flood'
            return attack_type  # ddos
        elif packet.haslayer(UDP) and packet[IP].len == 528 and packet[UDP].dport == 443:
            attack_type = 2  # 'UDP flood'
            return attack_type  # ddos
        elif packet.haslayer(ICMP) and packet[IP].len == 28 and packet[ICMP].type == 8:
            attack_type = 3  # 'ICMP flood'
            return attack_type  # ddos
    return 0


def analyze_packets(packets, csv_file):
    unique_src_ips = set()
    unique_dst_ips = set()


    # Добавление заголовков
    with open(csv_file, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["binary_ethernet_frame",
                         "binary_ip_packet",
                         "binary_transport_layer"])
                         #    ,
                         # "attack_type"])

        for i, packet in enumerate(packets, 1):

            # Инициализация списка для хранения каждого символа
            binary_ethernet_frame = []
            binary_ip_packet = []
            binary_transport_layer = []
            pus = 0  # переменная-заглушка
            # Извлекаем IP-адреса из пакетов
            if packet.haslayer(IP):
                unique_src_ips.add(packet[IP].src)
                unique_dst_ips.add(packet[IP].dst)
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                src_ip = sum(int(octet) << (8 * (3 - i)) for i, octet in enumerate(src_ip.split('.')))
                dst_ip = sum(int(octet) << (8 * (3 - i)) for i, octet in enumerate(dst_ip.split('.')))

            if Ether in packet:
                ethernet_header = packet[Ether].fields  # 112
                src_mac = format(int(ethernet_header['src'].replace(':', ''), 16), '048b')
                dst_mac = format(int(ethernet_header['dst'].replace(':', ''), 16), '048b')
                type_eth = format(ethernet_header['type'], '016b')

                for char in src_mac + dst_mac + type_eth:
                    binary_ethernet_frame.append(int(char))

            if IP in packet:  # 160
                ip_header = packet[IP].fields
                version = format(int(ip_header['version']), '04b')
                ihl = format(int(ip_header['ihl']), '04b')
                tos = format(int(ip_header['tos']), '08b')
                len_id = format(int(ip_header['len']), '016b')
                ip_id = format(int(ip_header['id']), '016b')
                ip_flags = format(int(ip_header['flags']), '03b')
                ip_frag = format(int(ip_header['frag']), '013b')
                ip_ttl = format(ip_header['ttl'], '08b')
                ip_proto = format(int(ip_header['proto']), '08b')
                ip_chsum = format(int(ip_header['chksum']), '016b')
                src = format(src_ip, '032b')
                dst = format(dst_ip, '032b')

                for char in version + ihl + tos + len_id + ip_id + ip_flags + ip_frag + ip_ttl + ip_proto + ip_chsum + src + dst:
                    binary_ip_packet.append(int(char))

            else:
                pus = format(int(pus), '0160b')
                for char in pus:
                    binary_ip_packet.append(int(char))

            if TCP in packet:  #160
                transport_layer_fields = packet[TCP].fields
                sport = format(int(transport_layer_fields['sport']), '016b')
                dport = format(int(transport_layer_fields['dport']), '016b')
                seq = format(int(transport_layer_fields['seq']), '032b')
                ack = format(int(transport_layer_fields['ack']), '032b')
                dataofs = format(int(transport_layer_fields['dataofs']), '04b')
                reserved = format(int(transport_layer_fields['reserved']), '06b')
                flags = format(int(transport_layer_fields['flags']), '06b')
                window = format(int(transport_layer_fields['window']), '016b')
                chksum = format(int(transport_layer_fields['chksum']), '016b')
                urgptr = format(int(transport_layer_fields['urgptr']), '016b')

                for char in sport + dport + seq + ack + dataofs + reserved + flags + window + chksum + urgptr:
                    binary_transport_layer.append(int(char))

            elif UDP in packet:  #64
                transport_layer_fields = packet[UDP].fields
                sport = format(int(transport_layer_fields['sport']), '016b')
                dport = format(int(transport_layer_fields['dport']), '016b')
                data_len = format(int(transport_layer_fields['len']), '016b')
                chksum = format(int(transport_layer_fields['chksum']), '016b')
                pus = format(int(pus), '096b')

                for char in sport + dport + data_len + chksum + pus:
                    binary_transport_layer.append(int(char))

            elif ICMP in packet:  # 64
                transport_layer_fields = packet[ICMP].fields
                type = format(int(transport_layer_fields['type']), '08b')
                code = format(int(transport_layer_fields['code']), '08b')
                chksum = format(int(transport_layer_fields['chksum']), '016b')
                id = format(int(transport_layer_fields.get('id', 0) or 0), '016b')
                seq = format(int(transport_layer_fields.get('seq', 0) or 0), '016b')
                pus = format(int(pus), '096b')

                for char in type + code + chksum + id + seq + pus:
                    binary_transport_layer.append(int(char))
            else:
                pus = format(int(pus), '0160b')
                for char in pus:
                    binary_transport_layer.append(int(char))

            # attack_type = label_packet(packet)

            writer.writerow([binary_ethernet_frame, binary_ip_packet, binary_transport_layer])  # , attack_type

    print("Statistics:\n",
          f"Total Packets: {len(packets)} \n",
          f"Unique Source IPs {len(unique_src_ips)} \n",
          f"Unique Destination IPs {len(unique_dst_ips)} \n")


def main():
    while True:
        try:
            file_path = input("Введите путь к файлу захвата: ")
            csv_file = "learn_data/" + os.path.splitext(os.path.basename(file_path))[0]
            csv_file += '.csv'
            packets = read_pcap(file_path)
            print(f"Файл создан")
            print(f"Данные прочитаны")
            analyze_packets(packets, csv_file)
            print(f"Данные записаны в {csv_file}")
            print()
            break
        except FileNotFoundError:
            print("Файл не найден. Проверьте путь к файлу и попробуйте снова.", file=sys.stderr)
        except ValueError:
            print("Файл пуст. Убедитесь, что выбранный файл содержит данные.", file=sys.stderr)
        except Exception as e:
            error_message = f"Произошла ошибка: {e}\n{traceback.format_exc()}, данные записаны в лог файл"
            print(f"Произошла ошибка: {e}, данные записаны в лог файл", file=sys.stderr)

            # Сохранение ошибки в файл
            with open('error_log.txt', 'a') as error_file:
                error_file.write(error_message + '\n' )


if __name__ == "__main__":
    main()
