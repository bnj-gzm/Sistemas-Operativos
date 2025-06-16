# Proyecto: Servidor RTMP Local con OBS y VLC

 
Este proyecto implementa un sistema de transmisión de video en tiempo real (RTMP) completamente local utilizando Docker, OBS Studio como emisor y VLC como receptor. Se utilizó Wireshark para capturar el tráfico de red y analizar los paquetes RTMP.

Demostración en vivo: No aplica (sistema local)

---

## Tabla de contenido

- [Información general](#información-general)
- [Tecnologías utilizadas](#tecnologías-utilizadas)
- [Características](#características)
- [Capturas de pantalla](#capturas-de-pantalla)
- [Configuración](#configuración)
- [Uso](#uso)
- [Estado del proyecto](#estado-del-proyecto)
- [Margen de mejora](#margen-de-mejora)
- [Expresiones de gratitud](#expresiones-de-gratitud)
- [Contacto](#contacto)

---

## Información general

Este proyecto busca implementar un flujo de transmisión RTMP desde un cliente emisor (OBS Studio) a un servidor personalizado alojado en Docker, y visualizar el contenido desde un cliente receptor (VLC), todo ejecutado en una misma máquina (localhost).

Se desarrolló como parte de una tarea académica en el área de redes y servicios.

Objetivos:

- Levantar un servidor RTMP local
- Emitir en tiempo real desde OBS
- Recibir el stream con VLC
- Capturar y analizar los paquetes en Wireshark

---

## Tecnologías utilizadas

- Ubuntu 22.04
- Docker 24.0+
- Node.js 18.x (con CoffeeScript)
- OBS Studio
- VLC Media Player
- Wireshark

---

##  Características

- Transmisión RTMP en tiempo real
- Configuración completamente local (no requiere internet)
- Análisis de tráfico TCP/RTMP en Wireshark
- Contenedor Docker totalmente funcional
- Configuración reproducible paso a paso

---

## Capturas de pantalla

OBS configurado como emisor RTMP:  
![OBS Studio]()

VLC recibiendo el stream:  
![VLC](imagenes/vlc-stream.png)

Wireshark mostrando tráfico RTMP:  
![Wireshark](imagenes/wireshark-packets.png)

---

## Configuración

Requisitos:

- Docker y Docker Compose instalados
- Flatpak (para instalar OBS)
- git
- VLC Media Player
- Wireshark

Configuración local:

```bash
git clone https://github.com/iizukanao/node-rtsp-rtmp-server.git
mkdir -p ~/rtmp-project/rtmp-server
mv node-rtsp-rtmp-server ~/rtmp-project/rtmp-server/
cd ~/rtmp-project
```
Crear archivo docker-compose.yml:
```bash
version: '3'
services:
  rtmp-server:
    build: ./rtmp-server
    ports:
      - "1935:1935"
    container_name: rtmp-server
```
Crear Dockerfile dentro de rtmp-server:

```bash
FROM node:18
RUN apt-get update && apt-get install -y coffeescript
WORKDIR /app
COPY node-rtsp-rtmp-server /app
RUN npm install
RUN chmod +x start_server.sh
EXPOSE 1935
CMD ["sh", "start_server.sh"]
```
Editar start_server.sh para eliminar sudo en coffee server.coffee.

## Uso
1. Iniciar el servidor RTMP:
```bash

cd ~/rtmp-project
docker compose up --build
```


2.En OBS Studio:

- Servidor: ```rtmp://localhost/live```

- Clave: stream

3. En VLC:
- Abrir ubicación de red:
```rtmp://localhost/live/stream```


4. Para ver el tráfico en Wireshark:

- Interfaz: lo

- Filtro: tcp.port == 1935

## Estado del proyecto

El proyecto está: Finalizado

## Margen de mejora

Áreas por mejorar:
- Añadir interfaz web para control de la transmisión
- Incluir autenticación RTMP
- Configurar múltiples streams simultáneos

Tareas pendientes:
 - Agregar logging al servidor RTMP
 - Exportar estadísticas de tráfico
 - Crear imagen Docker personalizada pública

## Expresiones de gratitud

- Este proyecto se inspiró en el repositorio:
```https://github.com/iizukanao/node-rtsp-rtmp-server```

- Gracias a OBS Studio y VLC por ser herramientas libres

- Agradecimientos a mi equipo docente y compañeros

## Contacto

Creado por:
- Benjamín Guzmán
- Martin Huiriqueo
- Maximiliano Palma


