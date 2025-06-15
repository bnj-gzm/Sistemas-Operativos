Tecnologías utilizadas
Ubuntu 22.04 / 24.04

Docker & Docker Compose

Node.js (servidor RTMP en CoffeeScript)

OBS Studio

VLC Media Player

Wireshark (análisis de red)

Instalación
Clonar el repositorio base del servidor RTMP:


git clone https://github.com/iizukanao/node-rtsp-rtmp-server.git
Crear la estructura del proyecto:


mkdir -p ~/rtmp-project/rtmp-server
mv node-rtsp-rtmp-server ~/rtmp-project/rtmp-server/
Crear el Dockerfile dentro de rtmp-server:

(Ver sección Dockerfile)

Crear el docker-compose.yml en la raíz de rtmp-project:

(Ver sección docker-compose.yml)

Construir e iniciar el servidor:


cd ~/rtmp-project
docker compose up --build
Transmisión desde OBS Studio
Configurar OBS:

Servicio: Personalizado

Servidor: rtmp://localhost/live

Clave: stream

Iniciar transmisión desde OBS.

Reproducción con VLC
Abrir VLC y elegir “Abrir ubicación de red”.

Ingresar:

rtmp://localhost/live/stream
Reproducir y verificar la transmisión.

Análisis de tráfico
Se utilizó Wireshark para capturar paquetes RTMP en la interfaz loopback.

Filtro aplicado: tcp.port == 1935

Se identificaron paquetes connect, createStream y publish, además de chunks de video/audio.

Estructura del proyecto
rtmp-project/

rtmp-server/

node-rtsp-rtmp-server/

Dockerfile

docker-compose.yml

Autor
Benjamín Guzmán
Martin Huiriqueo
Maximiliano Palma
(Universidad Diego Portales)

Año: 2025
