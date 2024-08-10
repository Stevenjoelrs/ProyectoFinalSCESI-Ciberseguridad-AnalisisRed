# ProyectoFinalSCESI-Ciberseguridad-AnalisisRed
Este script captura y analiza paquetes de red, mostrando información de las capas de enlace, red y transporte. También permite filtrar tipos de tráfico específicos (TCP, UDP, ICMP).

# Funciones
```parse_ethernet_header(data)```
- Analiza la cabecera Ethernet.
- Como parámetro usa data (bytes) - Los primeros 14 bytes del paquete de datos.
- y al terminar devuelve un diccionario con las direcciones MAC de destino y origen, y el protocolo.

```parse_ip_header(data)```
- Analiza la cabecera IP.
- Como parámetro usa data (bytes) - Los primeros 20 bytes de la cabecera IP.
- al terminar devuelve un diccionario con la versión, longitud de la cabecera, TTL, protocolo, y direcciones IP de origen y destino.

```parse_tcp_header```
- Analiza la cabecera TCP
- De parametros usa los primeros 12 bytes de la cabecera tcp
- Por ultimo devuelve un diccionario con los puertos de origen y destino, numero de secuencia, ACK number y longitud de cabecera.
