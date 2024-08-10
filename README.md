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

```parse_tcp_header(data)```
- Analiza la cabecera TCP
- De parametros usa los primeros 12 bytes de la cabecera tcp
- Por ultimo devuelve un diccionario con los puertos de origen y destino, numero de secuencia, ACK number y longitud de cabecera.

```filter_traffic(packet, protocol )```
- Filtro para los tipos de trafico
- Usa como parametro 
    - ```packet``` el paquete
    - ```protocol``` el tipo de protocolo a filtrar
- devuelve respuesta booleana al indicar el tipo
    - ```True``` si el paquete coincide con el protocolo filtrado
    - ```False``` si el paquete no coincide