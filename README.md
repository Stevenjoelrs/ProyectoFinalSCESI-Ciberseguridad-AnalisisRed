# ProyectoFinalSCESI-Ciberseguridad-AnalisisRed
Este script captura y analiza paquetes de red, mostrando información de las capas de enlace, red y transporte. También permite filtrar tipos de tráfico específicos (TCP, UDP, ICMP).

# Funciones
```parse_ethernet_header(data)```
- Analiza la cabecera Ethernet.
- Parámetros: data (bytes) - Los primeros 14 bytes del paquete de datos.
- Devuelve: Diccionario con las direcciones MAC de destino y origen, y el protocolo.

