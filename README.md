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
 
```scan_ports(ip)```
- Escanea puertos abiertos en una dirección IP.
- parametro dirección IP a escanear.
- Devuelve una Lista de puertos abiertos.
- Esta función se utiliza para detectar puertos abiertos en una dirección IP específica, lo que puede indicar servicios vulnerables.

```run_nmap(ip)```
- Ejecuta Nmap en una dirección IP y analiza los resultados.
- Usa de parametro la dirección IP a escanear con Nmap.
- Devuelve el Resultado del escaneo de Nmap.
- Esta función se utiliza para obtener información detallada sobre los servicios y versiones de software en una dirección IP, ayudando a identificar posibles vulnerabilidades.

```send_alert(message)```
- Envía una alerta con un mensaje específico.
- Esta función se utiliza para notificar cuando se detecta algo inusual o potencialmente peligroso en el tráfico de red.

```detect_anomalies(ip, packet_count)```
- Detecta anomalías en el tráfico de red.
- Parámetros:
    - Dirección IP a monitorear.
    - Contador de paquetes por dirección IP.
- Esta función se utiliza para detectar patrones de tráfico inusuales, como un aumento repentino en el número de paquetes enviados desde una dirección IP.

```detect_brute_force(ip, failed_attempts)```
- Detecta posibles ataques de fuerza bruta.
- Parámetros:
    - Dirección IP a monitorear.
    - Contador de intentos fallidos por dirección IP.
- Esta función se utiliza para detectar intentos repetidos de conexión fallidos, lo que puede indicar un ataque de fuerza bruta.

```main(protocol_filter=None)```
- Captura y analiza paquetes de red
- Como parametros usa:
    - ```protocol_filter``` verifica el protocolo filtrado si es ```None``` captura todo
    
