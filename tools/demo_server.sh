#!/bin/bash
# demo_server.sh - GROSO2

echo "=== DEMO AUTOMATIZADA: SERVIDOR ==="

# 1. Limpieza
sudo killall python3 2>/dev/null
sudo killall nc 2>/dev/null
rm -f recibido.demo server.log 2>/dev/null

# 2. Iniciar Servidor (Logs redirigidos a server.log)
echo "[*] Iniciando Servidor VPN..."
sudo python3 groso2.py --listen 0.0.0.0 --port 50000 --tun-ip 10.20.0.1/30 --tun-name tun0 > server.log 2>&1 &
PID_SERVER=$!

sleep 2

# 3. Preparar recepción
echo "[*] Esperando archivo en puerto 8080..."
nc -u -l -p 8080 > recibido.demo &
PID_NC=$!

echo ">>> SERVIDOR LISTO. EJECUTA EL CLIENTE AHORA <<<"
echo "(Esperando 15 segundos por la transferencia...)"
sleep 15

# 4. Resultados
echo ""
echo "=== RESULTADOS SERVIDOR ==="
if [ -f "recibido.demo" ]; then
    MD5=$(md5sum recibido.demo | awk '{print $1}')
    echo "MD5 Recibido: $MD5"
else
    echo "ERROR: No llegó el archivo."
fi

echo ""
echo "=== LOGS DE CRIPTOGRAFÍA (GROSO2) ==="
cat server.log
echo "====================================="

# Limpieza
sudo kill $PID_SERVER $PID_NC 2>/dev/null