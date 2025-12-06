#!/bin/bash
# demo_client.sh - GROSO1

SERVER_IP="192.168.10.12"
FILE_NAME="files/ReadMeTunel.pdf"

echo "=== DEMO AUTOMATIZADA: CLIENTE ==="

# 1. Verificación de seguridad
if [ ! -f "$FILE_NAME" ]; then
    echo "ERROR CRÍTICO: El archivo '$FILE_NAME' no se encuentra en esta carpeta."
    echo "Por favor, coloca el PDF aquí antes de ejecutar."
    exit 1
fi
# 1. Limpieza
sudo killall python3 2>/dev/null
rm -f client.log 2>/dev/null

MD5=$(md5sum $FILE_NAME | awk '{print $1}')
echo "------------------------------------------------"
echo "[*] Archivo a transferir: $FILE_NAME"
echo "[*] MD5 ORIGINAL (Cliente): $MD5"
echo "------------------------------------------------"
echo "(Compara este número con el que salga en el Servidor)"
echo ""

# 3. Iniciar Cliente (Logs redirigidos a client.log)
echo "[*] Conectando VPN..."
sudo python3 -u groso1.py --peer $SERVER_IP --port 50000 --tun-ip 10.20.0.2/30 --tun-name tun0 > client.log 2>&1 &
PID_CLIENT=$!

echo "Esperando Handshake..."
sleep 5

# 5. Enviar
echo "[*] Enviando archivo por el túnel cifrado..."
cat $FILE_NAME | nc -u -w 2 10.20.0.1 8080
echo "Envío finalizado."

# 5. Mostrar Logs
echo ""
echo "=== EVIDENCIA DE CRIPTOGRAFÍA Y RED ==="

# Mostrar Handshake y Claves
echo "--- [1] HANDSHAKE Y CLAVES ---"
grep -E "HANDSHAKE|KEYS" -A 2 client.log

echo ""
echo "--- [2] INICIO DE TRANSMISIÓN (Primeros paquetes) ---"
grep "TUN" client.log | head -n 10

echo "..."
echo "(... resto de paquetes ...)"
echo "================================================="
echo "Log completo disponible en 'client.log'"

sudo kill $PID_CLIENT 2>/dev/null