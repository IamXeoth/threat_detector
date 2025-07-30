#!/bin/bash

echo "🏢 Network Threat Detector - Modo Enterprise"
echo "=============================================="
echo ""

# Configurações enterprise
INTERFACE="eth0"
LOG_FILE="/var/log/threat_detector/enterprise.log"
WHITELIST_FILE="../config/enterprise_whitelist.txt"
WEBHOOK_URL="https://siem.empresa.com/api/alerts"

# Cria diretório de logs se não existir
mkdir -p "$(dirname "$LOG_FILE")" 2>/dev/null || {
    echo "⚠️  Não foi possível criar /var/log/threat_detector/"
    echo "Usando diretório local..."
    LOG_FILE="enterprise_$(date +%Y%m%d_%H%M%S).log"
}

echo "📋 Configuração Enterprise:"
echo "  🌐 Interface: $INTERFACE"
echo "  📝 Log: $LOG_FILE"
echo "  📋 Whitelist: $WHITELIST_FILE"
echo "  🔗 SIEM Webhook: $WEBHOOK_URL"
echo ""

# Verifica se é root (para monitoramento de rede real)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  Para monitoramento real de rede, execute como root"
    echo "Continuando em modo simulação..."
fi

echo "🚀 Iniciando monitoramento enterprise..."
ruby ../threat_detector.rb \
    -v -r \
    -i "$INTERFACE" \
    -l "$LOG_FILE" \
    --whitelist "$WHITELIST_FILE" \
    -w "$WEBHOOK_URL"

---