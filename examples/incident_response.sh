#!/bin/bash

echo "🚨 Incident Response - Threat Analysis"
echo "======================================"
echo ""

if [ -z "$1" ]; then
    echo "Análise rápida para resposta a incidentes"
    echo ""
    echo "Uso: $0 <suspicious_ip>"
    echo "Exemplo: $0 192.168.100.100"
    echo ""
    echo "Gera relatório focado em um IP específico"
    exit 1
fi

SUSPICIOUS_IP="$1"
INCIDENT_ID="INC_$(date +%Y%m%d_%H%M%S)"

echo "🎯 Analisando IP suspeito: $SUSPICIOUS_IP"
echo "📋 Incident ID: $INCIDENT_ID"
echo ""

# Cria whitelist temporária sem o IP suspeito
TEMP_WHITELIST="/tmp/incident_whitelist_$$.txt"
if [ -f "../config/whitelist.txt" ]; then
    grep -v "$SUSPICIOUS_IP" "../config/whitelist.txt" > "$TEMP_WHITELIST"
else
    touch "$TEMP_WHITELIST"
fi

echo "🔍 Executando análise focada..."
echo "⏰ Isso pode levar alguns minutos..."

# Executa análise com foco no IP
ruby ../threat_detector.rb \
    -v \
    -l "incident_${INCIDENT_ID}.log" \
    -f json \
    --whitelist "$TEMP_WHITELIST"

# Limpa arquivo temporário
rm -f "$TEMP_WHITELIST"

echo ""
echo "✅ Análise de incident response completa!"
echo "📁 Arquivos gerados:"
echo "   📝 incident_${INCIDENT_ID}.log"
echo "   📊 threat_report_*.json"
echo ""
echo "🔍 Procure por '$SUSPICIOUS_IP' nos relatórios para detalhes"

---