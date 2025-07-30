#!/bin/bash

echo "🕵️  Threat Hunting Mode"
echo "====================="
echo ""

echo "Modo especializado para caça ativa de ameaças"
echo "Configurações otimizadas para detecção avançada"
echo ""

# Configurações para threat hunting
HUNTING_LOG="threat_hunting_$(date +%Y%m%d_%H%M%S).log"
HUNTING_REPORT="hunting_report_$(date +%Y%m%d_%H%M%S).json"

echo "📋 Configuração Threat Hunting:"
echo "  🎯 Sensibilidade: Alta"
echo "  ⏱️  Janela de análise: 15 minutos"
echo "  📊 Relatório: $HUNTING_REPORT"
echo "  📝 Log detalhado: $HUNTING_LOG"
echo ""

echo "🔍 Iniciando caça de ameaças..."
echo "Procurando por:"
echo "  • APTs (Advanced Persistent Threats)"
echo "  • Lateral movement"
echo "  • Command & Control communication"
echo "  • Data staging"
echo "  • Covert channels"
echo ""

# Executa em modo hunting (mais sensível)
ruby ../threat_detector.rb \
    -v -r \
    -l "$HUNTING_LOG" \
    -f json

echo ""
echo "🎯 Threat hunting session completa!"
echo "📊 Analise $HUNTING_REPORT para IOCs descobertos"