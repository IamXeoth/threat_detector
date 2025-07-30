#!/bin/bash

echo "📊 Análise de ameaças de rede"
echo "Modo: Análise passiva de logs existentes"
echo ""

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
LOG_FILE="threat_analysis_${TIMESTAMP}.log"
REPORT_FILE="threat_report_${TIMESTAMP}.json"

echo "Arquivos que serão gerados:"
echo "  📝 Log: $LOG_FILE"
echo "  📊 Relatório: $REPORT_FILE"
echo ""

ruby ../threat_detector.rb -v -l "$LOG_FILE" -f json

echo ""
echo "✅ Análise completa!"
echo "📁 Verifique os arquivos gerados para detalhes"

---