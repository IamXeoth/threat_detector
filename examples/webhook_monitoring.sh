#!/bin/bash

if [ -z "$1" ]; then
    echo "Monitoramento com alertas via webhook"
    echo ""
    echo "Uso: $0 <webhook_url>"
    echo "Exemplo: $0 http://seu-server.com/alerts"
    echo ""
    echo "O webhook receberá POSTs JSON com alertas de segurança"
    exit 1
fi

WEBHOOK_URL="$1"

echo "🔗 Configurando monitoramento com webhook"
echo "URL: $WEBHOOK_URL"
echo ""

# Testa se o webhook responde
echo "🧪 Testando webhook..."
if curl -s --connect-timeout 5 "$WEBHOOK_URL" > /dev/null 2>&1; then
    echo "✅ Webhook respondeu"
else
    echo "⚠️  Webhook não respondeu - continuando mesmo assim"
fi

echo ""
echo "🚨 Iniciando monitoramento com alertas..."

ruby ../threat_detector.rb -v -r -w "$WEBHOOK_URL"

---