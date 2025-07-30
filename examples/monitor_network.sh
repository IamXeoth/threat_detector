#!/bin/bash

if [ -z "$1" ]; then
    echo "Scan em lote de múltiplos alvos"
    echo "Uso: $0 <arquivo_com_urls>"
    echo ""
    echo "Arquivo deve ter uma URL por linha:"
    echo "https://site1.com"
    echo "https://site2.com"
    echo "..."
    exit 1
fi

URLS_FILE="$1"

if [ ! -f "$URLS_FILE" ]; then
    echo "Arquivo não encontrado: $URLS_FILE"
    exit 1
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BATCH_DIR="batch_scan_$TIMESTAMP"

echo "📊 Scan em lote iniciado"
echo "Arquivo: $URLS_FILE"
echo "Pasta de relatórios: $BATCH_DIR"
echo ""

mkdir -p "$BATCH_DIR"

# Conta quantas URLs
TOTAL_URLS=$(wc -l < "$URLS_FILE")
CURRENT=1

while IFS= read -r url; do
    # Pula linhas vazias e comentários
    if [[ -z "$url" || "$url" =~ ^# ]]; then
        continue
    fi
    
    echo "[$CURRENT/$TOTAL_URLS] Scanning: $url"
    
    # Nome do arquivo baseado na URL
    SAFE_NAME=$(echo "$url" | sed 's|https\?://||' | sed 's|[^a-zA-Z0-9]|_|g')
    REPORT_FILE="$BATCH_DIR/scan_${SAFE_NAME}.json"
    
    ruby ../vulnerability_scanner.rb -d 2 -t 8 -o "$REPORT_FILE" "$url" > "$BATCH_DIR/scan_${SAFE_NAME}.txt" 2>&1
    
    echo "   Relatório: $REPORT_FILE"
    
    CURRENT=$((CURRENT + 1))
    
    # Pausa entre scans para ser gentil
    sleep 2
done < "$URLS_FILE"

echo ""
echo "✅ Scan em lote completo!"
echo "Relatórios salvos em: $BATCH_DIR/"

# Sumário rápido
echo ""
echo "📊 Sumário rápido:"
grep -h "🚨 Vulnerabilidades encontradas:" "$BATCH_DIR"/*.txt | sort -nr

---