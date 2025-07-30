#!/bin/bash

echo "♾️  Monitoramento Contínuo 24/7"
echo "============================="
echo ""

LOG_DIR="./continuous_logs"
mkdir -p "$LOG_DIR"

echo "📁 Logs serão salvos em: $LOG_DIR"
echo "🔄 Rotação automática a cada 6 horas"
echo "📊 Relatórios a cada 24 horas"
echo ""

read -p "Iniciar monitoramento contínuo? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelado."
    exit 1
fi

# Função de rotação de logs
rotate_logs() {
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    if [ -f "$LOG_DIR/current.log" ]; then
        mv "$LOG_DIR/current.log" "$LOG_DIR/rotated_$TIMESTAMP.log"
        echo "🔄 Log rotacionado: rotated_$TIMESTAMP.log"
    fi
}

# Função de limpeza de logs antigos
cleanup_old_logs() {
    find "$LOG_DIR" -name "rotated_*.log" -mtime +7 -delete
    echo "🧹 Logs antigos (>7 dias) removidos"
}

echo "🟢 Monitoramento contínuo iniciado"
echo "📋 PID: $$"
echo "🛑 Para parar: kill $$"

# Loop principal
while true; do
    echo "🔴 Iniciando sessão de monitoramento..."
    
    # Rotaciona logs se necessário
    if [ -f "$LOG_DIR/current.log" ] && [ $(stat -c%s "$LOG_DIR/current.log") -gt 10485760 ]; then
        rotate_logs
    fi
    
    # Executa monitoramento por 6 horas com timeout
    timeout 21600 ruby ../threat_detector.rb \
        -v -r \
        -l "$LOG_DIR/current.log" \
        -f json 2>/dev/null || true
    
    # Cleanup periódico
    cleanup_old_logs
    
    echo "⏸️  Pausa de 60 segundos antes da próxima sessão..."
    sleep 60
done

---