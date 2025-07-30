# Network Threat Detector

Detector de ameaças de rede em tempo real que monitora tráfego, identifica padrões suspeitos e responde automaticamente a ataques.

## O que detecta

- **IPs maliciosos** - baseado em threat intelligence
- **Port scanning** - tentativas de mapeamento de rede  
- **Ataques DDoS** - volume anormal de conexões
- **Brute force** - tentativas repetidas de login
- **Data exfiltration** - transferência suspeita de dados
- **Comportamento de bots** - padrões automatizados
- **Portas suspeitas** - backdoors e C&C servers
- **Anomalias de tráfego** - desvios do padrão normal

## Modos de operação

**Tempo real:**
```bash
ruby threat_detector.rb -v -r
```

**Análise passiva:**
```bash
ruby threat_detector.rb -v
```

**Com alertas por webhook:**
```bash
ruby threat_detector.rb -w http://seu-server/webhook -r
```

**Com whitelist personalizada:**
```bash
ruby threat_detector.rb --whitelist ips_confiaveis.txt -r
```

## Opções disponíveis

- `-r` - monitoramento em tempo real
- `-v` - modo verboso (mostra tudo)
- `-i` - interface de rede (padrão: eth0)
- `-l` - arquivo de log customizado
- `-w` - URL do webhook para alertas
- `--whitelist` - arquivo com IPs confiáveis
- `-f` - formato de saída (text, json)

## Exemplo do que aparece

```
🚨 NETWORK THREAT DETECTOR - TEMPO REAL
============================================================
⏰ 2025-07-29 15:30:45

📊 ESTATÍSTICAS (últimos 5 min):
   IPs ativos: 15
   Conexões: 1,234
   Ameaças: 3

🚨 AMEAÇAS RECENTES:
   🚨 malicious_ip - 192.168.100.100 (15:29:12)
   ⚠️  port_scan - 10.0.0.50 (15:28:45)
   🔍 suspicious_port - 172.16.0.10 (15:27:30)

💡 Pressione Ctrl+C para parar o monitoramento

🚨 CRITICAL - MALICIOUS_IP
   📍 IP malicioso conhecido: 192.168.100.100
   🌐 IP: 192.168.100.100
   ⏰ 15:30:45
   🎯 Confiança: 95%

🚫 AUTO-RESPONSE: IP 192.168.100.100 bloqueado automaticamente
```

## Auto-response

O sistema pode responder automaticamente a ameaças críticas:

- **IPs maliciosos** → bloqueio imediato
- **Ataques DDoS** → bloqueio de IP origem
- **Data exfiltration** → throttling de bandwidth

*Em ambiente real, executa comandos iptables e controles de rede*

## Relatórios

Gera relatórios completos em JSON com:

- Resumo executivo das ameaças
- Timeline detalhado de eventos
- Top atacantes e padrões
- Estatísticas de tráfego
- Recomendações de segurança

## Integração

**Webhook de alertas:**
```json
{
  "alert_type": "security_threat",
  "severity": "CRITICAL",
  "description": "IP malicioso conhecido detectado",
  "source_ip": "192.168.100.100",
  "timestamp": "2025-07-29T15:30:45Z",
  "confidence": 95
}
```

**SIEM Integration:**
Os logs são estruturados em JSON para fácil ingestão em sistemas SIEM.

## Arquivo de whitelist

Crie um arquivo `whitelist.txt`:
```
# IPs confiáveis (um por linha)
192.168.1.1
192.168.1.10
10.0.0.1
# Servidores internos
172.16.0.5
```

## Aviso

**Use apenas em redes próprias ou com autorização!**

Este detector:
- Monitora todo o tráfego de rede
- Pode gerar logs extensos
- Consome recursos do sistema
- Pode bloquear IPs automaticamente

## Requisitos

Ruby 2.7+ e permissões adequadas para monitoramento de rede.
