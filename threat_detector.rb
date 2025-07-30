#!/usr/bin/env ruby

require 'socket'
require 'json'
require 'time'
require 'digest'
require 'optparse'
require 'ipaddr'
require 'thread'
require 'net/http'
require 'uri'

class NetworkThreatDetector
  # Threat intelligence feeds (simplified for demo)
  MALICIOUS_IPS = [
    '192.168.100.100',  # Example malicious IP
    '10.0.0.666',       # Example C&C server
    '172.16.0.123'      # Example botnet node
  ]

  # Known malicious domains
  MALICIOUS_DOMAINS = [
    'malware-download.evil',
    'phishing-site.bad',
    'botnet-c2.malicious',
    'ransomware.threat'
  ]

  # Suspicious ports (commonly used by malware)
  SUSPICIOUS_PORTS = [
    1234,   # Common backdoor
    4444,   # Metasploit default
    5555,   # Android Debug Bridge
    6666,   # IRC bots
    7777,   # Tini backdoor
    8080,   # HTTP proxy/backdoor
    9999,   # Remote administration
    31337   # Elite/leet backdoor
  ]

  # Attack patterns
  ATTACK_PATTERNS = {
    port_scan: {
      description: "Port scanning activity detected",
      threshold: 10,    # connections to different ports from same IP
      time_window: 60   # within 60 seconds
    },
    brute_force: {
      description: "Brute force attack detected", 
      threshold: 5,     # failed attempts
      time_window: 300  # within 5 minutes
    },
    ddos: {
      description: "DDoS attack detected",
      threshold: 100,   # connections from same IP
      time_window: 60   # within 60 seconds
    },
    data_exfiltration: {
      description: "Potential data exfiltration",
      threshold: 50,    # MB transferred
      time_window: 300  # within 5 minutes
    }
  }

  def initialize(options = {})
    @interface = options[:interface] || 'eth0'
    @verbose = options[:verbose] || false
    @log_file = options[:log_file] || 'threat_detector.log'
    @alert_webhook = options[:webhook]
    @whitelist_file = options[:whitelist]
    @output_format = options[:format] || :text
    @real_time = options[:real_time] || false
    
    @connection_tracker = Hash.new { |h, k| h[k] = [] }
    @threat_history = []
    @whitelist = load_whitelist
    @alerts_sent = Set.new
    @mutex = Mutex.new
    
    setup_logging
  end

  def start_monitoring
    puts "🚨 Network Threat Detector iniciado"
    puts "🔍 Interface: #{@interface}"
    puts "📝 Log: #{@log_file}"
    puts "⚡ Modo: #{@real_time ? 'Tempo Real' : 'Análise'}"
    puts "-" * 60

    if @real_time
      start_real_time_monitoring
    else
      start_passive_monitoring
    end
  end

  private

  def setup_logging
    @logger = File.open(@log_file, 'a')
    @logger.sync = true
    log_event("SYSTEM", "Threat Detector iniciado", "INFO")
  end

  def load_whitelist
    return Set.new unless @whitelist_file && File.exist?(@whitelist_file)
    
    whitelist = Set.new
    File.readlines(@whitelist_file).each do |line|
      ip = line.strip
      whitelist.add(ip) unless ip.empty? || ip.start_with?('#')
    end
    
    puts "📋 Whitelist carregada: #{whitelist.size} IPs" if @verbose
    whitelist
  end

  def start_real_time_monitoring
    puts "🔴 Monitoramento em tempo real ativo..."
    
    # Thread para captura de pacotes (simulada)
    packet_thread = Thread.new { simulate_packet_capture }
    
    # Thread para análise de conexões
    analysis_thread = Thread.new { connection_analyzer }
    
    # Thread para verificação de threat intelligence
    intel_thread = Thread.new { threat_intelligence_checker }
    
    # Thread para cleanup de dados antigos
    cleanup_thread = Thread.new { data_cleanup }
    
    # Main monitoring loop
    begin
      loop do
        print_real_time_stats
        sleep 5
      end
    rescue Interrupt
      puts "\n🛑 Parando monitoramento..."
      packet_thread.kill
      analysis_thread.kill
      intel_thread.kill
      cleanup_thread.kill
    ensure
      @logger.close
    end
  end

  def start_passive_monitoring
    puts "📊 Análise passiva de conexões de rede..."
    
    # Simula análise de logs existentes
    analyze_existing_connections
    analyze_network_flows
    generate_threat_report
  end

  def simulate_packet_capture
    # Simula captura de pacotes de rede
    loop do
      # Gera conexões simuladas para demonstração
      generate_simulated_traffic
      sleep(0.1)
    end
  end

  def generate_simulated_traffic
    # Gera tráfego simulado para demonstração
    source_ips = [
      '192.168.1.100', '192.168.1.101', '192.168.1.102',
      '10.0.0.50', '172.16.0.10', '203.0.113.1',
      '192.168.100.100'  # IP malicioso da lista
    ]
    
    dest_ports = [80, 443, 22, 21, 25, 53, 1234, 4444, 6666]
    
    5.times do
      connection = {
        timestamp: Time.now,
        source_ip: source_ips.sample,
        dest_ip: get_local_ip,
        dest_port: dest_ports.sample,
        protocol: ['TCP', 'UDP'].sample,
        bytes: rand(1000..50000),
        flags: generate_tcp_flags
      }
      
      process_connection(connection)
    end
  end

  def process_connection(connection)
    return if whitelisted?(connection[:source_ip])
    
    @mutex.synchronize do
      @connection_tracker[connection[:source_ip]] << connection
      
      # Limita histórico por IP
      if @connection_tracker[connection[:source_ip]].size > 1000
        @connection_tracker[connection[:source_ip]] = 
          @connection_tracker[connection[:source_ip]].last(500)
      end
    end
    
    # Análise imediata de ameaças
    analyze_connection_for_threats(connection)
  end

  def analyze_connection_for_threats(connection)
    threats = []
    
    # Verifica IP malicioso conhecido
    if malicious_ip?(connection[:source_ip])
      threats << create_threat_alert(
        :malicious_ip,
        "IP malicioso conhecido: #{connection[:source_ip]}",
        connection,
        'CRITICAL'
      )
    end
    
    # Verifica porta suspeita
    if suspicious_port?(connection[:dest_port])
      threats << create_threat_alert(
        :suspicious_port,
        "Conexão para porta suspeita: #{connection[:dest_port]}",
        connection,
        'HIGH'
      )
    end
    
    # Análise de padrões
    analyze_attack_patterns(connection[:source_ip]).each do |pattern_threat|
      threats << pattern_threat
    end
    
    # Processa alertas encontrados
    threats.each { |threat| handle_threat_alert(threat) }
  end

  def analyze_attack_patterns(source_ip)
    threats = []
    recent_connections = get_recent_connections(source_ip, 300) # últimos 5 min
    
    # Port scan detection
    unique_ports = recent_connections.map { |c| c[:dest_port] }.uniq
    if unique_ports.size >= ATTACK_PATTERNS[:port_scan][:threshold]
      threats << create_threat_alert(
        :port_scan,
        "Port scan detectado: #{unique_ports.size} portas em 5 min",
        { source_ip: source_ip, ports: unique_ports },
        'HIGH'
      )
    end
    
    # DDoS detection
    recent_count = recent_connections.size
    if recent_count >= ATTACK_PATTERNS[:ddos][:threshold]
      threats << create_threat_alert(
        :ddos,
        "Possível DDoS: #{recent_count} conexões em 5 min",
        { source_ip: source_ip, connections: recent_count },
        'CRITICAL'
      )
    end
    
    # Data exfiltration detection
    total_bytes = recent_connections.sum { |c| c[:bytes] || 0 }
    mb_transferred = total_bytes / (1024 * 1024)
    if mb_transferred >= ATTACK_PATTERNS[:data_exfiltration][:threshold]
      threats << create_threat_alert(
        :data_exfiltration,
        "Possível exfiltração: #{mb_transferred.round(2)} MB em 5 min",
        { source_ip: source_ip, bytes: total_bytes },
        'HIGH'
      )
    end
    
    threats
  end

  def create_threat_alert(type, description, details, severity)
    {
      id: Digest::SHA256.hexdigest("#{type}_#{details}_#{Time.now.to_f}")[0..15],
      timestamp: Time.now,
      type: type,
      description: description,
      severity: severity,
      details: details,
      source_ip: details.is_a?(Hash) ? details[:source_ip] : details[:source_ip],
      confidence: calculate_confidence(type, details)
    }
  end

  def handle_threat_alert(threat)
    # Evita alertas duplicados
    alert_key = "#{threat[:type]}_#{threat[:source_ip]}_#{threat[:timestamp].to_i / 300}" # 5 min window
    return if @alerts_sent.include?(alert_key)
    
    @alerts_sent.add(alert_key)
    @threat_history << threat
    
    # Log do alerta
    log_event("THREAT", threat[:description], threat[:severity], threat)
    
    # Exibe alerta em tempo real
    if @real_time
      display_real_time_alert(threat)
    end
    
    # Envia webhook se configurado
    send_webhook_alert(threat) if @alert_webhook
    
    # Auto-response para ameaças críticas
    auto_respond_to_threat(threat) if threat[:severity] == 'CRITICAL'
  end

  def display_real_time_alert(threat)
    icon = threat[:severity] == 'CRITICAL' ? '🚨' : 
           threat[:severity] == 'HIGH' ? '⚠️' : '🔍'
    
    puts "\n#{icon} #{threat[:severity]} - #{threat[:type].to_s.upcase}"
    puts "   📍 #{threat[:description]}"
    puts "   🌐 IP: #{threat[:source_ip]}"
    puts "   ⏰ #{threat[:timestamp].strftime('%H:%M:%S')}"
    puts "   🎯 Confiança: #{threat[:confidence]}%"
    puts
  end

  def connection_analyzer
    loop do
      sleep 30 # Análise a cada 30 segundos
      
      @mutex.synchronize do
        # Análise de tendências
        analyze_traffic_trends
        
        # Detecção de comportamento anômalo
        detect_anomalous_behavior
        
        # Limpeza de conexões antigas
        cleanup_old_connections
      end
    end
  end

  def analyze_traffic_trends
    return if @connection_tracker.empty?
    
    # Análise de volume de tráfego
    current_time = Time.now
    last_hour_connections = 0
    
    @connection_tracker.each do |ip, connections|
      recent = connections.select { |c| current_time - c[:timestamp] < 3600 }
      last_hour_connections += recent.size
    end
    
    # Alerta se tráfego muito alto
    if last_hour_connections > 10000
      threat = create_threat_alert(
        :high_traffic,
        "Tráfego anormalmente alto: #{last_hour_connections} conexões/hora",
        { total_connections: last_hour_connections },
        'MEDIUM'
      )
      handle_threat_alert(threat)
    end
  end

  def detect_anomalous_behavior
    @connection_tracker.each do |ip, connections|
      next if connections.size < 10
      
      # Analisa padrões de tempo
      time_intervals = []
      connections.sort_by(&:timestamp).each_cons(2) do |conn1, conn2|
        interval = conn2[:timestamp] - conn1[:timestamp]
        time_intervals << interval if interval > 0
      end
      
      next if time_intervals.empty?
      
      # Detecta intervalos muito regulares (possível bot)
      avg_interval = time_intervals.sum / time_intervals.size
      variance = time_intervals.map { |i| (i - avg_interval) ** 2 }.sum / time_intervals.size
      
      if variance < 0.1 && avg_interval < 5 && time_intervals.size > 20
        threat = create_threat_alert(
          :bot_behavior,
          "Comportamento de bot detectado: intervalos muito regulares",
          { source_ip: ip, avg_interval: avg_interval, variance: variance },
          'MEDIUM'
        )
        handle_threat_alert(threat)
      end
    end
  end

  def threat_intelligence_checker
    loop do
      sleep 60 # Verifica a cada minuto
      
      # Verifica IPs ativos contra threat intelligence
      active_ips = get_active_ips(300) # últimos 5 min
      
      active_ips.each do |ip|
        next if whitelisted?(ip)
        
        # Simula verificação em feeds de threat intel
        threat_level = check_threat_intelligence(ip)
        
        if threat_level > 0
          severity = threat_level > 8 ? 'CRITICAL' : 
                    threat_level > 5 ? 'HIGH' : 'MEDIUM'
          
          threat = create_threat_alert(
            :threat_intel,
            "IP flagged por threat intelligence (score: #{threat_level})",
            { source_ip: ip, threat_score: threat_level },
            severity
          )
          handle_threat_alert(threat)
        end
      end
    end
  end

  def check_threat_intelligence(ip)
    # Simula consulta a feeds de threat intelligence
    # Em implementação real, consultaria APIs como VirusTotal, AbuseIPDB, etc.
    
    score = 0
    
    # Verifica se IP está em listas conhecidas
    score += 10 if MALICIOUS_IPS.include?(ip)
    
    # Simula verificação de reputação
    if ip.start_with?('192.168.100.') || ip.include?('666')
      score += rand(5..9)
    end
    
    # Simula verificação de geolocalização suspeita
    if suspicious_geolocation?(ip)
      score += rand(2..4)
    end
    
    score
  end

  def auto_respond_to_threat(threat)
    case threat[:type]
    when :malicious_ip, :ddos
      # Simula bloqueio de IP
      block_ip(threat[:source_ip])
    when :data_exfiltration
      # Simula throttling de bandwidth
      throttle_ip(threat[:source_ip])
    end
  end

  def block_ip(ip)
    log_event("AUTO-RESPONSE", "Bloqueando IP #{ip}", "INFO")
    puts "🚫 AUTO-RESPONSE: IP #{ip} bloqueado automaticamente" if @verbose
    
    # Em implementação real, executaria:
    # system("iptables -A INPUT -s #{ip} -j DROP")
  end

  def throttle_ip(ip)
    log_event("AUTO-RESPONSE", "Aplicando throttling em #{ip}", "INFO")
    puts "⏱️  AUTO-RESPONSE: Throttling aplicado em #{ip}" if @verbose
    
    # Em implementação real, aplicaria rate limiting
  end

  def data_cleanup
    loop do
      sleep 300 # Cleanup a cada 5 minutos
      
      @mutex.synchronize do
        # Remove conexões antigas (> 1 hora)
        cleanup_time = Time.now - 3600
        
        @connection_tracker.each do |ip, connections|
          @connection_tracker[ip] = connections.select do |conn|
            conn[:timestamp] > cleanup_time
          end
        end
        
        # Remove IPs sem conexões
        @connection_tracker.delete_if { |ip, connections| connections.empty? }
        
        # Limita histórico de ameaças
        if @threat_history.size > 1000
          @threat_history = @threat_history.last(500)
        end
        
        # Limpa alertas antigos
        old_alerts = @alerts_sent.select do |alert_key|
          timestamp = alert_key.split('_').last.to_i * 300
          Time.now.to_i - timestamp > 3600 # Remove alertas > 1 hora
        end
        old_alerts.each { |alert| @alerts_sent.delete(alert) }
      end
    end
  end

  def analyze_existing_connections
    puts "📊 Analisando conexões existentes..."
    
    # Simula análise de logs de conexão
    sample_connections = generate_sample_log_data
    
    sample_connections.each do |connection|
      process_connection(connection)
    end
    
    puts "✅ Análise de #{sample_connections.size} conexões completa"
  end

  def analyze_network_flows
    puts "🌊 Analisando fluxos de rede..."
    
    # Análise de padrões de tráfego
    traffic_analysis = {
      total_connections: @connection_tracker.values.sum(&:size),
      unique_sources: @connection_tracker.keys.size,
      suspicious_ips: @connection_tracker.keys.select { |ip| malicious_ip?(ip) },
      high_volume_ips: find_high_volume_ips,
      port_distribution: analyze_port_distribution
    }
    
    puts "📈 Fluxos analisados:"
    puts "   Total conexões: #{traffic_analysis[:total_connections]}"
    puts "   IPs únicos: #{traffic_analysis[:unique_sources]}"
    puts "   IPs suspeitos: #{traffic_analysis[:suspicious_ips].size}"
    puts "   IPs alto volume: #{traffic_analysis[:high_volume_ips].size}"
  end

  def generate_threat_report
    puts "\n" + "=" * 80
    puts "🛡️  RELATÓRIO DE AMEAÇAS DETECTADAS"
    puts "=" * 80
    puts "⏰ Período: #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
    puts "📊 Total de ameaças: #{@threat_history.size}"
    puts

    if @threat_history.empty?
      puts "✅ Nenhuma ameaça detectada!"
      return
    end

    # Agrupa por severidade
    by_severity = @threat_history.group_by { |t| t[:severity] }
    
    puts "📊 AMEAÇAS POR SEVERIDADE:"
    %w[CRITICAL HIGH MEDIUM LOW].each do |severity|
      count = by_severity[severity]&.size || 0
      puts "   #{severity}: #{count}" if count > 0
    end
    puts

    # Top 10 ameaças
    puts "🚨 TOP AMEAÇAS DETECTADAS:"
    threat_counts = @threat_history.group_by { |t| t[:type] }
    threat_counts.sort_by { |_, threats| -threats.size }.first(10).each do |type, threats|
      puts "   #{type.to_s.tr('_', ' ').upcase}: #{threats.size}"
    end
    puts

    # Top IPs maliciosos
    puts "🎯 TOP IPs MALICIOSOS:"
    ip_threats = @threat_history.group_by { |t| t[:source_ip] }
    ip_threats.sort_by { |_, threats| -threats.size }.first(10).each do |ip, threats|
      puts "   #{ip}: #{threats.size} ameaças"
    end
    puts

    # Ameaças críticas recentes
    critical_threats = @threat_history.select { |t| t[:severity] == 'CRITICAL' }.last(5)
    if critical_threats.any?
      puts "🚨 AMEAÇAS CRÍTICAS RECENTES:"
      critical_threats.each do |threat|
        puts "   [#{threat[:timestamp].strftime('%H:%M:%S')}] #{threat[:type]} - #{threat[:source_ip]}"
        puts "      #{threat[:description]}"
        puts
      end
    end

    # Salva relatório se especificado
    save_threat_report if @output_format == :json
  end

  def print_real_time_stats
    return unless @real_time
    
    # Clear screen and show stats
    system('clear') || system('cls')
    
    puts "🚨 NETWORK THREAT DETECTOR - TEMPO REAL"
    puts "=" * 60
    puts "⏰ #{Time.now.strftime('%Y-%m-%d %H:%M:%S')}"
    puts

    active_ips = get_active_ips(300)
    recent_threats = @threat_history.select { |t| Time.now - t[:timestamp] < 300 }
    
    puts "📊 ESTATÍSTICAS (últimos 5 min):"
    puts "   IPs ativos: #{active_ips.size}"
    puts "   Conexões: #{@connection_tracker.values.sum { |conns| conns.select { |c| Time.now - c[:timestamp] < 300 }.size }}"
    puts "   Ameaças: #{recent_threats.size}"
    puts

    if recent_threats.any?
      puts "🚨 AMEAÇAS RECENTES:"
      recent_threats.last(5).each do |threat|
        icon = threat[:severity] == 'CRITICAL' ? '🚨' : 
               threat[:severity] == 'HIGH' ? '⚠️' : '🔍'
        puts "   #{icon} #{threat[:type]} - #{threat[:source_ip]} (#{threat[:timestamp].strftime('%H:%M:%S')})"
      end
      puts
    end

    puts "💡 Pressione Ctrl+C para parar o monitoramento"
  end

  # Métodos auxiliares
  def get_recent_connections(ip, seconds)
    cutoff_time = Time.now - seconds
    @connection_tracker[ip].select { |conn| conn[:timestamp] > cutoff_time }
  end

  def get_active_ips(seconds)
    cutoff_time = Time.now - seconds
    @connection_tracker.keys.select do |ip|
      @connection_tracker[ip].any? { |conn| conn[:timestamp] > cutoff_time }
    end
  end

  def malicious_ip?(ip)
    MALICIOUS_IPS.include?(ip) || ip.include?('666') || ip.start_with?('192.168.100.')
  end

  def suspicious_port?(port)
    SUSPICIOUS_PORTS.include?(port)
  end

  def suspicious_geolocation?(ip)
    # Simula verificação de geolocalização suspeita
    ip.start_with?('192.168.') || ip.include?('.')
  end

  def whitelisted?(ip)
    @whitelist.include?(ip)
  end

  def calculate_confidence(type, details)
    base_confidence = {
      malicious_ip: 95,
      suspicious_port: 70,
      port_scan: 85,
      ddos: 90,
      data_exfiltration: 75,
      threat_intel: 80,
      bot_behavior: 65,
      high_traffic: 50
    }
    
    base_confidence[type] || 50
  end

  def generate_tcp_flags
    flags = []
    flags << 'SYN' if rand < 0.3
    flags << 'ACK' if rand < 0.7
    flags << 'FIN' if rand < 0.1
    flags << 'RST' if rand < 0.05
    flags.join(',')
  end

  def get_local_ip
    '192.168.1.1' # Simula IP local
  end

  def generate_sample_log_data
    connections = []
    
    # Gera 100 conexões de exemplo
    100.times do
      connections << {
        timestamp: Time.now - rand(3600), # últimas 1 hora
        source_ip: ['192.168.1.100', '192.168.1.101', '10.0.0.50', '192.168.100.100'].sample,
        dest_ip: get_local_ip,
        dest_port: [80, 443, 22, 21, 1234, 4444].sample,
        protocol: 'TCP',
        bytes: rand(1000..10000),
        flags: generate_tcp_flags
      }
    end
    
    connections
  end

  def find_high_volume_ips
    @connection_tracker.select { |ip, connections| connections.size > 50 }.keys
  end

  def analyze_port_distribution
    port_counts = Hash.new(0)
    @connection_tracker.values.flatten.each do |conn|
      port_counts[conn[:dest_port]] += 1
    end
    port_counts.sort_by { |port, count| -count }.first(10).to_h
  end

  def cleanup_old_connections
    cutoff_time = Time.now - 3600 # Remove conexões > 1 hora
    @connection_tracker.each do |ip, connections|
      @connection_tracker[ip] = connections.select { |conn| conn[:timestamp] > cutoff_time }
    end
    @connection_tracker.delete_if { |ip, connections| connections.empty? }
  end

  def send_webhook_alert(threat)
    return unless @alert_webhook
    
    begin
      uri = URI(@alert_webhook)
      http = Net::HTTP.new(uri.host, uri.port)
      http.use_ssl = uri.scheme == 'https'
      
      request = Net::HTTP::Post.new(uri)
      request['Content-Type'] = 'application/json'
      request.body = {
        alert_type: 'security_threat',
        severity: threat[:severity],
        description: threat[:description],
        source_ip: threat[:source_ip],
        timestamp: threat[:timestamp].iso8601,
        confidence: threat[:confidence]
      }.to_json
      
      response = http.request(request)
      log_event("WEBHOOK", "Alert sent: #{response.code}", "INFO") if @verbose
      
    rescue => e
      log_event("WEBHOOK", "Failed to send alert: #{e.message}", "ERROR")
    end
  end

  def save_threat_report
    report = {
      generated_at: Time.now.iso8601,
      summary: {
        total_threats: @threat_history.size,
        critical_threats: @threat_history.count { |t| t[:severity] == 'CRITICAL' },
        high_threats: @threat_history.count { |t| t[:severity] == 'HIGH' },
        medium_threats: @threat_history.count { |t| t[:severity] == 'MEDIUM' }
      },
      threats: @threat_history,
      statistics: {
        total_connections: @connection_tracker.values.sum(&:size),
        unique_sources: @connection_tracker.keys.size,
        active_ips: get_active_ips(3600).size
      }
    }
    
    filename = "threat_report_#{Time.now.strftime('%Y%m%d_%H%M%S')}.json"
    File.write(filename, JSON.pretty_generate(report))
    puts "💾 Relatório salvo em: #{filename}"
  end

  def log_event(category, message, level, details = nil)
    log_entry = {
      timestamp: Time.now.iso8601,
      category: category,
      level: level,
      message: message,
      details: details
    }
    
    @logger.puts(JSON.generate(log_entry))
    
    if @verbose
      puts "[#{level}] #{category}: #{message}"
    end
  end
end

# CLI Interface
if __FILE__ == $0
  options = {}
  
  OptionParser.new do |opts|
    opts.banner = "Uso: #{$0} [opções]"
    
    opts.on("-i", "--interface INTERFACE", "Interface de rede (padrão: eth0)") do |interface|
      options[:interface] = interface
    end
    
    opts.on("-v", "--verbose", "Modo verboso") do
      options[:verbose] = true
    end
    
    opts.on("-l", "--log-file FILE", "Arquivo de log (padrão: threat_detector.log)") do |file|
      options[:log_file] = file
    end
    
    opts.on("-w", "--webhook URL", "URL do webhook para alertas") do |url|
      options[:webhook] = url
    end
    
    opts.on("--whitelist FILE", "Arquivo com IPs da whitelist") do |file|
      options[:whitelist] = file
    end
    
    opts.on("-f", "--format FORMAT", "Formato de saída: text, json (padrão: text)") do |format|
      options[:format] = format.to_sym
    end
    
    opts.on("-r", "--real-time", "Monitoramento em tempo real") do
      options[:real_time] = true
    end
    
    opts.on("-h", "--help", "Mostra esta ajuda") do
      puts opts
      puts "\nExemplos:"
      puts "  #{$0} -v -r                           # Monitoramento em tempo real"
      puts "  #{$0} -f json -l threats.log          # Análise com log customizado"
      puts "  #{$0} -w http://server/webhook -v     # Com alertas por webhook"
      puts "  #{$0} --whitelist trusted_ips.txt -r  # Com whitelist personalizada"
      puts "\nFuncionalidades:"
      puts "  • Detecção de IPs maliciosos conhecidos"
      puts "  • Análise de padrões de ataque (port scan, DDoS, brute force)"
      puts "  • Threat intelligence em tempo real"
      puts "  • Auto-response para ameaças críticas"
      puts "  • Alertas via webhook"
      puts "  • Relatórios detalhados em JSON"
      exit
    end
  end.parse!

  puts "⚠️  AVISO: Use apenas em redes que você possui ou tem autorização para monitorar!"
  puts "Este detector pode gerar logs extensos e consumir recursos do sistema."
  print "Pressione Enter para continuar ou Ctrl+C para cancelar... "
  gets
  
  detector = NetworkThreatDetector.new(options)
  detector.start_monitoring
end
