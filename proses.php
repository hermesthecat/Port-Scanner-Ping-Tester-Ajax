<?php
// Port Scanner & Ping Tester - Güvenli Versiyon
header('Content-Type: text/html; charset=UTF-8');

// Güvenlik ayarları
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
	http_response_code(405);
	exit('Method Not Allowed');
}

// CSRF koruması için basit bir kontrol
if (!isset($_POST['domain'])) {
	http_response_code(400);
	exit('Bad Request');
}

// Input sanitization ve validation
function validateAndSanitizeInput($input)
{
	$input = trim($input);
	$input = filter_var($input, FILTER_SANITIZE_STRING, FILTER_FLAG_NO_ENCODE_QUOTES);

	// Domain/IP format kontrolü
	if (filter_var($input, FILTER_VALIDATE_IP)) {
		// Güvenlik: Private IP aralıklarını engelle
		if (filter_var($input, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
			return $input;
		} else {
			return false; // Private IP engellendi
		}
	} elseif (filter_var($input, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME)) {
		// Domain name validation
		if (strlen($input) <= 253 && preg_match('/^[a-zA-Z0-9.-]+$/', $input)) {
			return $input;
		}
	}

	return false;
}

$domain = validateAndSanitizeInput($_POST['domain']);

if (!$domain) {
	echo '<div style="color: #ee4444; font-weight: bold;">❌ Geçersiz domain/IP adresi!</div>';
	echo '<div style="color: #666; font-size: 0.9em;">• Private IP adresleri (192.168.x.x, 10.x.x.x, 127.x.x.x) engellendi</div>';
	echo '<div style="color: #666; font-size: 0.9em;">• Sadece geçerli domain isimleri ve public IP adresleri kabul edilir</div>';
	exit;
}

// Taranacak portlar ve açıklamaları
$ports = array(
	21 => 'FTP',
	22 => 'SSH',
	23 => 'Telnet',
	25 => 'SMTP',
	53 => 'DNS',
	80 => 'HTTP',
	110 => 'POP3',
	443 => 'HTTPS',
	993 => 'IMAPS',
	995 => 'POP3S',
	1433 => 'MSSQL',
	3306 => 'MySQL',
	5432 => 'PostgreSQL',
	8080 => 'HTTP-Alt'
);

$results = array();
$scan_start = microtime(true);

// Port tarama işlemi
foreach ($ports as $port => $service) {
	$start_time = microtime(true);

	// fsockopen ile bağlantı testi (2 saniye timeout)
	$connection = @fsockopen($domain, $port, $errno, $errstr, 2);

	if ($connection) {
		$results[$port] = array(
			'status' => 'open',
			'service' => $service,
			'response_time' => round((microtime(true) - $start_time) * 1000, 2)
		);
		fclose($connection);
	} else {
		$results[$port] = array(
			'status' => 'closed',
			'service' => $service,
			'response_time' => round((microtime(true) - $start_time) * 1000, 2)
		);
	}
}

$total_scan_time = round((microtime(true) - $scan_start), 2);

// Sonuçları HTML formatında göster
echo '<div style="margin-bottom: 15px;">';
echo '<strong>🎯 Hedef:</strong> ' . htmlspecialchars($domain, ENT_QUOTES, 'UTF-8') . '<br>';
echo '<strong>⏱️ Tarama Süresi:</strong> ' . $total_scan_time . ' saniye<br>';
echo '<strong>📊 Taranan Port:</strong> ' . count($ports) . ' adet';
echo '</div>';

$open_ports = 0;
$closed_ports = 0;

foreach ($results as $port => $result) {
	$service = $result['service'];
	$status = $result['status'];
	$response_time = $result['response_time'];

	echo '<div style="margin: 8px 0; padding: 8px; border-radius: 6px; ';

	if ($status === 'open') {
		echo 'background: #d4edda; border-left: 4px solid #28a745;">';
		echo "🟢 <strong>Port $port</strong> (<span style=\"color:#0066cc\">$service</span>): ";
		echo "<span style=\"color:#155724; font-weight: bold;\">AÇIK</span>";
		echo " <small style=\"color:#666;\">({$response_time}ms)</small>";

		// HTTP/HTTPS portları için özel link
		if ($port == 80) {
			echo " <a href=\"http://" . htmlspecialchars($domain, ENT_QUOTES, 'UTF-8') . "\" target=\"_blank\" style=\"color:#007bff; text-decoration:none;\">[🌐 Web Sitesini Aç]</a>";
		} elseif ($port == 443) {
			echo " <a href=\"https://" . htmlspecialchars($domain, ENT_QUOTES, 'UTF-8') . "\" target=\"_blank\" style=\"color:#007bff; text-decoration:none;\">[🔒 HTTPS Aç]</a>";
		}

		$open_ports++;
	} else {
		echo 'background: #f8d7da; border-left: 4px solid #dc3545;">';
		echo "🔴 <strong>Port $port</strong> (<span style=\"color:#0066cc\">$service</span>): ";
		echo "<span style=\"color:#721c24; font-weight: bold;\">KAPALI</span>";
		echo " <small style=\"color:#666;\">({$response_time}ms)</small>";
		$closed_ports++;
	}

	echo '</div>';
}

// Özet bilgiler
echo '<div style="margin-top: 20px; padding: 15px; background: #e9ecef; border-radius: 8px;">';
echo '<strong>📈 Tarama Özeti:</strong><br>';
echo "✅ Açık Portlar: <span style=\"color:#28a745; font-weight:bold;\">$open_ports</span><br>";
echo "❌ Kapalı Portlar: <span style=\"color:#dc3545; font-weight:bold;\">$closed_ports</span><br>";

if ($open_ports > 0) {
	echo '<br><div style="color:#856404; background:#fff3cd; padding:8px; border-radius:4px; font-size:0.9em;">';
	echo '⚠️ <strong>Güvenlik Notu:</strong> Açık portlar potansiyel güvenlik riskleri oluşturabilir. ';
	echo 'Gerekli olmayan servisleri kapatmayı düşünün.';
	echo '</div>';
}

echo '</div>';

// Rate limiting için basit kontrol (opsiyonel)
if (!isset($_SESSION)) {
	session_start();
}

$_SESSION['last_scan_time'] = time();
