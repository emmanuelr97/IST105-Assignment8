<?php
header('Content-Type: application/json'); 

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $mac = $_POST['mac_address'];
    $dhcp_version = $_POST['dhcp_version'];

    $mac_clean = escapeshellarg($mac);
    $dhcp_clean = escapeshellarg($dhcp_version);

    $command = "python3 network_config.py --mac $mac_clean --dhcp-version $dhcp_clean 2>&1";
    $output = shell_exec($command);
    $response = json_decode($output, true);

    if ($response) {
        echo "<h3>Result:</h3><pre>";
        if (isset($response['error'])) {
            echo "Error: " . $response['error'];
        } else {
            echo "MAC: " . $response['mac_address'] . "\n";
            $ip_key = isset($response['assigned_ipv4']) ? 'assigned_ipv4' : 'assigned_ipv6';
            echo "IP: " . $response[$ip_key] . "\n";
            echo "Lease: " . $response['lease_time'] . "\n";
            echo "Subnet: " . $response['subnet'];
        }
        echo "</pre>";
    } else {
        echo "Error: Invalid response from server";
    }
}