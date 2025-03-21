<!DOCTYPE html>
<html>
<head>
    <title>DHCP IP Request</title>
</head>
<body>
    <h2>Request an IP Address</h2>
    <form action="process.php" method="post">
        MAC Address: <input type="text" name="mac_address" required 
        pattern="^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"><br>
        DHCP Version: 
        <select name="dhcp_version" required>
            <option value="DHCPv4">DHCPv4</option>
            <option value="DHCPv6">DHCPv6</option>
        </select><br>
        <input type="submit" value="Submit">
    </form>
</body>
</html>