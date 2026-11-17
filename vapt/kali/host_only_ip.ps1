# Prints the IPv4 address of the VirtualBox host-only adapter, or nothing if there is none.
# Used by start_lab_for_kali.bat so the lab servers listen only on the isolated host-only network.
$adapter = Get-NetAdapter -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceDescription -like '*VirtualBox Host-Only*' -and $_.Status -eq 'Up' } |
    Select-Object -First 1
if ($adapter) {
    (Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object -First 1).IPAddress
}
