# run.ps1 - Genera iface.txt y ejecuta contenedor

#Ruta del archivo iface.txt
$ifaceFile = "iface.txt"

# Eliminar iface.txt si existe
if (Test-Path $ifaceFile) {
    Remove-Item $ifaceFile
}

#Generar lista de interfaces con IP valida
$ifaces = Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -ne "0.0.0.0" -and
    $_.IPAddress -notlike "169.*" -and
    $_.IPAddress -notlike "127.*"
} | Select-Object -Property InterfaceAlias,IPAddress

# Guardar en iface.txt
$ifaces | ForEach-Object {
    if ($_.InterfaceAlias -and $_.IPAddress) {
        "$($_.InterfaceAlias),$($_.IPAddress)"
    }
} | Out-File -Encoding UTF8 $ifaceFile

Write-Host "✅ iface.txt generado"

#Crear carpeta para la base de datos
$dir = "data"
if (-Not (Test-Path $dir)) {
    New-Item -ItemType Directory -Path $dir | Out-Null
}

#Ejecutar el contenedor Docker
docker run -it  `
    --net=host `
    --cap-add=NET_ADMIN `
    -v "${PWD}\iface.txt:/app/iface.txt" `
    -v "${PWD}\data:/app/data" `
    sniffer-lite