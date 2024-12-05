

```powershell
# Convertido a PowerShell

# Cargar las bibliotecas necesarias
$kernel32 = "kernel32.dll"
$ntAllocateVirtualMemoryStr = "NtAllocateVirtualMemory"

# Cargar kernel32.dll para obtener las funciones necesarias
$kernel32Handle = [System.Runtime.InteropServices.Marshal]::LoadLibrary($kernel32)
if ($kernel32Handle -eq 0) {
    Write-Error "Error: No se pudo cargar kernel32.dll"
    exit
}

# Obtener la dirección de NtAllocateVirtualMemory
$ntAllocateVirtualMemoryAddr = [System.Runtime.InteropServices.Marshal]::GetProcAddress($kernel32Handle, $ntAllocateVirtualMemoryStr)
if ($ntAllocateVirtualMemoryAddr -eq 0) {
    Write-Error "Error: No se pudo obtener la dirección de NtAllocateVirtualMemory"
    exit
}

# Ejemplo de estructura ExampleStruct
$exampleStruct = [PSCustomObject]@{
    NtAllocateVirtualMemory = $ntAllocateVirtualMemoryAddr
    ProcessHandle = 0x1
    BaseAddress = 0x2
    RegionSize = 0x1000
    Protect = 0x40
    AllocationType = 0x3000
    ZeroBits = 0
}

# Función de bloqueo
function Lock {
    while (-not ([System.Threading.Interlocked]::CompareExchange([ref]$global:lockFlag, 1, 0) -eq 0)) {
        Start-Sleep -Milliseconds 1  # Pequeño retardo para evitar busy-waiting
    }
}

# Función de desbloqueo
function Unlock {
    [System.Threading.Interlocked]::Exchange([ref]$global:lockFlag, 0) | Out-Null
}

# Llamar a la función de ejemplo
function WorkCallback {
    param ([PSCustomObject]$example)

    if (-not $example -or -not $example.NtAllocateVirtualMemory) {
        Write-Error "Error: Parámetro example inválido"
        return
    }

    # Bloqueo para asegurar la seguridad del hilo
    Lock

    # Parámetros para la función NtAllocateVirtualMemory
    $processHandle = $example.ProcessHandle
    $baseAddress = [ref]$example.BaseAddress
    $zeroBits = $example.ZeroBits
    $regionSize = [ref]$example.RegionSize
    $allocationType = $example.AllocationType
    $protect = $example.Protect

    # Simular llamada a la función
    Write-Output "Llamando a NtAllocateVirtualMemory con los siguientes parámetros:"
    Write-Output "ProcessHandle: $processHandle"
    Write-Output "BaseAddress: $baseAddress"
    Write-Output "ZeroBits: $zeroBits"
    Write-Output "RegionSize: $regionSize"
    Write-Output "AllocationType: $allocationType"
    Write-Output "Protect: $protect"

    # Desbloquear después de la sección crítica
    Unlock
}

# Llamar a la función WorkCallback con el ejemplo
WorkCallback -example $exampleStruct
```
