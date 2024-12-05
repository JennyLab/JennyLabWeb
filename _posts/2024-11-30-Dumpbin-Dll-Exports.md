

### dump-dll_exports.py <file.dll>

```python
import pefile
import sys

# Asegurarse de que se proporciona un archivo como argumento
if len(sys.argv) != 2:
    print("Uso: python dumpbin_exports_clone.py <archivo.dll/exe>")
    sys.exit(1)

# Archivo DLL o EXE objetivo
file_path = sys.argv[1]

try:
    # Cargar el archivo PE
    pe = pefile.PE(file_path)

    # Comprobar si tiene una tabla de exportaciones
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print(f"Exportaciones del archivo {file_path}:")
        print("Ordinal  RVA      Nombre")
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            ordinal = export.ordinal
            rva = hex(export.address)
            name = export.name.decode('utf-8') if export.name else ""
            print(f"{ordinal:7} {rva:8} {name}")
    else:
        print(f"El archivo {file_path} no tiene exportaciones.")

except FileNotFoundError:
    print(f"Error: El archivo {file_path} no se encontró.")
except pefile.PEFormatError:
    print(f"Error: {file_path} no es un archivo PE válido.")
```



```powershell
# PowerShell script para replicar el comportamiento de 'dumpbin /exports'

param (
    [Parameter(Mandatory=$true)]
    [string]$FilePath
)

function Get-PEExports {
    param (
        [string]$Path
    )

    try {
        # Comprobar si el archivo existe
        if (-not (Test-Path -Path $Path)) {
            Write-Error "Error: El archivo $Path no se encontró."
            return
        }

        # Leer el archivo PE y obtener el encabezado DOS
        $fs = [System.IO.File]::OpenRead($Path)
        $br = New-Object System.IO.BinaryReader($fs)

        # Leer el encabezado DOS
        $dosHeader = $br.ReadBytes(64)
        $e_lfanew = [BitConverter]::ToUInt32($dosHeader, 60)
        $fs.Seek($e_lfanew, 'Begin') | Out-Null

        # Leer el encabezado NT
        $ntHeader = $br.ReadBytes(248)
        $optionalHeaderOffset = 24
        $numberOfRvaAndSizes = [BitConverter]::ToUInt32($ntHeader, $optionalHeaderOffset + 92)

        if ($numberOfRvaAndSizes -lt 1) {
            Write-Output "El archivo $Path no tiene exportaciones."
            return
        }

        # Leer la tabla de exportaciones
        $exportDirectoryRva = [BitConverter]::ToUInt32($ntHeader, $optionalHeaderOffset + 96)
        $exportDirectorySize = [BitConverter]::ToUInt32($ntHeader, $optionalHeaderOffset + 100)
        $fs.Seek($exportDirectoryRva, 'Begin') | Out-Null
        $exportDirectory = $br.ReadBytes($exportDirectorySize)

        # Leer información de las exportaciones
        $numberOfFunctions = [BitConverter]::ToUInt32($exportDirectory, 24)
        $numberOfNames = [BitConverter]::ToUInt32($exportDirectory, 28)
        $addressOfFunctions = [BitConverter]::ToUInt32($exportDirectory, 32)
        $addressOfNames = [BitConverter]::ToUInt32($exportDirectory, 36)
        $addressOfNameOrdinals = [BitConverter]::ToUInt32($exportDirectory, 40)

        Write-Output "Exportaciones del archivo $Path:"
        Write-Output "Ordinal  RVA      Nombre"

        for ($i = 0; $i -lt $numberOfNames; $i++) {
            $fs.Seek($addressOfNames + ($i * 4), 'Begin') | Out-Null
            $nameRva = [BitConverter]::ToUInt32($br.ReadBytes(4), 0)
            $fs.Seek($nameRva, 'Begin') | Out-Null
            $name = ""
            while (($char = $br.ReadByte()) -ne 0) {
                $name += [char]$char
            }

            $fs.Seek($addressOfNameOrdinals + ($i * 2), 'Begin') | Out-Null
            $ordinal = [BitConverter]::ToUInt16($br.ReadBytes(2), 0)

            $fs.Seek($addressOfFunctions + ($ordinal * 4), 'Begin') | Out-Null
            $functionRva = [BitConverter]::ToUInt32($br.ReadBytes(4), 0)

            Write-Output "{0,7} {1,8:X} {2}" -f $ordinal, $functionRva, $name
        }
    } catch {
        Write-Error "Error: $($_.Exception.Message)"
    } finally {
        $br.Close()
        $fs.Close()
    }
}

Get-PEExports -Path $FilePath


```