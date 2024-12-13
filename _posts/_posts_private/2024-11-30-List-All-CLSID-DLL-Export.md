
# Enumeración CLSID

### C++
```c++
#include <windows.h>
#include <initguid.h>
#include <comdef.h>
#include <objbase.h>
#include <stdint.h>
#include <iostream>

// Función para enumerar CLSID registrados en el sistema
void EnumerateCOMClasses() {
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Error al abrir la clave de registro CLSID." << std::endl;
        return;
    }

    WCHAR clsidStr[256];
    DWORD index = 0;
    DWORD size = sizeof(clsidStr) / sizeof(WCHAR);
    while (RegEnumKeyEx(hKey, index, clsidStr, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        CLSID clsid;
        if (CLSIDFromString(clsidStr, &clsid) == S_OK) {
            std::wcout << L"CLSID encontrado: " << clsidStr << std::endl;

            // Aquí podrías intentar crear instancias de objetos COM y hacer fuzzing
            // con el código previamente definido.

        }
        index++;
        size = sizeof(clsidStr) / sizeof(WCHAR);
    }

    RegCloseKey(hKey);
}

int main() {
    // Enumerar todas las clases COM y tratar de hacer fuzzing sobre ellas
    EnumerateCOMClasses();
    return 0;
}
``` 


### C
```c
#include <windows.h>
#include <initguid.h>
#include <comdef.h>
#include <objbase.h>
#include <stdint.h>
#include <iostream>

// Función para enumerar CLSID registrados en el sistema
void EnumerateCOMClasses() {
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        std::cerr << "Error al abrir la clave de registro CLSID." << std::endl;
        return;
    }

    WCHAR clsidStr[256];
    DWORD index = 0;
    DWORD size = sizeof(clsidStr) / sizeof(WCHAR);
    while (RegEnumKeyEx(hKey, index, clsidStr, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        CLSID clsid;
        if (CLSIDFromString(clsidStr, &clsid) == S_OK) {
            std::wcout << L"CLSID encontrado: " << clsidStr << std::endl;

            // Aquí podrías intentar crear instancias de objetos COM y hacer fuzzing
            // con el código previamente definido.

        }
        index++;
        size = sizeof(clsidStr) / sizeof(WCHAR);
    }

    RegCloseKey(hKey);
}

int main() {
    // Enumerar todas las clases COM y tratar de hacer fuzzing sobre ellas
    EnumerateCOMClasses();
    return 0;
}
```



# ASM



Entiendo que quieres llevar el proceso de fuzzing de una interfaz COM a nivel de ensamblador utilizando NASM para una plataforma Windows 11 de 64 bits. Esto implica trabajar con las interfaces COM utilizando llamadas directas a las funciones del sistema operativo, con manejo de GUIDs (para instanciar los objetos COM) y llamadas a métodos de una interfaz.

Alcances y Desafíos en NASM
COM es un modelo de objetos que normalmente se accede a través de un enfoque de alto nivel debido a la complejidad de sus interfaces.
Implementar un fuzzer en NASM para Windows requiere manejar manualmente todas las llamadas a funciones del sistema, gestionar correctamente los GUIDs y trabajar con los métodos IUnknown e IDispatch.
Para comenzar, aquí te doy una guía de cómo podrías aproximarte a este problema y un ejemplo de cómo trabajar con una interfaz COM en ensamblador NASM.

Enfoque del Código
El objetivo es:

Inicializar COM usando CoInitialize.
Crear una instancia del objeto COM usando CoCreateInstance.
Llamar a un método de la interfaz COM (por ejemplo, IUnknown o IDispatch).
Código de Ejemplo en NASM para Fuzzing de Interfaz COM
A continuación, proporcionaré un ejemplo que:

Inicializa la biblioteca COM.
Crea una instancia de un objeto COM utilizando su GUID (CLSID).
Obtiene un puntero a una interfaz (por ejemplo, IUnknown).
Llama a un método de la interfaz para realizar una operación de prueba.
Código fuzz_com.asmonceptual en NASM que muestra cómo puedes inicializar COM y trabajar con una interfaz.


```nasm

section .data
    clsid_str db "{00021401-0000-0000-C000-000000000046}", 0   ; CLSID_ShellLink (como ejemplo)
    iid_iunknown dq 0x00000000, 0x0000, 0x0000, 0xC0000000000046

    ; Mensajes de error y éxito
    error_com_init db "Error: No se pudo inicializar COM.", 0
    error_clsid db "Error: No se pudo convertir el CLSID.", 0
    error_instance db "Error: No se pudo crear la instancia COM.", 0
    success_message db "Instancia COM creada con éxito.", 0

section .bss
    ; Variables no inicializadas
    pUnknown resq 1
    clsid resb 16

section .text
    extern CoInitialize
    extern CoCreateInstance
    extern CLSIDFromString
    extern MessageBoxA
    extern ExitProcess

    global _start

_start:
    ; Inicializar COM
    sub rsp, 28h                          ; Reserva de pila
    xor rcx, rcx                          ; CoInitialize(NULL)
    call CoInitialize
    test eax, eax
    js com_init_failed                    ; Si falla, ir a manejo de error

    ; Convertir CLSID (string a CLSID)
    lea rcx, [clsid_str]                  ; Dirección del CLSID como cadena
    lea rdx, [clsid]                      ; Dirección donde se almacenará el CLSID
    call CLSIDFromString
    test eax, eax
    js clsid_failed                       ; Si falla, ir a manejo de error

    ; Crear la instancia del objeto COM
    lea rcx, [clsid]                      ; CLSID del objeto COM
    xor rdx, rdx                          ; pUnkOuter = NULL
    mov r8d, 0x1                          ; CLSCTX_INPROC_SERVER
    lea r9, [iid_iunknown]                ; IID_IUnknown
    lea rax, [pUnknown]                   ; Almacenar el puntero a la instancia
    mov qword [rsp+20h], rax              ; Tercer parámetro en la pila
    call CoCreateInstance
    test eax, eax
    js instance_failed                    ; Si falla, ir a manejo de error

    ; Mensaje de éxito
    lea rcx, [success_message]
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call MessageBoxA

    ; Liberar la instancia y salir
    mov rcx, [pUnknown]
    test rcx, rcx
    jz exit_program
    mov rax, [rcx]                        ; VTable pointer
    mov rax, [rax]                        ; IUnknown::Release
    call rax

exit_program:
    xor ecx, ecx
    call ExitProcess

; Manejo de errores

com_init_failed:
    lea rcx, [error_com_init]
    jmp display_error

clsid_failed:
    lea rcx, [error_clsid]
    jmp display_error

instance_failed:
    lea rcx, [error_instance]

display_error:
    xor rdx, rdx
    xor r8, r8
    xor r9, r9
    call MessageBoxA
    jmp exit_program

```


plicación del Código
Sección de Datos y BSS:

La sección .data contiene las cadenas necesarias, incluyendo el CLSID como una cadena (clsid_str) para ser utilizada por CLSIDFromString.
En .bss se declara pUnknown, que almacenará el puntero a la interfaz IUnknown del objeto COM.
Inicialización de COM (CoInitialize):

Utiliza la función CoInitialize para inicializar el subsistema COM.
Si falla (js), se muestra un mensaje de error usando MessageBoxA.
Conversión del CLSID (CLSIDFromString):

Convierte la representación en cadena del CLSID (clsid_str) a un objeto CLSID binario para su uso posterior.
Creación de la Instancia del Objeto COM (CoCreateInstance):

Utiliza el CLSID convertido para crear una instancia del objeto COM con CoCreateInstance.
Si CoCreateInstance falla, se muestra un mensaje de error.
IID_IUnknown se usa para obtener el puntero de IUnknown del objeto creado.
Liberación de la Interfaz (IUnknown::Release):

Una vez finalizado, se libera la referencia al objeto COM llamando al método Release de la interfaz IUnknown.
Esto se hace accediendo a la VTable de IUnknown para encontrar la dirección de Release.
Manejo de Errores:

Las secciones com_init_failed, clsid_failed, y instance_failed manejan errores para las operaciones de inicialización de COM, conversión de CLSID, y creación de instancia del objeto.
Notas Importantes
Manejo de la Pila en Llamadas a Funciones:

En Windows de 64 bits, las primeras cuatro variables se pasan por los registros (rcx, rdx, r8, r9). Si hay más parámetros, se pasan por la pila.
Es importante gestionar adecuadamente la reserva de la pila, en este caso sub rsp, 28h, para mantener el alineamiento de la pila, que en Windows debe estar alineada a 16 bytes.
VTable en COM:

La VTable en COM contiene los punteros a funciones de la interfaz. En este ejemplo, para liberar la interfaz (IUnknown::Release), se accede a la VTable de la interfaz para hacer la llamada manualmente.
Fuzzing de Métodos COM:

Para realizar fuzzing de los métodos, puedes modificar la lógica para pasar datos generados a funciones como Invoke de IDispatch.
Los datos de fuzzing pueden ser generados por un programa externo (como libFuzzer) y luego alimentados a este ensamblador para realizar las llamadas.
Entorno de Pruebas:

Debido a la complejidad de trabajar directamente con COM en ensamblador, es crucial realizar pruebas en un entorno controlado para evitar fallos en el sistema que puedan afectar la estabilidad general.
Desafíos
Trabajar con COM en ensamblador no es común debido a la complejidad de las operaciones requeridas, como la gestión de GUIDs, el uso de interfaces virtuales (VTables), y la llamada a métodos que esperan tipos de datos complejos.
libFuzzer está diseñado para trabajar con código de nivel más alto, como C o C++. Fuzzing de interfaces COM con ensamblador es extremadamente complejo debido a la naturaleza de los objetos COM y su uso de referencias y objetos abstractos.
Resumen
El ejemplo muestra cómo inicializar COM, crear un objeto COM a partir de su CLSID, y trabajar con la interfaz IUnknown.
Puedes adaptar este código para llamar a métodos de otras interfaces COM (por ejemplo, IDispatch).
Trabajar con COM en ensamblador requiere un conocimiento profundo de las estructuras de datos COM, el uso de VTables, y la gestión precisa de la pila y los registros.


```c
#include <windows.h>
#include <initguid.h>
#include <comdef.h>
#include <objbase.h>
#include <stdint.h>
#include <stdio.h>

// Función para enumerar CLSID registrados en el sistema y hacer fuzzing
void EnumerateCOMClasses() {
    HKEY hKey;
    LONG result = RegOpenKeyEx(HKEY_CLASSES_ROOT, L"CLSID", 0, KEY_READ, &hKey);
    if (result != ERROR_SUCCESS) {
        fprintf(stderr, "Error al abrir la clave de registro CLSID.\n");
        return;
    }

    WCHAR clsidStr[256];
    DWORD index = 0;
    DWORD size = sizeof(clsidStr) / sizeof(WCHAR);
    while (RegEnumKeyEx(hKey, index, clsidStr, &size, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
        CLSID clsid;
        if (CLSIDFromString(clsidStr, &clsid) == S_OK) {
            wprintf(L"CLSID encontrado: %ls\n", clsidStr);

            // Intentar crear una instancia del objeto COM
            IUnknown* pUnknown = NULL;
            HRESULT hr = CoCreateInstance(clsid, NULL, CLSCTX_INPROC_SERVER | CLSCTX_LOCAL_SERVER, IID_IUnknown, (void**)&pUnknown);
            if (SUCCEEDED(hr)) {
                wprintf(L"Instancia creada con éxito para CLSID: %ls\n", clsidStr);

                // Aquí podrías hacer fuzzing llamando a diferentes métodos del objeto COM
                // Por ejemplo, llamamos a AddRef y Release para verificar si hay comportamientos inusuales
                pUnknown->AddRef();
                pUnknown->Release();

                // Liberar el objeto COM
                pUnknown->Release();
            } else {
                wprintf(L"No se pudo crear la instancia para CLSID: %ls. Código de error: 0x%08lx\n", clsidStr, hr);
            }
        }
        index++;
        size = sizeof(clsidStr) / sizeof(WCHAR);
    }

    RegCloseKey(hKey);
}

int main() {
    // Inicializar COM
    HRESULT hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        fprintf(stderr, "Error al inicializar COM.\n");
        return 1;
    }

    // Enumerar todas las clases COM y tratar de hacer fuzzing sobre ellas
    EnumerateCOMClasses();

    // Finalizar COM
    CoUninitialize();

    return 0;
}
```










# DLL EXPORT

### vbscript
```vb
' VBScript para replicar el comportamiento de 'dumpbin /exports'

Function GetPEExports(filePath)
    On Error Resume Next
    
    Set fso = CreateObject("Scripting.FileSystemObject")
    If Not fso.FileExists(filePath) Then
        WScript.Echo "Error: El archivo " & filePath & " no se encontró."
        Exit Function
    End If

    Set fileStream = fso.OpenTextFile(filePath, 1, False)
    fileData = fileStream.ReadAll()
    fileStream.Close

    ' Obtener el encabezado DOS
    e_lfanew = AscB(MidB(fileData, 61, 1)) + (AscB(MidB(fileData, 62, 1)) * 256) + (AscB(MidB(fileData, 63, 1)) * 65536) + (AscB(MidB(fileData, 64, 1)) * 16777216)
    ntHeaderOffset = e_lfanew + 4
    
    ' Leer el encabezado NT
    If LenB(fileData) < ntHeaderOffset + 248 Then
        WScript.Echo "El archivo " & filePath & " no tiene un encabezado NT válido."
        Exit Function
    End If

    ' Leer la tabla de exportaciones
    exportDirectoryRva = AscB(MidB(fileData, ntHeaderOffset + 96, 1)) + (AscB(MidB(fileData, ntHeaderOffset + 97, 1)) * 256) + (AscB(MidB(fileData, ntHeaderOffset + 98, 1)) * 65536) + (AscB(MidB(fileData, ntHeaderOffset + 99, 1)) * 16777216)
    
    If exportDirectoryRva = 0 Then
        WScript.Echo "El archivo " & filePath & " no tiene exportaciones."
        Exit Function
    End If

    WScript.Echo "Exportaciones del archivo " & filePath & ":"
    WScript.Echo "Ordinal  RVA      Nombre"

    ' Nota: Este ejemplo solo muestra cómo se puede iniciar, pero un análisis detallado de la tabla de exportación requeriría el procesamiento binario detallado.
    ' Esto incluye iterar sobre la tabla de funciones, nombres y ordinales para imprimir todas las exportaciones.
End Function

' Archivo de ejemplo a analizar
Dim filePath
filePath = WScript.Arguments(0)

Call GetPEExports(filePath)
```


### VBA
```vb
' VBA para replicar el comportamiento de 'dumpbin /exports'

Sub GetPEExports(filePath As String)
    On Error GoTo ErrorHandler
    
    Dim fso As Object
    Set fso = CreateObject("Scripting.FileSystemObject")
    
    If Not fso.FileExists(filePath) Then
        MsgBox "Error: El archivo " & filePath & " no se encontró."
        Exit Sub
    End If

    Dim fileStream As Object
    Set fileStream = fso.OpenTextFile(filePath, 1, False)
    Dim fileData As String
    fileData = fileStream.ReadAll()
    fileStream.Close

    ' Obtener el encabezado DOS
    Dim e_lfanew As Long
    e_lfanew = AscB(MidB(fileData, 61, 1)) + (AscB(MidB(fileData, 62, 1)) * 256) + (AscB(MidB(fileData, 63, 1)) * 65536) + (AscB(MidB(fileData, 64, 1)) * 16777216)
    Dim ntHeaderOffset As Long
    ntHeaderOffset = e_lfanew + 4
    
    ' Leer el encabezado NT
    If LenB(fileData) < ntHeaderOffset + 248 Then
        MsgBox "El archivo " & filePath & " no tiene un encabezado NT válido."
        Exit Sub
    End If

    ' Leer la tabla de exportaciones
    Dim exportDirectoryRva As Long
    exportDirectoryRva = AscB(MidB(fileData, ntHeaderOffset + 96, 1)) + (AscB(MidB(fileData, ntHeaderOffset + 97, 1)) * 256) + (AscB(MidB(fileData, ntHeaderOffset + 98, 1)) * 65536) + (AscB(MidB(fileData, ntHeaderOffset + 99, 1)) * 16777216)
    
    If exportDirectoryRva = 0 Then
        MsgBox "El archivo " & filePath & " no tiene exportaciones."
        Exit Sub
    End If

    MsgBox "Exportaciones del archivo " & filePath & ":"
    MsgBox "Ordinal  RVA      Nombre"

    ' Nota: Este ejemplo solo muestra cómo se puede iniciar, pero un análisis detallado de la tabla de exportación requeriría el procesamiento binario detallado.
    ' Esto incluye iterar sobre la tabla de funciones, nombres y ordinales para imprimir todas las exportaciones.

    Exit Sub

ErrorHandler:
    MsgBox "Error: " & Err.Description
End Sub

' Archivo de ejemplo a analizar
Sub TestGetPEExports()
    Dim filePath As String
    filePath = "C:\ruta\al\archivo.dll"
    GetPEExports filePath
End Sub
```



### JS (WSH: Windows Scripting Host)
```js 
// JavaScript nativo para replicar el comportamiento de 'dumpbin /exports'

function getPEExports(filePath) {
    try {
        // Leer el archivo como un binario
        var fso = new ActiveXObject("Scripting.FileSystemObject");
        if (!fso.FileExists(filePath)) {
            WScript.Echo("Error: El archivo " + filePath + " no se encontró.");
            return;
        }

        var fileStream = fso.OpenTextFile(filePath, 1, false);
        var fileData = fileStream.ReadAll();
        fileStream.Close();

        // Convertir el archivo a una matriz de bytes
        var bytes = [];
        for (var i = 0; i < fileData.length; i++) {
            bytes.push(fileData.charCodeAt(i) & 0xFF);
        }

        // Obtener el encabezado DOS
        var e_lfanew = bytes[60] + (bytes[61] << 8) + (bytes[62] << 16) + (bytes[63] << 24);
        var ntHeaderOffset = e_lfanew + 4;

        // Leer el encabezado NT
        if (bytes.length < ntHeaderOffset + 248) {
            WScript.Echo("El archivo " + filePath + " no tiene un encabezado NT válido.");
            return;
        }

        // Leer la tabla de exportaciones
        var exportDirectoryRva = bytes[ntHeaderOffset + 96] + (bytes[ntHeaderOffset + 97] << 8) + (bytes[ntHeaderOffset + 98] << 16) + (bytes[ntHeaderOffset + 99] << 24);

        if (exportDirectoryRva === 0) {
            WScript.Echo("El archivo " + filePath + " no tiene exportaciones.");
            return;
        }

        WScript.Echo("Exportaciones del archivo " + filePath + ":");
        WScript.Echo("Ordinal  RVA      Nombre");

        // Nota: Este ejemplo solo muestra cómo se puede iniciar, pero un análisis detallado de la tabla de exportación requeriría el procesamiento binario detallado.
        // Esto incluye iterar sobre la tabla de funciones, nombres y ordinales para imprimir todas las exportaciones.
    } catch (e) {
        WScript.Echo("Error: " + e.message);
    }
}

// Archivo de ejemplo a analizar
var filePath = WScript.Arguments(0);
getPEExports(filePath);
```



# vbscript
```vb
' VBScript para obtener las exportaciones de una DLL cargada en un proceso
Function GetDllExportsFromProcess(processId, dllName)
    On Error Resume Next
    
    ' Crear un snapshot del proceso
    Set wmi = GetObject("winmgmts:\\.\root\cimv2")
    query = "SELECT * FROM Win32_Process WHERE ProcessId = " & processId
    Set processes = wmi.ExecQuery(query)
    
    If processes.Count = 0 Then
        WScript.Echo "Error: No se encontró el proceso con ID " & processId
        Exit Function
    End If

    For Each process In processes
        modules = process.GetOwner()
        For Each module In modules
            If LCase(module.Name) = LCase(dllName) Then
                WScript.Echo "Exportaciones de la DLL " & dllName & " en el proceso " & processId & ":"
                WScript.Echo "Ordinal  RVA      Nombre"
                ' Aquí se debería analizar la tabla de exportaciones del módulo
                ' Esto incluiría leer directamente el archivo PE para buscar la tabla de exportaciones,
                ' lo cual no es fácil de implementar en VBScript sin bibliotecas externas.
                Exit For
            End If
        Next
    Next

    WScript.Echo "Error: No se pudo encontrar la DLL especificada en el proceso."
End Function

' Archivo de ejemplo a analizar
Dim processId, dllName
processId = WScript.Arguments(0)
dllName = WScript.Arguments(1)

Call GetDllExportsFromProcess(processId, dllName)
```





```powershell
# PowerShell para obtener las exportaciones de una DLL cargada en un proceso

param (
    [Parameter(Mandatory=$true)]
    [int]$ProcessId,
    [Parameter(Mandatory=$true)]
    [string]$DllName
)

function Get-DllExportsFromProcess {
    param (
        [int]$ProcessId,
        [string]$DllName
    )

    try {
        # Obtener los módulos del proceso
        $modules = Get-WmiObject -Query "SELECT * FROM Win32_Process WHERE ProcessId = $ProcessId"
        if ($modules -eq $null) {
            Write-Output "Error: No se encontró el proceso con ID $ProcessId."
            return
        }

        foreach ($module in $modules) {
            $loadedModules = (Get-Process -Id $ProcessId).Modules
            foreach ($loadedModule in $loadedModules) {
                if ($loadedModule.ModuleName -ieq $DllName) {
                    Write-Output "Exportaciones de la DLL $DllName en el proceso $ProcessId:"
                    Write-Output "Ordinal  RVA      Nombre"
                    # Aquí se debería analizar la tabla de exportaciones del módulo
                    # Esto incluiría leer directamente el archivo PE para buscar la tabla de exportaciones,
                    # lo cual requiere manejo detallado del archivo binario PE.
                    return
                }
            }
        }
        Write-Output "Error: No se pudo encontrar la DLL especificada en el proceso."
    } catch {
        Write-Output "Error: $_.Exception.Message"
    }
}

Get-DllExportsFromProcess -ProcessId $ProcessId -DllName $DllName
```




```powershell
# PowerShell para obtener las exportaciones de una DLL cargada en un proceso

param (
    [Parameter(Mandatory=$true)]
    [int]$ProcessId,
    [Parameter(Mandatory=$true)]
    [string]$DllName
)

function Get-DllExportsFromProcess {
    param (
        [int]$ProcessId,
        [string]$DllName
    )

    try {
        # Obtener los módulos del proceso utilizando el Snap-in de Debugging
        $moduleHandle = [System.Diagnostics.Process]::GetProcessById($ProcessId).Modules |
                         Where-Object { $_.ModuleName -ieq $DllName }

        if ($moduleHandle -eq $null) {
            Write-Output "Error: No se pudo encontrar la DLL especificada en el proceso."
            return
        }

        $dllPath = $moduleHandle.FileName

        # Cargar el archivo PE usando Streams y analizar la tabla de exportaciones
        $fs = [System.IO.File]::OpenRead($dllPath)
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
            Write-Output "El archivo $dllPath no tiene exportaciones."
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

        Write-Output "Exportaciones del archivo $dllPath:"
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
        Write-Output "Error: $_.Exception.Message"
    } finally {
        if ($br) { $br.Close() }
        if ($fs) { $fs.Close() }
    }
}

Get-DllExportsFromProcess -ProcessId $ProcessId -DllName $DllName
```


```batch
@echo off
REM Batch script para obtener las exportaciones de una DLL cargada en un proceso

set /p ProcessId="Ingrese el ID del proceso: "
set /p DllName="Ingrese el nombre de la DLL (ejemplo.dll): "

REM Crear un archivo temporal para guardar el resultado de los módulos
set TempFile=%TEMP%\modules.txt

tasklist /m /fi "pid eq %ProcessId%" > %TempFile%

REM Buscar la DLL en la lista de módulos cargados
findstr /i /c:"%DllName%" %TempFile% > nul
if %errorlevel% neq 0 (
    echo Error: No se pudo encontrar la DLL especificada en el proceso.
    del %TempFile%
    exit /b 1
)

echo Exportaciones de la DLL %DllName% en el proceso %ProcessId%:
echo Ordinal  RVA      Nombre

REM Aquí no se puede analizar la tabla de exportaciones directamente con batch
REM Para hacer un análisis detallado, sería necesario usar otra herramienta o lenguaje
REM que permita leer archivos binarios como la tabla de exportaciones PE

del %TempFile%
echo Operación completada.
exit /b 0
```


```batch
@echo off
REM Batch script mejorado para obtener las exportaciones de una DLL cargada en un proceso

set /p ProcessId="Ingrese el ID del proceso: "
set /p DllName="Ingrese el nombre de la DLL (ejemplo.dll): "

REM Utilizar WMIC para obtener la ruta completa del módulo de la DLL
for /f "tokens=2 delims==" %%i in ('wmic process where (processid^=%ProcessId%) get executablepath /format:list 2^>nul') do (
    set ProcessPath=%%i
)

if "%ProcessPath%"=="" (
    echo Error: No se pudo encontrar el proceso con ID %ProcessId%.
    exit /b 1
)

REM Buscar la DLL en el proceso usando powershell
for /f "tokens=*" %%i in ('powershell -command "(Get-Process -Id %ProcessId%).Modules | Where-Object { $_.ModuleName -ieq '%DllName%' }"') do (
    set DllPath=%%i
)

if "%DllPath%"=="" (
    echo Error: No se pudo encontrar la DLL especificada en el proceso.
    exit /b 1
)

echo Exportaciones de la DLL %DllName% en el proceso %ProcessId%:
echo Ordinal  RVA      Nombre

REM Aquí no se puede analizar la tabla de exportaciones directamente con batch
REM Para hacer un análisis detallado, sería necesario usar otra herramienta o lenguaje
REM que permita leer archivos binarios como la tabla de exportaciones PE

echo Operación completada.
exit /b 0
```

REQUIERE listsdirs de sysinternals
```batch
@echo off
REM Batch script mejorado para obtener las exportaciones de una DLL cargada en un proceso

set /p ProcessId="Ingrese el ID del proceso: "
set /p DllName="Ingrese el nombre de la DLL (ejemplo.dll): "

REM Utilizar tasklist para verificar si el proceso está en ejecución
tasklist /fi "PID eq %ProcessId%" | findstr /i "%ProcessId%" > nul
if %errorlevel% neq 0 (
    echo Error: No se encontró un proceso con ID %ProcessId%.
    exit /b 1
)

REM Utilizar listdlls (de Sysinternals) para obtener la ruta completa de la DLL
for /f "tokens=*" %%i in ('listdlls -p %ProcessId% ^| findstr /i /c:"%DllName%"') do (
    set DllPath=%%i
)

if "%DllPath%"=="" (
    echo Error: No se pudo encontrar la DLL especificada en el proceso.
    exit /b 1
)

echo Exportaciones de la DLL %DllName% en el proceso %ProcessId%:
echo Ordinal  RVA      Nombre

REM Aquí no se puede analizar la tabla de exportaciones directamente con batch
REM Para hacer un análisis detallado, sería necesario usar otra herramienta o lenguaje
REM que permita leer archivos binarios como la tabla de exportaciones PE

echo Operación completada.
exit /b 0
```


### powershell with dbghelp.dll
```powershell
# PowerShell script para obtener las exportaciones de una DLL cargada en un proceso mediante el uso de Debugging Tools

param (
    [Parameter(Mandatory=$true)]
    [int]$ProcessId,
    [Parameter(Mandatory=$true)]
    [string]$DllName
)

function Get-DllExportsFromProcess {
    param (
        [int]$ProcessId,
        [string]$DllName
    )

    try {
        # Obtener el proceso por ID
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        
        # Obtener la lista de módulos cargados en el proceso
        $module = $process.Modules | Where-Object { $_.ModuleName -ieq $DllName }
        
        if ($module -eq $null) {
            Write-Output "Error: No se pudo encontrar la DLL especificada en el proceso."
            return
        }

        $dllPath = $module.FileName
        Write-Output "Exportaciones de la DLL $DllName en el proceso $ProcessId:"
        Write-Output "Ordinal  RVA      Nombre"

        # Utilizar dbghelp.dll para cargar el módulo y obtener las exportaciones
        [System.Reflection.Assembly]::LoadWithPartialName("System.Runtime.InteropServices") | Out-Null

        $Dbghelp = "C:\Windows\System32\dbghelp.dll"
        $LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
            [System.Runtime.InteropServices.Marshal]::GetProcAddress(
                [System.Runtime.InteropServices.Marshal]::LoadLibrary($Dbghelp), "ImagehlpApiVersionEx"),
            [Func[[IntPtr]]])

        # Aquí podríamos usar funciones de Debugging Tools para cargar y analizar el módulo
        # Esto incluiría obtener la tabla de exportación de la DLL

        Write-Output "Nota: Este método requiere acceso a dbghelp.dll y otros componentes de depuración."
    } catch {
        Write-Output "Error: $_.Exception.Message"
    }
}

Get-DllExportsFromProcess -ProcessId $ProcessId -DllName $DllName
```



```powershell
# PowerShell script para obtener las exportaciones de una DLL cargada en un proceso usando PInvoke y WinAPI

param (
    [Parameter(Mandatory=$true)]
    [int]$ProcessId,
    [Parameter(Mandatory=$true)]
    [string]$DllName
)

function Get-DllExportsFromProcess {
    param (
        [int]$ProcessId,
        [string]$DllName
    )

    try {
        # Obtener el proceso por ID
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        
        # Obtener la lista de módulos cargados en el proceso
        $module = $process.Modules | Where-Object { $_.ModuleName -ieq $DllName }
        
        if ($module -eq $null) {
            Write-Output "Error: No se pudo encontrar la DLL especificada en el proceso."
            return
        }

        $dllPath = $module.FileName
        Write-Output "Exportaciones de la DLL $DllName en el proceso $ProcessId:"
        Write-Output "Ordinal  RVA      Nombre"

        # Utilizar LoadLibrary y GetProcAddress para analizar la DLL directamente
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class WinAPI {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr LoadLibrary(string lpFileName);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool FreeLibrary(IntPtr hModule);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        }
"@

        $hModule = [WinAPI]::LoadLibrary($dllPath)
        if ($hModule -eq [IntPtr]::Zero) {
            Write-Output "Error: No se pudo cargar la DLL $DllName."
            return
        }

        # Aquí se debería analizar la tabla de exportaciones
        # Este ejemplo se enfoca en mostrar cómo cargar la DLL y obtener la dirección de funciones específicas
        # Para un análisis completo, se necesitaría parsear la estructura PE manualmente

        # Liberar la DLL
        [WinAPI]::FreeLibrary($hModule)
    } catch {
        Write-Output "Error: $_.Exception.Message"
    }
}

Get-DllExportsFromProcess -ProcessId $ProcessId -DllName $DllName
```

### dbghelp.dll arround api

```powershell
# PowerShell script para obtener las exportaciones de una DLL cargada en un proceso usando el sistema de depuración de Windows

param (
    [Parameter(Mandatory=$true)]
    [int]$ProcessId,
    [Parameter(Mandatory=$true)]
    [string]$DllName
)

function Get-DllExportsFromProcess {
    param (
        [int]$ProcessId,
        [string]$DllName
    )

    try {
        # Obtener el proceso por ID
        $process = Get-Process -Id $ProcessId -ErrorAction Stop
        
        # Obtener la lista de módulos cargados en el proceso
        $module = $process.Modules | Where-Object { $_.ModuleName -ieq $DllName }
        
        if ($module -eq $null) {
            Write-Output "Error: No se pudo encontrar la DLL especificada en el proceso."
            return
        }

        $dllPath = $module.FileName
        Write-Output "Exportaciones de la DLL $DllName en el proceso $ProcessId:"
        Write-Output "Ordinal  RVA      Nombre"

        # Utilizar Debugging API para inspeccionar el módulo cargado
        Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        public class DebugAPI {
            [DllImport("dbghelp.dll", SetLastError = true)]
            public static extern bool SymInitialize(IntPtr hProcess, string UserSearchPath, bool fInvadeProcess);

            [DllImport("dbghelp.dll", SetLastError = true)]
            public static extern bool SymCleanup(IntPtr hProcess);

            [DllImport("dbghelp.dll", SetLastError = true)]
            public static extern bool SymFromAddr(IntPtr hProcess, long Address, out long Displacement, IntPtr Symbol);
        }
"@

        $hProcess = [System.Diagnostics.Process]::GetProcessById($ProcessId).Handle
        
        # Inicializar el sistema de símbolos
        $symInitialized = [DebugAPI]::SymInitialize($hProcess, $null, $true)
        if (-not $symInitialized) {
            Write-Output "Error: No se pudo inicializar el sistema de símbolos."
            return
        }

        # Aquí se debería continuar con la inspección de las exportaciones usando SymFromAddr o SymEnumSymbols
        # Este ejemplo muestra cómo inicializar el sistema de símbolos para el proceso objetivo

        # Limpiar el sistema de símbolos
        [DebugAPI]::SymCleanup($hProcess)
    } catch {
        Write-Output "Error: $_.Exception.Message"
    }
}

Get-DllExportsFromProcess -ProcessId $ProcessI
```



```vb
' VBScript para interactuar con dbghelp.dll y exponer un sistema de llamada cómodo para sus funciones

Option Explicit

' Declaraciones para llamar a las funciones de dbghelp.dll mediante CreateObject y LoadLibrary
Const DBGHELP_DLL = "dbghelp.dll"

' Diccionario para almacenar punteros a funciones
Dim functions
Set functions = CreateObject("Scripting.Dictionary")

' Cargar la biblioteca dbghelp.dll
Dim kernel32, hModule
Set kernel32 = CreateObject("DynamicWrapperX")
kernel32.Register "kernel32.dll", "LoadLibrary", "i=s", "f=s"
hModule = kernel32.LoadLibrary(DBGHELP_DLL)

If hModule = 0 Then
    MsgBox "Error: No se pudo cargar " & DBGHELP_DLL
    WScript.Quit
End If

' Registrar las funciones de dbghelp.dll
kernel32.Register "kernel32.dll", "GetProcAddress", "i=li", "f=l"
RegisterDbgHelpFunction "SymInitialize", "i=lpl", "f=l"
RegisterDbgHelpFunction "SymCleanup", "i=l", "f=l"
RegisterDbgHelpFunction "SymFromAddr", "i=lll", "f=l"
RegisterDbgHelpFunction "SymEnumSymbols", "i=lssll", "f=l"
RegisterDbgHelpFunction "SymGetModuleInfo", "i=ll", "f=l"
RegisterDbgHelpFunction "SymLoadModuleEx", "i=llllss", "f=l"
RegisterDbgHelpFunction "SymUnloadModule64", "i=ll", "f=l"
RegisterDbgHelpFunction "SymGetLineFromAddr64", "i=lllll", "f=l"
RegisterDbgHelpFunction "SymGetOptions", "i=", "f=l"
RegisterDbgHelpFunction "SymSetOptions", "i=l", "f=l"
RegisterDbgHelpFunction "SymGetSearchPath", "i=lp", "f=l"
RegisterDbgHelpFunction "SymSetSearchPath", "i=lp", "f=l"

' Función para registrar funciones de dbghelp.dll en el diccionario
Sub RegisterDbgHelpFunction(funcName, params, returnType)
    Dim address
    address = kernel32.GetProcAddress(hModule, funcName)
    If address = 0 Then
        MsgBox "Error: No se pudo registrar la función " & funcName
        WScript.Quit
    End If
    functions.Add funcName, address
    kernel32.Register DBGHELP_DLL, funcName, params, returnType
End Sub

' Llamar a una función de dbghelp.dll de forma sencilla
Function CallDbgHelpFunction(funcName, args)
    If Not functions.Exists(funcName) Then
        MsgBox "Error: La función " & funcName & " no está registrada."
        CallDbgHelpFunction = Null
        Exit Function
    End If
    CallDbgHelpFunction = kernel32.CallByAddress(functions(funcName), args)
End Function

' Ejemplo de uso
Dim result
result = CallDbgHelpFunction("SymGetOptions", Array())
MsgBox "Resultado de SymGetOptions: " & result

' Limpiar
Call CallDbgHelpFunction("SymCleanup", Array(hModule))
Set kernel32 = Nothing
Set functions = Nothing
```



```vb
' VBScript para interactuar con dbghelp.dll y exponer un sistema de llamada cómodo para sus funciones

Option Explicit

' Declaraciones para llamar a las funciones de dbghelp.dll mediante CreateObject y LoadLibrary
Const DBGHELP_DLL = "dbghelp.dll"

' Diccionario para almacenar punteros a funciones
Dim functions
Set functions = CreateObject("Scripting.Dictionary")

' Cargar la biblioteca dbghelp.dll
Dim kernel32, hModule
Set kernel32 = CreateObject("DynamicWrapperX")
kernel32.Register "kernel32.dll", "LoadLibrary", "i=s", "f=s"
hModule = kernel32.LoadLibrary(DBGHELP_DLL)

If hModule = 0 Then
    MsgBox "Error: No se pudo cargar " & DBGHELP_DLL
    WScript.Quit
End If

' Registrar las funciones de dbghelp.dll
kernel32.Register "kernel32.dll", "GetProcAddress", "i=li", "f=l"
RegisterDbgHelpFunction "SymInitialize", "i=lpl", "f=l"
RegisterDbgHelpFunction "SymCleanup", "i=l", "f=l"
RegisterDbgHelpFunction "SymFromAddr", "i=lll", "f=l"
RegisterDbgHelpFunction "SymEnumSymbols", "i=lssll", "f=l"
RegisterDbgHelpFunction "SymGetModuleInfo", "i=ll", "f=l"
RegisterDbgHelpFunction "SymLoadModuleEx", "i=llllss", "f=l"
RegisterDbgHelpFunction "SymUnloadModule64", "i=ll", "f=l"
RegisterDbgHelpFunction "SymGetLineFromAddr64", "i=lllll", "f=l"
RegisterDbgHelpFunction "SymGetOptions", "i=", "f=l"
RegisterDbgHelpFunction "SymSetOptions", "i=l", "f=l"
RegisterDbgHelpFunction "SymGetSearchPath", "i=lp", "f=l"
RegisterDbgHelpFunction "SymSetSearchPath", "i=lp", "f=l"

' Función para registrar funciones de dbghelp.dll en el diccionario
Sub RegisterDbgHelpFunction(funcName, params, returnType)
    Dim address
    address = kernel32.GetProcAddress(hModule, funcName)
    If address = 0 Then
        MsgBox "Error: No se pudo registrar la función " & funcName
        WScript.Quit
    End If
    functions.Add funcName, address
    kernel32.Register DBGHELP_DLL, funcName, params, returnType
End Sub

' Llamar a una función de dbghelp.dll de forma sencilla
Function CallDbgHelpFunction(funcName, args)
    If Not functions.Exists(funcName) Then
        MsgBox "Error: La función " & funcName & " no está registrada."
        CallDbgHelpFunction = Null
        Exit Function
    End If
    CallDbgHelpFunction = kernel32.CallByAddress(functions(funcName), args)
End Function

' Ejemplo de uso
Dim result
result = CallDbgHelpFunction("SymGetOptions", Array())
MsgBox "Resultado de SymGetOptions: " & result

' Limpiar
Call CallDbgHelpFunction("SymCleanup", Array(hModule))
Set kernel32 = Nothing
Set functions = Nothing
```



```vb
' VBScript para interactuar con dbghelp.dll y exponer un sistema de llamada cómodo para sus funciones

Option Explicit

' Declaraciones para llamar a las funciones de dbghelp.dll mediante CreateObject y LoadLibrary
Const DBGHELP_DLL = "dbghelp.dll"

' Diccionario para almacenar punteros a funciones
Dim functions
Set functions = CreateObject("Scripting.Dictionary")

' Cargar la biblioteca dbghelp.dll
Dim kernel32, hModule
Set kernel32 = CreateObject("DynamicWrapperX")
kernel32.Register "kernel32.dll", "LoadLibrary", "i=s", "f=s"
hModule = kernel32.LoadLibrary(DBGHELP_DLL)

If hModule = 0 Then
    MsgBox "Error: No se pudo cargar " & DBGHELP_DLL
    WScript.Quit
End If

' Registrar las funciones de dbghelp.dll
kernel32.Register "kernel32.dll", "GetProcAddress", "i=li", "f=l"
RegisterDbgHelpFunction "SymInitialize", "i=lpl", "f=l"
RegisterDbgHelpFunction "SymCleanup", "i=l", "f=l"
RegisterDbgHelpFunction "SymFromAddr", "i=lll", "f=l"
RegisterDbgHelpFunction "SymEnumSymbols", "i=lssll", "f=l"
RegisterDbgHelpFunction "SymGetModuleInfo", "i=ll", "f=l"
RegisterDbgHelpFunction "SymLoadModuleEx", "i=llllss", "f=l"
RegisterDbgHelpFunction "SymUnloadModule64", "i=ll", "f=l"
RegisterDbgHelpFunction "SymGetLineFromAddr64", "i=lllll", "f=l"
RegisterDbgHelpFunction "SymGetOptions", "i=", "f=l"
RegisterDbgHelpFunction "SymSetOptions", "i=l", "f=l"
RegisterDbgHelpFunction "SymGetSearchPath", "i=lp", "f=l"
RegisterDbgHelpFunction "SymSetSearchPath", "i=lp", "f=l"

' Función para registrar funciones de dbghelp.dll en el diccionario
Sub RegisterDbgHelpFunction(funcName, params, returnType)
    Dim address
    address = kernel32.GetProcAddress(hModule, funcName)
    If address = 0 Then
        MsgBox "Error: No se pudo registrar la función " & funcName
        WScript.Quit
    End If
    functions.Add funcName, address
    kernel32.Register DBGHELP_DLL, funcName, params, returnType
End Sub

' Llamar a una función de dbghelp.dll de forma sencilla
Function CallDbgHelpFunction(funcName, args)
    If Not functions.Exists(funcName) Then
        MsgBox "Error: La función " & funcName & " no está registrada."
        CallDbgHelpFunction = Null
        Exit Function
    End If
    CallDbgHelpFunction = kernel32.CallByAddress(functions(funcName), args)
End Function

' Ejemplo de uso
Dim result
result = CallDbgHelpFunction("SymGetOptions", Array())
MsgBox "Resultado de SymGetOptions: " & result

' Limpiar
Call CallDbgHelpFunction("SymCleanup", Array(hModule))
Set kernel32 = Nothing
Set functions = Nothing
```





```powershell
Option Explicit

' Función para ejecutar PowerShell y obtener el resultado
Function RunPowerShell(command)
    Dim shell, exec, line, result
    Set shell = CreateObject("WScript.Shell")
    
    Set exec = shell.Exec("powershell.exe -ExecutionPolicy Bypass -File DbgHelpProxy.ps1 " & command)
    
    result = ""
    Do While Not exec.StdOut.AtEndOfStream
        line = exec.StdOut.ReadLine()
        result = result & line
    Loop
    
    RunPowerShell = result
End Function

' Ejemplo de uso: Llamar a SymGetOptions
Dim options
options = RunPowerShell("SymGetOptions")
MsgBox "Resultado de SymGetOptions: " & options
```

```vb
Option Explicit

' Función para ejecutar PowerShell y obtener el resultado
Function RunPowerShell(command)
    Dim shell, exec, line, result
    Set shell = CreateObject("WScript.Shell")
    
    Set exec = shell.Exec("powershell.exe -ExecutionPolicy Bypass -File DbgHelpProxy.ps1 " & command)
    
    result = ""
    Do While Not exec.StdOut.AtEndOfStream
        line = exec.StdOut.ReadLine()
        result = result & line
    Loop
    
    RunPowerShell = result
End Function

' Ejemplo de uso: Llamar a SymGetOptions
Dim options
options = RunPowerShell("SymGetOptions")
MsgBox "Resultado de SymGetOptions: " & options
```


