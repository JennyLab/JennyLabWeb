---
layout: post
title: "Mi Primer Post"
date: 2024-11-29
categories: redteam
---

# Lenguaje Script f0r VXers
## 1. VBA
### 1.1. Uso de VBA cómo lenguaje script para documentos
Vamos hacer una instrumentación común cómo la que se haría en un documento Word
Para hacer esto en VBA, puedes recorrer el contenido del documento de Word, buscando las cadenas {{ foto }} y {{ texto1 }}, y reemplazarlas por una imagen y un texto respectivamente. Aquí te dejo un ejemplo de cómo hacerlo.

### 1.2. Código de ejemplo
```vb
Sub InsertarContenido()
    Dim doc As Document
    Dim rango As Range
    Dim imagenPath As String
    Dim texto As String

    ' Asume que el documento ya está abierto
    Set doc = ActiveDocument

    ' Ruta de la imagen que quieres insertar
    imagenPath = "C:\Users\Public\\Documents\jennylogo.jpg"

    ' Texto a insertar
    texto = "JennyL4b Is Sexy!"

    ' Buscar y reemplazar {{ foto }} por la imagen
    Set rango = doc.Content
    With rango.Find
        .ClearFormatting
        .Text = "{{ foto }}"
        If .Execute Then
            ' Insertar la imagen en el lugar donde se encontró {{ foto }}
            rango.InlineShapes.AddPicture FileName:=imagenPath
        End If
    End With

    ' Buscar y reemplazar {{ texto1 }} por el texto deseado
    Set rango = doc.Content
    With rango.Find
        .ClearFormatting
        .Text = "{{ texto1 }}"
        If .Execute Then
            ' Reemplazar {{ texto1 }} por el texto
            rango.Text = texto
        End If
    End With
End Sub
```

#### 1.1.1. Explicación del código:
**Definición** | de variables:
**doc**  *se refiere al documento activo.*
**rango** es la parte del documento donde se busca y reemplaza el texto.
**imagenPath** contiene la ruta de la imagen que quieres insertar.
**texto** es el texto que reemplazará la cadena {{ texto1 }}.


#### 1.1.2. Búsqueda de {{ foto }}:
Utiliza el objeto Find para buscar la cadena {{ foto }}.
Cuando se encuentra, la imagen especificada en imagenPath se inserta en esa posición.
Búsqueda de {{ texto1 }}:

De forma similar, busca {{ texto1 }} y lo reemplaza con el texto especificado en la variable texto.

#### 1.1.3. Consideraciones:
Asegúrate de que el documento de Word esté abierto antes de ejecutar el código.
La ruta de la imagen debe ser válida y accesible desde el código VBA.
Este código asume que solo hay una aparición de {{ foto }} y {{ texto1 }}. Si hay varias, el código puede necesitar ajustes para iterar por todas las instancias.


### 1.2. Ejemplo básico para antender el Lenguaje
```vb
Declare Sub Sleep Lib "kernel32" (ByVal dwMilliseconds As Long)

Sub PausarEjecucion()
    MsgBox "La ejecución se pausará durante 5 segundos"
    Sleep 5000 ' Pausa la ejecución por 5000 milisegundos (5 segundos)
    MsgBox "La ejecución ha reanudado"
End Sub
```


### 1.3. Ejemplo de Código VBA para Llamar a `GetProcAddress` y `LoadLibrary`
Este ejemplo usa la función `GetProcAddress` para obtener la dirección de una función dentro de una DLL cargada. Usaremos la DLL `kernel32.dll` como ejemplo.


```vb
Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpFileName As String) As Long
Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As Long, ByVal lpProcName As String) As Long
Declare PtrSafe Function GetModuleHandle Lib "kernel32" Alias "GetModuleHandleA" (ByVal lpModuleName As String) As Long
Declare PtrSafe Function MessageBox Lib "user32.dll" Alias "MessageBoxA" (ByVal hwnd As Long, ByVal lpText As String, ByVal lpCaption As String, ByVal uType As Long) As LongSub CargarDLLyObtenerFuncion()
    Dim hModule As Long
    Dim pFunc As Long
    Dim resultado As Long    ' Cargar la DLL
    hModule = LoadLibrary("kernel32.dll")    If hModule = 0 Then
        MsgBox "Error al cargar la DLL."
        Exit Sub
    End If    ' Obtener la dirección de la función GetTickCount
    pFunc = GetProcAddress(hModule, "GetTickCount")    If pFunc = 0 Then
        MsgBox "Error al obtener la dirección de la función."
        Exit Sub
    End If    ' Llamar a la función GetTickCount (usando la dirección de la función)
    resultado = CallFunction(pFunc)    ' Mostrar el resultado (el número de milisegundos desde que el sistema arrancó)
    MsgBox "Resultado de GetTickCount: " & resultado
End SubFunction CallFunction(ByVal pFunc As Long) As Long
    ' Esta función usa la dirección de la función obtenida
    ' Llamada indirecta a la función GetTickCount
    ' Esto sería una simplificación; en un entorno real, se usarían mecanismos como "CallWindowProc" o APIs adicionales para invocar dinámicamente las funciones
    CallFunction = pFunc ' Simulación, solo para ilustrar el uso
End Function
```


### 1.4. Ejemplo de Código VBA para Llamar a `GetProcAddress` y `LoadLibrary`

Este ejemplo usa la función `GetProcAddress` para obtener la dirección de una función dentro de una DLL cargada. Usaremos la DLL `kernel32.dll` como ejemplo.

```vb
pFunc = GetProcAddress(hModule, "GetTickCount")
hModule = GetModuleHandle("kernel32.dll")
```


### 1.5. Lamadas a la GDI

```vb
Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpFileName As String) As Long
Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As Long, ByVal lpProcName As String) As Long
Declare PtrSafe Function CreatePen Lib "gdi32.dll" (ByVal fnPenStyle As Long, ByVal nWidth As Long, ByVal crColor As Long) As Long

Sub CrearLapis()
    Dim hModule As Long
    Dim pCreatePen As Long
    Dim hPen As Long
    
    ' Cargar la librería gdi32.dll
    hModule = LoadLibrary("gdi32.dll")
    
    ' Obtener la dirección de la función CreatePen
    pCreatePen = GetProcAddress(hModule, "CreatePen")
    
    If pCreatePen <> 0 Then
        ' Crear un lápiz (solo como ejemplo, no dibuja en VBA directamente)
        hPen = CreatePen(0, 2, RGB(255, 0, 0)) ' Estilo sólido, grosor 2, color rojo
        MsgBox "Lápiz creado con éxito: " & hPen
    Else
        MsgBox "No se pudo cargar la función CreatePen."
    End If
End Sub
```


### 1.6. Llamada a ntdll.dll
```vb
Declare PtrSafe Function LoadLibrary Lib "kernel32" Alias "LoadLibraryA" (ByVal lpFileName As String) As Long
Declare PtrSafe Function GetProcAddress Lib "kernel32" (ByVal hModule As Long, ByVal lpProcName As String) As Long
Declare PtrSafe Function NtQuerySystemInformation Lib "ntdll.dll" (ByVal SystemInformationClass As Long, ByVal SystemInformation As Long, ByVal SystemInformationLength As Long, ByRef ReturnLength As Long) As Long

Sub ConsultarInformacionDelSistema()
    Dim hModule As Long
    Dim pNtQuerySystemInformation As Long
    Dim result As Long
    Dim buffer As Long
    Dim length As Long
    
    ' Cargar la librería ntdll.dll
    hModule = LoadLibrary("ntdll.dll")
    
    ' Obtener la dirección de la función NtQuerySystemInformation
    pNtQuerySystemInformation = GetProcAddress(hModule, "NtQuerySystemInformation")
    
    If pNtQuerySystemInformation <> 0 Then
        ' Llamar a NtQuerySystemInformation para obtener información del sistema
        result = NtQuerySystemInformation(0, buffer, 0, length)
        
        ' Mostrar el resultado (sólo un ejemplo simple, puedes usar estructuras más complejas)
        MsgBox "Resultado de NtQuerySystemInformation: " & result
    Else
        MsgBox "No se pudo cargar la función NtQuerySystemInformation."
    End If
End Sub
```


### 1.7 Ejecutar JavaScript desde VBA
Para ejecutar JavaScript desde VBA, puedes utilizar el motor de JavaScript de Internet Explorer (en versiones más antiguas de Windows) a través de CreateObject("MSHTML.HTMLDocument"). Aquí tienes un ejemplo de cómo podrías ejecutar JavaScript en un objeto de navegador:

Esta técnica es más comúnmente usada cuando necesitas interactuar con un navegador web o manipular el DOM de una página.

```vb
Dim IE As Object
Set IE = CreateObject("InternetExplorer.Application")
IE.Visible = False
IE.Navigate "about:blank"

' Ejecuta JavaScript
IE.document.parentWindow.execScript "alert('Jenny ON... VBA!')", "JavaScript"
```


### 1.8. Ejecutar PowerShell desde VBA
Para ejecutar PowerShell desde VBA, puedes usar WScript.Shell para ejecutar un script de PowerShell. 
Este código ejecuta un comando de PowerShell directamente desde VBA.


### 1.9. Aquí tienes un ejemplo:

```vb
Dim objShell As Object
Set objShell = CreateObject("WScript.Shell")
objShell.Run "powershell -Command ""Write-Host 'JEnnyL4B Is Sexy say!.. fr0m PowerShell'"""
Set objShell = Nothing
```


### 1.10. Ejecutar Batch desde VBA
También puedes ejecutar scripts de Batch desde VBA de manera similar a cómo lo harías con PowerShell, utilizando (WScript.Shell).

* Aquí, el comando cmd.exe /C ejecuta un script de Batch (o simplemente un comando de consola)


```vb
Dim objShell As Object
Set objShell = CreateObject("WScript.Shell")
objShell.Run "cmd.exe /C echo Hello from Batch"
Set objShell = Nothing
```


### 1.11. Ejecutar VBScript desde VBA
VBA y VBScript son lenguajes muy similares, y puedes invocar directamente VBScript desde VBA utilizando CreateObject("WScript.Shell") para ejecutar un archivo .vbs o directamente el código VBScript


#### 1.11.1. Ejecutar VBScript desde VBA: Cargando .vbs
```vb
Dim objShell As Object
Set objShell = CreateObject("WScript.Shell")
objShell.Run "wscript.exe ""C:\WINDOWS\TEMP\script.vbs"""
Set objShell = Nothing
```

#### 1.11.2. Ejecutar VBScript desde VBA: Código embebido
```vb
Dim vbScript As String
vbScript = "Set objShell = CreateObject(""WScript.Shell"")" & vbCrLf & _
           "objShell.Popup ""JennyLab from VBScript!""" & vbCrLf & _
           "Set objShell = Nothing"
CreateObject("WScript.Shell").Run "wscript.exe """ & vbScript & """", 0, True
```


### 1.2. Inyección de código VBA en Documento Word abierto

```vb
Sub InyectarContenidoEnWord()
    Dim doc As Document
    Dim rango As Range
    Dim texto As String
    Dim imagenPath As String

    ' Asume que el documento ya está abierto
    Set doc = ActiveDocument

    ' Texto a insertar
    texto = "JennyLab Is Pwn3r"

    ' Ruta de la imagen que quieres insertar
    imagenPath = "C:\Users\JennyLab\SexyPics\imagen.jpg"

    ' Inyectar texto
    Set rango = doc.Content
    rango.Find.Text = "{{texto1}}"
    If rango.Find.Execute Then
        rango.Text = texto
    End If

    ' Inyectar imagen
    Set rango = doc.Content
    rango.Find.Text = "{{foto}}"
    If rango.Find.Execute Then
        rango.InlineShapes.AddPicture FileName:=imagenPath
    End If
End Sub
```




## 1.3. Resumen

**JavaScript:** Puedes usar el motor de Internet Explorer para ejecutar JavaScript en VBA.
**PowerShell:** Se ejecuta mediante WScript.Shell lanzando el comando powershell.
**Batch:** Similar a PowerShell, pero usando el comando cmd.exe.
**VBScript:** Puedes ejecutar archivos .vbs o incrustar código VBScript directamente en VBA.

Estos métodos permiten la ejecución de scripts o comandos de otros lenguajes desde VBA, lo cual puede ser útil para integraciones o tareas más complejas que necesiten un lenguaje adicional.






# 2. VBS / VBScript / Visual Basic Script
Si quieres VBScript para interactuar con un documento de Word, puedes crear un objeto de Word y modificar el contenido de la misma manera.

En este apartado se analizará cómo iniciar en este lenguaje con fines de RedTeam y Pentesting. Y también algunos conceptos interesantes de este lenguaje.


## 2.8. Inyectando texto e imagen en un documento abierto

```vb
Sub InyectarContenidoEnWord()
    Dim doc As Document
    Dim rango As Range
    Dim texto As String
    Dim imagenPath As String

    ' Asume que el documento ya está abierto
    Set doc = ActiveDocument

    ' Texto a insertar
    texto = "Este es el texto que quiero inyectar en el documento."

    ' Ruta de la imagen que quieres insertar
    imagenPath = "C:\ruta\a\tu\imagen.jpg"

    ' Inyectar texto
    Set rango = doc.Content
    rango.Find.Text = "{{texto1}}"
    If rango.Find.Execute Then
        rango.Text = texto
    End If

    ' Inyectar imagen
    Set rango = doc.Content
    rango.Find.Text = "{{foto}}"
    If rango.Find.Execute Then
        rango.InlineShapes.AddPicture FileName:=imagenPath
    End If
End Sub

```

### 2.8.1. Explicación del código:
CreateObject("Word.Application"): Crea una instancia de la aplicación Word en el entorno de VBScript.
Abrir el documento: El documento de Word se abre con Documents.Open.
Buscar y reemplazar: Similar al ejemplo de VBA, se usa el objeto Find para buscar marcas específicas en el documento y luego insertar texto o imágenes.

### 2.8.2. Consideraciones:
Ambos métodos requieren que el archivo de Word esté abierto previamente o se abra desde el script.
El uso de VBScript o VBA depende de tus preferencias, pero VBA es generalmente más potente ya que ofrece una integración más fluida con las aplicaciones de Microsoft.
En el caso de VBScript, si deseas modificar documentos de forma automatizada en una máquina sin interacción del usuario, necesitarás asegurarte de que Word esté instalado y configurado correctamente en el equipo.
Si lo que deseas es inyectar contenido de manera externa en un documento sin abrirlo (por ejemplo, desde otro archivo o aplicación), esto también sería posible, pero dependería de las bibliotecas de interop o las interfaces COM para interactuar con el documento sin que esté abierto en Word.

Este tipo de integración es bastante útil cuando trabajas con plantillas o procesos automatizados donde las partes del documento pueden cambiar dinámicamente, como en informes o generadores de documentos personalizados.


