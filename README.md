# 🛡️ Detección de técnicas de explotación PowerShell en Windows usando Wazuh

¡En este repositorio aprenderás a detectar ataques con PowerShell en sistemas Windows utilizando Wazuh! Esta configuración está pensada para **analistas SOC, defensores Blue Team y entusiastas de la ciberseguridad**.

---

## ⚙️ 1. Habilitar el registro de PowerShell en Windows

Ejecuta esta función en PowerShell como administrador para activar el logging de comandos:

```powershell
function Enable-PSLogging {
    $scriptBlockPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
    $moduleLoggingPath = 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ModuleLogging'

    if (-not (Test-Path $scriptBlockPath)) {
        $null = New-Item $scriptBlockPath -Force
    }
    Set-ItemProperty -Path $scriptBlockPath -Name EnableScriptBlockLogging -Value 1

    if (-not (Test-Path $moduleLoggingPath)) {
        $null = New-Item $moduleLoggingPath -Force
    }
    Set-ItemProperty -Path $moduleLoggingPath -Name EnableModuleLogging -Value 1

    $moduleNames = @('*')
    New-ItemProperty -Path $moduleLoggingPath -Name ModuleNames -PropertyType MultiString -Value $moduleNames -Force

    Write-Output "Script Block Logging and Module Logging have been enabled."
}

Enable-PSLogging
```

---

## 📄 2. Configuración del agente de Wazuh

Agrega el siguiente bloque en el archivo `ossec.conf` del agente:

```xml
<localfile>
  <location>Microsoft-Windows-PowerShell/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Esto permite a Wazuh leer eventos del registro de PowerShell.

---

## 🔍 3. Reglas de detección para `local_rules.xml`

Agrega este bloque dentro del archivo `local_rules.xml` para detectar posibles técnicas ofensivas comunes en PowerShell:

```xml
<group name="windows,powershell,">

  <rule id="100201" level="8">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.payload" type="pcre2">(?i)CommandInvocation</field>
    <field name="win.system.message" type="pcre2">(?i)EncodedCommand|FromBase64String|EncodedArguments|-e\b|-enco\b|-en\b</field>
    <description>Encoded command executed via PowerShell.</description>
    <mitre>
      <id>T1059.001</id>
      <id>T1562.001</id>
    </mitre>
  </rule>

  <rule id="100202" level="4">
    <if_sid>60009</if_sid>
    <field name="win.system.message" type="pcre2">(?i)blocked by your antivirus software</field>
    <description>Windows Security blocked malicious command executed via PowerShell.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <rule id="100203" level="10">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.payload" type="pcre2">(?i)CommandInvocation</field>
    <field name="win.system.message" type="pcre2">(?i)(Add-Persistence|Invoke-Mimikatz|Invoke-Shellcode|...)</field>
    <description>Risky CMDLet executed. Possible malicious activity detected.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <rule id="100204" level="8">
    <if_sid>91802</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)mshta.*GetObject|mshta.*new ActiveXObject</field>
    <description>Mshta used to download a file. Possible malicious activity detected.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <rule id="100205" level="5">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.contextInfo" type="pcre2">(?i)ExecutionPolicy bypass|exec bypass</field>
    <description>PowerShell execution policy set to bypass.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

  <rule id="100206" level="5">
    <if_sid>60009</if_sid>
    <field name="win.eventdata.contextInfo" type="pcre2">(?i)Invoke-WebRequest|IWR.*-url|IWR.*-InFile</field>
    <description>Invoke Webrequest executed, possible download cradle detected.</description>
    <mitre>
      <id>T1059.001</id>
    </mitre>
  </rule>

</group>
```

---

## 🎯 Referencias MITRE ATT&CK

Estas reglas están relacionadas principalmente con la técnica:

- [T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)

---

## 🧠 Créditos y contribución

Creado por [TuNombre] | Si encuentras mejoras o deseas aportar nuevas reglas, ¡los PR son bienvenidos!  
¿Te fue útil? 🌟 ¡Dale una estrella al repositorio!