# Masterclass: automatiza tu primera alerta de Wazuh a Telegram con n8n

Material de la transmisión en vivo del **13 de noviembre de 2026**. Una alerta de fuerza bruta SSH detectada por **Wazuh** llega a **n8n**, se filtra y se entrega en **Telegram**, sin escribir código en Python.

- Grabación: [ENLACE A LA GRABACIÓN]
- Bootcamp SOC Automation & Engineering: [ENLACE DEL CURSO]

## Qué incluye

```
masterclass-2026-11-13-wazuh-n8n-telegram/
├── README.md
├── docker/
│   ├── docker-compose.yml
│   └── .env.example
├── wazuh/
│   └── integracion-n8n.xml
├── n8n/
│   ├── 01-nivel1-alerta-telegram.json
│   └── 02-nivel2-enriquecimiento-botones.json
└── pruebas/
    ├── alerta-ejemplo.json
    └── enviar-alerta.sh
```

| Flujo | Qué hace |
| --- | --- |
| `01-nivel1-alerta-telegram.json` | Webhook → filtro (nivel 10 o mayor) → extracción de campos → mensaje en Telegram. |
| `02-nivel2-enriquecimiento-botones.json` | Agrega la reputación de la IP (AbuseIPDB o VirusTotal) y botones **Bloquear IP** y **Falso positivo**. Es el nivel avanzado; lee las notas dentro del flujo. |

## Requisitos

- Docker y Docker Compose.
- Wazuh funcionando (manager y dashboard) con al menos un agente Linux. Sigue la [documentación oficial de Wazuh](https://documentation.wazuh.com) si aún no lo tienes.
- Una cuenta de Telegram.
- Para el nivel 2: una clave gratuita de [AbuseIPDB](https://www.abuseipdb.com) o [VirusTotal](https://www.virustotal.com). Los planes gratuitos tienen límite de consultas.

## Paso a paso

### 1. Descarga el material

Si no usas Git: **Code → Download ZIP** y descomprime.

### 2. Levanta n8n

```bash
cd docker
cp .env.example .env        # edita los valores del archivo .env
docker compose up -d
```

Abre `http://localhost:5678` y crea tu usuario. Comprueba que el contenedor de n8n y tu Wazuh se pueden alcanzar por red (misma red de Docker o una IP accesible).

### 3. Crea tu bot de Telegram

1. En Telegram habla con **@BotFather** y envía `/newbot`. Guarda el **token**.
2. Escríbele cualquier mensaje a tu bot (o agrégalo a un grupo de pruebas).
3. Abre en el navegador `https://api.telegram.org/bot<TU_TOKEN>/getUpdates` y copia el valor de `chat.id`.


### 4. Importa los flujos en n8n

1. En n8n, **Workflows → Import from file**.
2. Elige `n8n/01-nivel1-alerta-telegram.json`.
3. Crea la credencial de **Telegram** con tu token y selecciónala en el nodo.
4. Escribe tu **chat ID** en el nodo de Telegram.
5. Haz lo mismo con el nivel 2 cuando el nivel 1 funcione.

### 5. Conecta Wazuh con n8n

Copia la **URL de producción** de tu nodo Webhook y agrega este bloque en `/var/ossec/etc/ossec.conf` del manager (también en `wazuh/integracion-n8n.xml`):

```xml
<integration>
  <name>n8n</name>
  <hook_url>URL_DE_PRODUCCION_DE_TU_WEBHOOK</hook_url>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

Reinicia el manager:

```bash
sudo systemctl restart wazuh-manager
```

Esta integración envía el JSON de la alerta a cualquier URL, así que funciona con el webhook de n8n. Si no funciona en tu versión, revisa la documentación de integraciones personalizadas de Wazuh.

### 6. Activa el flujo

En n8n, activa el flujo (interruptor **Active**). Mientras construyes puedes usar la URL de prueba, pero esa solo escucha cuando pulsas *Listen for test event*.

## Cómo probarlo

**Sin Wazuh**, enviando una alerta de ejemplo directo al webhook:

```bash
curl -X POST -H "Content-Type: application/json" \
  -d @pruebas/alerta-ejemplo.json \
  URL_DE_TU_WEBHOOK
```

**Con Wazuh**, desde otra VM de tu laboratorio, genera intentos fallidos de SSH con un usuario inexistente (8 a 10 en menos de dos minutos):

```bash
for i in $(seq 1 10); do
  ssh -o BatchMode=yes -o ConnectTimeout=5 usuario_falso@IP_DEL_AGENTE
done
```

Wazuh puede tardar unos segundos en alertar. El ID de la regla de fuerza bruta (por ejemplo `5712` o `5763`) puede variar según tu versión; confírmalo en el dashboard.

## Problemas comunes

| Síntoma | Qué revisar |
| --- | --- |
| No llega nada a n8n | URL de prueba contra URL de producción, flujo activo, y que Wazuh alcance a n8n por red. |
| El flujo recibe la alerta pero no hay mensaje | Token del bot, chat ID y que le hayas escrito primero al bot. |
| La alerta no se dispara | Que el intento fallido se registre en el agente y que el nivel sea 10 o mayor. |
| Error de la API de reputación | Límite del plan gratuito o clave mal copiada. |
| Los botones no aparecen | Tu versión de n8n debe incluir la operación *Send and Wait for Response* en Telegram. |

## Aviso

Material educativo y defensivo. Úsalo solo en laboratorios propios o con autorización. La rama de **bloqueo automático** puede cortar conexiones legítimas: pruébala en un entorno aislado antes de usarla en producción.

## Licencia

MIT. Consulta `LICENSE` en la raíz del repositorio.
