# 🛡️ Network Security Scanner

Escáner de seguridad de red con interfaz web. Detecta puertos abiertos, estado del firewall, conexiones activas e interfaces de red.

**Sin dependencias externas** — Solo usa librería estándar de Python 3.

## Instalación

No requiere instalación de dependencias:

```bash
# Solo asegúrate de tener Python 3 instalado
python3 --version
```

## Uso

### Opción 1: Sin privilegios (información limitada)
```bash
python3 app.py
```

### Opción 2: Con permisos root (acceso completo)
```bash
sudo python3 app.py
```

Luego abre en tu navegador: **http://localhost:5000**

> **Nota**: Algunos datos (firewall, conexiones con proceso) requieren permisos de administrador. Si ves datos limitados, intenta con `sudo`.

## Características

- 🔌 **Escaneo de 26 puertos comunes** con clasificación de riesgo (crítico/alto/medio/bajo)
- 🔥 **Estado del firewall** (UFW, iptables, nftables, pf, Windows Defender)
- 🌐 **Conexiones TCP activas** (necesita permisos root para ver procesos)
- 🖧 **Interfaces de red** con IPs y estado
- 💻 **Info del sistema** (hostname, OS, RAM, CPU)
- 📱 **Descubrimiento de dispositivos** en red local (ARP + ping sweep opcional)
- 📥 **Exportar resultado a JSON**
- ⚡ **Re-escaneo en tiempo real**

## Seguridad & Legalidad

> ⚠️ Este escáner es **SOLO para uso en tu propio sistema o redes que administras**.
>
> **Escanear sistemas ajenos sin permiso explícito es ilegal** y puede resultar en consecuencias legales graves.
>
> Úsalo responsablemente en entornos autorizados (pentesting con contrato, educación, pruebas en tu infraestructura).

## Estructura

```
.
├── app.py              # Servidor HTTP + API endpoints
├── scanner.py          # Lógica de escaneo (sin dependencias)
├── templates/
│   └── index.html      # Interfaz web (HTML/CSS/JS)
├── requirements.txt    # (vacío - no hay dependencias)
└── README.md
```

## API Endpoints

- `POST /api/scan` — Escanea un objetivo (IP)
  - Body: `{"target": "127.0.0.1"}`
- `POST /api/devices` — Descubre dispositivos en red local
  - Body: `{"sweep": false}` (si sweep=true hace ping sweep completo)

## Ejemplo de uso

1. Inicia el servidor:
   ```bash
   python3 app.py
   ```

2. Abre http://localhost:5000 en tu navegador

3. La interfaz hará un escaneo automático al cargar

4. O escanea un objetivo específico ingresando una IP

5. Exporta los resultados a JSON con el botón "📥 Exportar JSON"
