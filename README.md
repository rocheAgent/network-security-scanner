# 🛡️ Network Security Scanner

Escáner de seguridad de red con interfaz web. Detecta puertos abiertos, estado del firewall, conexiones activas e interfaces de red.

## Instalación

```bash
cd portscan
pip install -r requirements.txt
```

## Uso

```bash
python app.py
```

Luego abre: **http://localhost:5000**

## Características

- 🔌 **Escaneo de 26 puertos comunes** con clasificación de riesgo (crítico/alto/medio/bajo)
- 🔥 **Estado del firewall** (UFW, iptables, pf, Windows Defender)
- 🌐 **Conexiones TCP activas** con proceso y PID
- 🖧 **Interfaces de red** con IPs y estado
- 💻 **Info del sistema** (hostname, OS, RAM, CPU)
- 📥 **Exportar resultado a JSON**
- ⚡ **Re-escaneo con un clic**

## Seguridad

> Este escáner es para uso en tu **propio sistema o redes que administras**. Escanear sistemas ajenos sin permiso es ilegal.

## Estructura

```
portscan/
├── app.py          # Flask server + API
├── scanner.py      # Lógica de escaneo
├── templates/
│   └── index.html  # Interfaz web
└── requirements.txt
```
