"""
discord_bot.py — Network Security Scanner Bot para Discord
Requiere: pip install discord.py python-dotenv

Setup:
  1. Crear bot en https://discord.com/developers/applications
  2. Copiar el token
  3. Crear archivo .env con:  DISCORD_TOKEN=tu_token_aqui
  4. Ejecutar: python3 discord_bot.py

Comandos disponibles:
  !scan [ip]    — Escaneo completo de seguridad (default: 127.0.0.1)
  !ports [ip]   — Solo escaneo de puertos
  !devices      — Descubrir dispositivos en la red (ping sweep)
  !firewall     — Estado del firewall
  !sysinfo      — Información del sistema
  !conns        — Conexiones activas
  !help_scan    — Mostrar ayuda
"""

import os
import discord
from discord.ext import commands
from dotenv import load_dotenv
from scanner import full_scan, get_connected_devices, scan_ports, get_firewall_status, get_system_info, get_active_connections
import ipaddress
import re

load_dotenv()

# ─── Config ──────────────────────────────────────────────────────────────────
TOKEN = os.getenv("DISCORD_TOKEN")
PREFIX = os.getenv("BOT_PREFIX", "!")

# IDs de usuarios autorizados (opcional — dejar vacío para permitir a todos)
# Ejemplo: ALLOWED_USERS = {123456789, 987654321}
ALLOWED_USERS_RAW = os.getenv("ALLOWED_USERS", "")
ALLOWED_USERS = set(
    int(uid.strip()) for uid in ALLOWED_USERS_RAW.split(",") if uid.strip().isdigit()
)

# ─── Colores para embeds ──────────────────────────────────────────────────────
COLOR_OK      = 0x3fb950   # verde
COLOR_WARN    = 0xd29922   # amarillo
COLOR_DANGER  = 0xf85149   # rojo
COLOR_INFO    = 0x58a6ff   # azul
COLOR_NEUTRAL = 0x30363d   # gris

RISK_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "none":     "⚪",
}

# ─── Intents & bot ───────────────────────────────────────────────────────────
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)


# ─── Helpers ─────────────────────────────────────────────────────────────────
def is_authorized(source) -> bool:
    """Verifica si el usuario tiene permiso. Acepta Context o Message."""
    if not ALLOWED_USERS:
        return True
    author = getattr(source, "author", source)
    return author.id in ALLOWED_USERS


def validate_target(target: str) -> str | None:
    """
    Valida que el target sea una IP válida o un hostname seguro.
    Retorna el target limpio o None si es inválido.
    """
    target = target.strip()
    # Intentar como IP
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        pass
    # Validar como hostname (solo alfanumérico, guiones, puntos)
    if re.fullmatch(r"[a-zA-Z0-9.\-]{1,253}", target):
        return target
    return None


def risk_color(critical: int, high: int) -> int:
    if critical > 0:
        return COLOR_DANGER
    if high > 0:
        return COLOR_WARN
    return COLOR_OK


def chunk_list(lst: list, size: int) -> list:
    """Divide una lista en chunks de tamaño máximo `size`."""
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def build_ports_text(ports: list) -> list[str]:
    """
    Construye bloques de texto para los puertos.
    Retorna una lista de strings (cada uno cabe en un campo de embed).
    """
    open_ports  = [p for p in ports if p["open"]]
    closed_ports = [p for p in ports if not p["open"]]

    lines = []
    if open_ports:
        lines.append("**── Puertos Abiertos ──**")
        for p in open_ports:
            emoji = RISK_EMOJI.get(p["risk"], "⚪")
            lines.append(f"{emoji} `{p['port']:5}` {p['service']:<18} `{p['risk'].upper()}`")

    if closed_ports:
        lines.append(f"\n⚫ {len(closed_ports)} puertos cerrados")

    # Dividir en bloques de max ~900 chars para respetar límite de Discord
    blocks = []
    current = ""
    for line in lines:
        if len(current) + len(line) + 1 > 900:
            blocks.append(current)
            current = line
        else:
            current += ("\n" + line if current else line)
    if current:
        blocks.append(current)

    return blocks or ["No se encontraron puertos"]


# ─── Comandos ─────────────────────────────────────────────────────────────────

@bot.event
async def on_ready():
    print(f"  ✅ Bot conectado como {bot.user} (id: {bot.user.id})")
    print(f"  Prefijo: {PREFIX}")
    await bot.change_presence(
        activity=discord.Activity(
            type=discord.ActivityType.watching,
            name="tu red 🛡️"
        )
    )


@bot.command(name="help_scan")
async def help_scan(ctx: commands.Context):
    """Muestra la ayuda del bot."""
    embed = discord.Embed(
        title="🛡️ Network Security Scanner — Ayuda",
        color=COLOR_INFO,
    )
    cmds = [
        (f"`{PREFIX}scan [ip]`",    "Escaneo completo: puertos, firewall, interfaces, dispositivos y conexiones"),
        (f"`{PREFIX}ports [ip]`",   "Solo escaneo de puertos (default: 127.0.0.1)"),
        (f"`{PREFIX}devices`",      "Descubrir dispositivos en la red local (ping sweep ~30s)"),
        (f"`{PREFIX}firewall`",     "Estado del firewall del sistema"),
        (f"`{PREFIX}sysinfo`",      "Información del sistema (OS, CPU, RAM)"),
        (f"`{PREFIX}conns`",        "Conexiones TCP activas"),
        (f"`{PREFIX}help_scan`",    "Mostrar este mensaje"),
    ]
    for name, desc in cmds:
        embed.add_field(name=name, value=desc, inline=False)
    embed.set_footer(text="Usa solo en redes que tienes autorización para escanear.")
    await ctx.send(embed=embed)


@bot.command(name="scan")
async def cmd_scan(ctx: commands.Context, target: str = "127.0.0.1"):
    """Escaneo completo de seguridad."""
    if not is_authorized(ctx):
        await ctx.send("❌ No tienes permiso para usar este comando.")
        return

    clean = validate_target(target)
    if not clean:
        await ctx.send(f"❌ Target inválido: `{target}`. Usa una IP o hostname válido.")
        return

    msg = await ctx.send(f"🔍 Escaneando `{clean}`… esto puede tomar unos segundos.")

    try:
        data = full_scan(clean)
    except Exception as e:
        await msg.edit(content=f"❌ Error durante el escaneo: `{e}`")
        return

    s = data["summary"]
    fw = data["firewall"]

    # ── Embed principal ──
    color = risk_color(s["critical"], s["high"])
    embed = discord.Embed(
        title=f"🛡️ Resultado del Escaneo — `{clean}`",
        color=color,
        timestamp=discord.utils.utcnow(),
    )
    embed.add_field(
        name="📊 Resumen",
        value=(
            f"🔌 Puertos abiertos: **{s['open_ports']}**\n"
            f"🔴 Críticos: **{s['critical']}**\n"
            f"🟠 Alto riesgo: **{s['high']}**\n"
            f"🟡 Medio: **{s['medium']}**\n"
            f"🔵 Bajo: **{s['low']}**\n"
            f"📱 Dispositivos: **{s['devices']}**\n"
            f"🌐 Conexiones: **{len(data['connections'])}**"
        ),
        inline=True,
    )
    embed.add_field(
        name="🔥 Firewall",
        value=(
            f"{'🔒 ACTIVO' if fw['active'] else '🔓 INACTIVO'}\n"
            f"{fw['name']}"
        ),
        inline=True,
    )
    sys = data["system"]
    embed.add_field(
        name="💻 Sistema",
        value=(
            f"`{sys['hostname']}`\n"
            f"{sys['os']}\n"
            f"CPU: {sys['cpu_count']} cores | RAM: {sys['ram_gb']} GB"
        ),
        inline=True,
    )
    embed.set_footer(text=f"Duración: {data['duration_s']}s")

    # Advertencia si firewall inactivo
    if not fw["active"]:
        embed.add_field(
            name="⚠️ Advertencia",
            value="Firewall inactivo. Activa UFW con:\n```sudo ufw enable```",
            inline=False,
        )

    await msg.edit(content="", embed=embed)

    # ── Puertos en mensaje separado ──
    open_ports = [p for p in data["ports"] if p["open"]]
    if open_ports:
        port_blocks = build_ports_text(data["ports"])
        for i, block in enumerate(port_blocks):
            port_embed = discord.Embed(
                title=f"🔌 Puertos {'(continuación)' if i > 0 else ''}",
                description=block,
                color=COLOR_WARN if s["high"] > 0 or s["critical"] > 0 else COLOR_OK,
            )
            await ctx.send(embed=port_embed)


@bot.command(name="ports")
async def cmd_ports(ctx: commands.Context, target: str = "127.0.0.1"):
    """Escaneo de puertos solamente."""
    if not is_authorized(ctx):
        await ctx.send("❌ No tienes permiso.")
        return

    clean = validate_target(target)
    if not clean:
        await ctx.send(f"❌ Target inválido: `{target}`")
        return

    msg = await ctx.send(f"🔍 Escaneando puertos en `{clean}`…")

    try:
        ports = scan_ports(clean)
    except Exception as e:
        await msg.edit(content=f"❌ Error: `{e}`")
        return

    open_ports  = [p for p in ports if p["open"]]
    critical    = sum(1 for p in open_ports if p["risk"] == "critical")
    high        = sum(1 for p in open_ports if p["risk"] == "high")

    color = risk_color(critical, high)
    blocks = build_ports_text(ports)

    await msg.delete()
    for i, block in enumerate(blocks):
        embed = discord.Embed(
            title=f"🔌 Puertos en `{clean}` — {len(open_ports)} abiertos {'(continuación)' if i > 0 else ''}",
            description=block,
            color=color,
        )
        if i == 0:
            embed.add_field(
                name="Resumen",
                value=f"🔴 {critical} críticos | 🟠 {high} altos | Total abiertos: {len(open_ports)}"
            )
        await ctx.send(embed=embed)


@bot.command(name="devices")
async def cmd_devices(ctx: commands.Context):
    """Descubrir dispositivos en la red local (ping sweep)."""
    if not is_authorized(ctx):
        await ctx.send("❌ No tienes permiso.")
        return

    msg = await ctx.send("📡 Ejecutando ping sweep en la red local (puede tardar ~30s)…")

    try:
        devices = get_connected_devices(sweep=True)
    except Exception as e:
        await msg.edit(content=f"❌ Error: `{e}`")
        return

    if not devices:
        await msg.edit(content="📡 No se encontraron dispositivos en la red local.")
        return

    embed = discord.Embed(
        title=f"📱 Dispositivos en la Red — {len(devices)} encontrados",
        color=COLOR_INFO,
        timestamp=discord.utils.utcnow(),
    )

    # Mostrar hasta 25 dispositivos (límite de campos de Discord)
    for d in devices[:25]:
        name = d["hostname"] if d["hostname"] != "—" else d["ip"]
        embed.add_field(
            name=f"📟 {name}",
            value=(
                f"IP: `{d['ip']}`\n"
                f"MAC: `{d['mac']}`\n"
                f"Vendor: {d['vendor']}\n"
                f"Interfaz: `{d['iface']}`"
            ),
            inline=True,
        )

    if len(devices) > 25:
        embed.set_footer(text=f"Mostrando 25 de {len(devices)} dispositivos.")

    await msg.edit(content="", embed=embed)


@bot.command(name="firewall")
async def cmd_firewall(ctx: commands.Context):
    """Estado del firewall del sistema."""
    if not is_authorized(ctx):
        await ctx.send("❌ No tienes permiso.")
        return

    msg = await ctx.send("🔥 Verificando estado del firewall…")

    try:
        fw = get_firewall_status()
    except Exception as e:
        await msg.edit(content=f"❌ Error: `{e}`")
        return

    color  = COLOR_OK if fw["active"] else COLOR_DANGER
    status = "🔒 ACTIVO" if fw["active"] else "🔓 INACTIVO"

    embed = discord.Embed(
        title=f"🔥 Firewall — {status}",
        color=color,
        timestamp=discord.utils.utcnow(),
    )
    embed.add_field(name="Software", value=fw["name"], inline=True)
    embed.add_field(name="Estado",   value=status,     inline=True)

    if fw["details"]:
        details_text = "\n".join(fw["details"][:15])
        if len(details_text) > 1000:
            details_text = details_text[:997] + "..."
        embed.add_field(
            name="Detalles",
            value=f"```\n{details_text}\n```",
            inline=False,
        )

    if not fw["active"]:
        embed.add_field(
            name="⚠️ Recomendación",
            value="Activa el firewall:\n```bash\nsudo ufw enable\nsudo ufw default deny incoming\nsudo ufw default allow outgoing\n```",
            inline=False,
        )

    await msg.edit(content="", embed=embed)


@bot.command(name="sysinfo")
async def cmd_sysinfo(ctx: commands.Context):
    """Información del sistema."""
    if not is_authorized(ctx):
        await ctx.send("❌ No tienes permiso.")
        return

    try:
        s = get_system_info()
    except Exception as e:
        await ctx.send(f"❌ Error: `{e}`")
        return

    embed = discord.Embed(
        title="💻 Información del Sistema",
        color=COLOR_INFO,
        timestamp=discord.utils.utcnow(),
    )
    embed.add_field(name="🖥️ Hostname",        value=f"`{s['hostname']}`", inline=True)
    embed.add_field(name="🐧 Sistema Operativo", value=s["os"],            inline=True)
    embed.add_field(name="⚙️ Arquitectura",     value=s["arch"],           inline=True)
    embed.add_field(name="🧠 CPUs",             value=str(s["cpu_count"]), inline=True)
    embed.add_field(name="💾 RAM Total",        value=f"{s['ram_gb']} GB", inline=True)
    await ctx.send(embed=embed)


@bot.command(name="conns")
async def cmd_conns(ctx: commands.Context):
    """Conexiones TCP activas."""
    if not is_authorized(ctx):
        await ctx.send("❌ No tienes permiso.")
        return

    msg = await ctx.send("🌐 Obteniendo conexiones activas…")

    try:
        conns = get_active_connections()
    except Exception as e:
        await msg.edit(content=f"❌ Error: `{e}`")
        return

    if not conns:
        await msg.edit(content="🌐 No hay conexiones TCP activas.")
        return

    lines = ["```"]
    lines.append(f"{'LOCAL':<22} {'REMOTO':<22} ESTADO")
    lines.append("─" * 60)
    for c in conns[:15]:
        lines.append(f"{c['local']:<22} {c['remote']:<22} {c['status']}")
    if len(conns) > 15:
        lines.append(f"... y {len(conns) - 15} más")
    lines.append("```")

    embed = discord.Embed(
        title=f"🌐 Conexiones Activas — {len(conns)} establecidas",
        description="\n".join(lines),
        color=COLOR_INFO,
        timestamp=discord.utils.utcnow(),
    )
    await msg.edit(content="", embed=embed)


# ─── Listener de lenguaje natural ────────────────────────────────────────────

TRIGGER_PHRASES = [
    "corre seguridad",
    "ejecuta seguridad",
    "escanea la red",
    "scan de seguridad",
    "analiza la red",
]

@bot.event
async def on_message(message: discord.Message):
    # Ignorar mensajes del propio bot
    if message.author == bot.user:
        await bot.process_commands(message)
        return

    content = message.content.lower().strip()

    if any(phrase in content for phrase in TRIGGER_PHRASES):
        if not is_authorized(message):
            await message.channel.send("❌ No tienes permiso para ejecutar escaneos.")
            return

        msg = await message.channel.send("🔍 Iniciando escaneo de seguridad en la red local…")

        try:
            data = full_scan("127.0.0.1")
        except Exception as e:
            await msg.edit(content=f"❌ Error durante el escaneo: `{e}`")
            return

        s  = data["summary"]
        fw = data["firewall"]
        sy = data["system"]

        color = risk_color(s["critical"], s["high"])

        # ── Embed principal ──
        embed = discord.Embed(
            title="🛡️ Resultado del Escaneo de Seguridad",
            color=color,
            timestamp=discord.utils.utcnow(),
        )
        embed.add_field(
            name="📊 Puertos",
            value=(
                f"🔌 Abiertos: **{s['open_ports']}**\n"
                f"🔴 Críticos: **{s['critical']}**\n"
                f"🟠 Alto riesgo: **{s['high']}**\n"
                f"🟡 Medio: **{s['medium']}**\n"
                f"🔵 Bajo: **{s['low']}**"
            ),
            inline=True,
        )
        embed.add_field(
            name="🔥 Firewall",
            value=(
                f"{'🔒 ACTIVO' if fw['active'] else '🔓 **INACTIVO**'}\n"
                f"{fw['name']}"
            ),
            inline=True,
        )
        embed.add_field(
            name="🌐 Red",
            value=(
                f"📱 Dispositivos: **{s['devices']}**\n"
                f"🔗 Conexiones: **{len(data['connections'])}**"
            ),
            inline=True,
        )
        embed.add_field(
            name="💻 Sistema",
            value=f"`{sy['hostname']}` — {sy['os']}",
            inline=False,
        )
        embed.set_footer(text=f"Duración: {data['duration_s']}s")

        if not fw["active"]:
            embed.add_field(
                name="⚠️ Advertencia",
                value="Firewall inactivo. Activa con:\n```sudo ufw enable```",
                inline=False,
            )

        await msg.edit(content="", embed=embed)

        # ── Puertos abiertos ──
        open_ports = [p for p in data["ports"] if p["open"]]
        if open_ports:
            port_blocks = build_ports_text(data["ports"])
            for i, block in enumerate(port_blocks):
                port_embed = discord.Embed(
                    title=f"🔌 Puertos Abiertos {'(cont.)' if i > 0 else ''}",
                    description=block,
                    color=color,
                )
                await message.channel.send(embed=port_embed)

        # ── Dispositivos ──
        if data["devices"]:
            dev_lines = []
            for d in data["devices"][:20]:
                name = d["hostname"] if d["hostname"] != "—" else d["ip"]
                dev_lines.append(f"`{d['ip']:<16}` {d['mac']}  {d['vendor']}  ({name})")
            dev_embed = discord.Embed(
                title=f"📱 Dispositivos en la Red — {len(data['devices'])} encontrados",
                description="\n".join(dev_lines),
                color=COLOR_INFO,
            )
            await message.channel.send(embed=dev_embed)

        return  # No procesar como comando

    # Procesar comandos normales (!scan, !ports, etc.)
    await bot.process_commands(message)


# ─── Error handling ───────────────────────────────────────────────────────────
@bot.event
async def on_command_error(ctx: commands.Context, error: commands.CommandError):
    if isinstance(error, commands.CommandNotFound):
        return
    if isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(f"❌ Argumento faltante. Usa `{PREFIX}help_scan` para ver la sintaxis.")
        return
    await ctx.send(f"❌ Error inesperado: `{error}`")
    raise error


# ─── Entry point ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not TOKEN:
        print("❌ DISCORD_TOKEN no encontrado.")
        print("   Crea un archivo .env con:  DISCORD_TOKEN=tu_token_aqui")
        raise SystemExit(1)
    print("\n  🛡️  Network Security Scanner — Discord Bot")
    print("  ─────────────────────────────────────────")
    bot.run(TOKEN)
