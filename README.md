# 🛡️ Proyecto Ciberseguridad 1 – Gestor de Contraseñas con DNIe + Firma de archivos mediante certificado DNIe.

Un gestor de contraseñas seguro que utiliza el **DNI electrónico (DNIe)** como método de autenticación y cifrado.  
El sistema cifra las contraseñas mediante una clave derivada de la firma digital del DNIe, garantizando máxima seguridad.
Para mostrar las contraseñas guardadas se usa Google Authenticator como doble factor.
El programa, además es capáz de firmar archivos y comprobar su originalidad mediante el DNIe.

---

## 🚀 Características

- 🔐 Autenticación mediante **DNIe físico** (con lector de tarjetas)
- 🧠 Cifrado y descifrado con **Fernet (AES-128 GCM)** derivado de la firma del DNIe (PBKDF2-HMAC-SHA256)
- 💾 Base de datos cifrada local (`passwords.db.enc`)
- 🧰 CLI (interfaz de línea de comandos) con `click`
- 🖥️ Interfaz gráfica moderna con **CustomTkinter** aportando además, modo claro y oscuro.
- ⚙️ Compatibilidad multiplataforma (Windows, macOS, Linux)

---

## 📦 Instalación

### 1️⃣ Clonar el repositorio

```bash
git clone https://github.com/740540/Trabajo_Seguridad.git
cd Trabajo_Seguridad
```

### 2️⃣ **Instalar Dependencias

```En Windows/Linux:

pip install cryptography customtkinter click python-pkcs11

En MacOS

pip install cryptography customtkinter click PyKCS11
```

### 3️⃣ Instalar OpenSC

```El DNIe requiere los controladores de OpenSC:

Windows: https://github.com/OpenSC/OpenSC/releases

macOS (Homebrew): brew install opensc

Linux (Debian/Ubuntu): sudo apt install opensc
```

## 🧰 Uso

```🔹 Ejecución con Interfaz Gráfica (Programa Principal)

Ejecutar por terminal : python main.py

Inserta tu DNIe en el lector.

Introduce el PIN cuando se solicite.

Se abrirá la interfaz gráfica para gestionar tus contraseñas.

🔹 Ejecución por Línea de Comandos

El CLI (cli.py) permite usar el gestor desde la terminal:

# Inicializar base de datos
python cli.py init

# Añadir contraseña
python cli.py add --service Gmail --username usuario@gmail.com --password 1234

# Listar entradas
python cli.py list

# Comprobar el estado del DNIe
python cli.py status
```

## 🔑 Estructura del Proyecto
```Trabajo_Seguridad/
│
├── 📁 src/                          # Directorio actual del código
│   │
│   ├── main.py                      # Punto de entrada principal con GUI
│   ├── crypto.py                    # Cifrado y base de datos segura
│   ├── dnie.py                      # Autenticación y firma con DNIe
│   ├── interfaz.py                  # Interfaz gráfica (CustomTkinter)
│   ├── cli.py                       # Interfaz de línea de comandos (Click)
│   └── OTP.py                       # Generador de QR para 2FA
├── Documento_Importante.txt         # Archivo de ejemplo para firmar
└── README.md
```








