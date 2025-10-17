# main.py - Pasa el crypto manager autenticado a la interfaz
import sys
import tkinter as tk
from tkinter import simpledialog, messagebox
import customtkinter as ctk

# --- Fix Tkinter + CustomTkinter float issue ---
try:
    # Sobrescribir función interna para forzar enteros
    original_apply_widget_scaling = ctk.CTkBaseClass._apply_widget_scaling
    def fixed_apply_widget_scaling(self, value):
        return int(original_apply_widget_scaling(self, value))
    ctk.CTkBaseClass._apply_widget_scaling = fixed_apply_widget_scaling
    CTK_AVAILABLE = True
except Exception as e:
    print("No se pudo aplicar workaround de CustomTkinter:", e)
    CTK_AVAILABLE = False

# --- Importar módulos ---
try:
    from crypto import CryptoManager
    DNIE_AVAILABLE = True
except ImportError as e:
    print(f"❌ No se pudo importar crypto.py: {e}")
    DNIE_AVAILABLE = False

try:
    import interfaz
    INTERFAZ_AVAILABLE = True
except ImportError as e:
    print(f"❌ No se pudo importar interfaz.py: {e}")
    INTERFAZ_AVAILABLE = False

def ask_dnie_pin():
    """Solicitar PIN del DNIe mediante popup"""
    root = tk.Tk()
    root.withdraw()
    
    pin = simpledialog.askstring(
        "PIN del DNIe", 
        "🔐 Introduzca el PIN de su DNIe para acceder al gestor:",
        show='*'
    )
    root.destroy()
    return pin

def main():
    # Verificar dependencias
    if not CTK_AVAILABLE:
        print("❌ CustomTkinter no está disponible")
        sys.exit(1)
    
    if not DNIE_AVAILABLE:
        print("❌ Módulo crypto no está disponible")
        sys.exit(1)
    
    if not INTERFAZ_AVAILABLE:
        print("❌ Módulo interfaz no está disponible")
        sys.exit(1)
    
    try:
        # Autenticación única al inicio
        print("🔐 Iniciando autenticación DNIe...")
        print("📱 Por favor, inserte su DNIe en el lector...")
        
        pin = ask_dnie_pin()
        if not pin:
            print("❌ Autenticación cancelada por el usuario")
            sys.exit(0)
        
        # Crear y autenticar crypto manager
        crypto_manager = CryptoManager(multi_user=True)
        if not crypto_manager.initialize_with_pin(pin):
            messagebox.showerror("Error de autenticación", "No se pudo autenticar con DNIe")
            sys.exit(1)
        
        print("✅ Autenticación DNIe exitosa")
        print("✅ Acceso concedido - Abriendo interfaz...")
        
        # Pasar el crypto manager autenticado a la interfaz
        app = interfaz.BitwardenLikeApp(crypto_manager)
        app.mainloop()
        
    except KeyboardInterrupt:
        print("\n🛑 Operación cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error inesperado: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()