# crypto.py - Sistema de cifrado unificado con soporte multi-usuario DNIe
import json
import os
import hashlib
from cryptography.fernet import Fernet
from dnie import DNIeManager
import base64

class CryptoManager:
    def __init__(self, multi_user=True):
        self.fernet = None
        self.dnie_manager = None
        self.user_id = None
        self.multi_user = multi_user
        
        if multi_user:
            # Sistema multi-usuario: base de datos por DNIe
            self.db_file = None
        else:
            # Sistema simple: base de datos única
            VAULT_DIR = os.path.expanduser("~/Documents/UNIVERSIDAD/CIBER/PROYECTO_SEC")
            os.makedirs(VAULT_DIR, exist_ok=True)
            self.db_file = os.path.join(VAULT_DIR, "passwords.db.enc")
    
    def get_user_id_from_dnie(self, pin: str) -> str:
        """Obtener ID único del usuario basado en el certificado del DNIe"""
        try:
            self.dnie_manager = DNIeManager()
            self.dnie_manager.authenticate(pin)
            certificate = self.dnie_manager.get_certificate()
            
            if not certificate:
                raise Exception("No se pudo obtener el certificado del DNIe")
            
            # Crear ID único del hash del certificado
            self.user_id = hashlib.sha256(certificate).hexdigest()[:32]
            
            if self.multi_user:
                # Configurar archivo de base de datos único para este usuario
                vault_dir = os.path.expanduser(f"~/.vault_dnie_{self.user_id}")
                os.makedirs(vault_dir, exist_ok=True)
                self.db_file = os.path.join(vault_dir, "passwords.db.enc")
            
            return self.user_id
            
        except Exception as e:
            raise Exception(f"Error obteniendo ID del DNIe: {str(e)}")
    
    def authenticate_with_dnie(self, pin: str) -> bool:
        """Autenticar con DNIe y configurar clave de cifrado"""
        try:
            if self.multi_user:
                # Sistema multi-usuario: derivar clave del certificado
                user_id = self.get_user_id_from_dnie(pin)
                if not user_id:
                    return False
                
                certificate = self.dnie_manager.get_certificate()
                if not certificate:
                    return False
                
                # Derivar clave de cifrado del certificado
                key = self._derive_key_from_certificate(certificate)
                self.fernet = Fernet(key)
                return True
            else:
                # Sistema simple: usar autenticación básica
                self.dnie_manager = DNIeManager()
                key = self.dnie_manager.authenticate(pin)
                self.fernet = Fernet(key)
                return True
            
        except Exception as e:
            print(f"❌ Error de autenticación DNIe: {e}")
            return False
    
    def _derive_key_from_certificate(self, certificate: bytes) -> bytes:
        """Derivar clave Fernet del certificado del DNIe (multi-usuario)"""
        derived = hashlib.pbkdf2_hmac(
            'sha256', 
            certificate, 
            b'dnie_vault_salt', 
            100000, 
            32
        )
        return base64.urlsafe_b64encode(derived)
    
    def initialize_db(self, pin: str):
        """Initialize encrypted database with DNIe key"""
        if not self.authenticate_with_dnie(pin):
            raise Exception("No se pudo autenticar con DNIe")
        
        empty_db = {"entries": []}
        self._save_db(empty_db)
    
    def _save_db(self, db_dict: dict):
        """Encrypt and save database"""
        if not self.fernet:
            raise Exception("No autenticado con DNIe")
        if not self.db_file:
            raise Exception("No se ha configurado archivo de base de datos")
            
        plaintext = json.dumps(db_dict).encode()
        ciphertext = self.fernet.encrypt(plaintext)
        with open(self.db_file, 'wb') as f:
            f.write(ciphertext)
    
    def load_db(self, pin: str = None) -> dict:
        """Decrypt and load database"""
        if not self.fernet:
            if pin and not self.authenticate_with_dnie(pin):
                raise Exception("No se pudo autenticar con DNIe")
            else:
                raise Exception("No autenticado con DNIe")
                
        try:
            with open(self.db_file, 'rb') as f:
                ciphertext = f.read()
            plaintext = self.fernet.decrypt(ciphertext)
            return json.loads(plaintext.decode())
        except FileNotFoundError:
            return {"entries": []}
    
    def add_password(self, service: str, username: str, password: str, pin: str):
        """Add password entry"""
        db = self.load_db(pin)
        db["entries"].append({
            "service": service,
            "username": username,
            "password": password
        })
        self._save_db(db)
    
    def list_entries(self, pin: str = None):
        """List all password entries"""
        db = self.load_db(pin)
        return db["entries"]
    
    def update_password(self, service: str, username: str, password: str, pin: str):
        """Update existing password entry"""
        db = self.load_db(pin)
        for entry in db["entries"]:
            if entry["service"] == service and entry["username"] == username:
                entry["password"] = password
                self._save_db(db)
                return True
        return False
    
    def delete_password(self, service: str, username: str, pin: str):
        """Delete password entry"""
        db = self.load_db(pin)
        db["entries"] = [entry for entry in db["entries"] 
                        if not (entry["service"] == service and entry["username"] == username)]
        self._save_db(db)
    
    def list_users(self):
        """Listar todos los usuarios DNIe que tienen vaults (solo multi-usuario)"""
        if not self.multi_user:
            return []
            
        vault_users = []
        home_dir = os.path.expanduser("~")
        for item in os.listdir(home_dir):
            if item.startswith(".vault_dnie_") and os.path.isdir(os.path.join(home_dir, item)):
                user_id = item.replace(".vault_dnie_", "")
                vault_users.append(user_id)
        return vault_users
    
    def get_user_info(self, user_id: str) -> dict:
        """Obtener información de un usuario DNIe (solo multi-usuario)"""
        if not self.multi_user:
            return None
            
        vault_dir = os.path.expanduser(f"~/.vault_dnie_{user_id}")
        db_file = os.path.join(vault_dir, "passwords.db.enc")
        
        if os.path.exists(db_file):
            return {
                "user_id": user_id,
                "vault_dir": vault_dir,
                "db_file": db_file,
                "entries_count": self._count_entries(db_file) if os.path.exists(db_file) else 0
            }
        return None
    
    def _count_entries(self, db_file: str) -> int:
        """Contar entradas en una base de datos (sin descifrar)"""
        try:
            with open(db_file, 'rb') as f:
                ciphertext = f.read()
            return len(ciphertext)
        except:
            return 0
    
    def close(self):
        """Cerrar sesión DNIe"""
        if self.dnie_manager:
            self.dnie_manager.close()