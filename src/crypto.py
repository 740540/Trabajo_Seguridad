# crypto.py - Sistema con sesión persistente
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
        self.authenticated = False
        
        # Obtener directorio actual y crear carpeta Contraseñas en el directorio superior
        current_dir = os.path.dirname(os.path.abspath(__file__))
        parent_dir = os.path.dirname(current_dir)
        self.vaults_dir = os.path.join(parent_dir, ".Contraseñas")
        os.makedirs(self.vaults_dir, exist_ok=True)
        
        if multi_user:
            self.db_file = None
        else:
            self.db_file = os.path.join(self.vaults_dir, "passwords.db.enc")
    
    def initialize_with_pin(self, pin: str) -> bool:
        """Inicializar con PIN y mantener sesión abierta"""
        try:
            if self.multi_user:
                user_id = self.get_user_id_from_dnie(pin)
                if not user_id:
                    return False
                
                certificate = self.dnie_manager.get_certificate()
                if not certificate:
                    return False
                
                key = self._derive_key_from_certificate(certificate)
                self.fernet = Fernet(key)
            else:
                self.dnie_manager = DNIeManager()
                key = self.dnie_manager.authenticate(pin)
                self.fernet = Fernet(key)
            
            self.authenticated = True
            return True
            
        except Exception as e:
            print(f"❌ Error de autenticación DNIe: {e}")
            return False
    
    def get_user_id_from_dnie(self, pin: str) -> str:
        """Obtener ID único del usuario basado en el certificado del DNIe"""
        try:
            self.dnie_manager = DNIeManager()
            self.dnie_manager.authenticate(pin)
            certificate = self.dnie_manager.get_certificate()
            
            if not certificate:
                raise Exception("No se pudo obtener el certificado del DNIe")
            
            self.user_id = hashlib.sha256(certificate).hexdigest()[:32]
            
            if self.multi_user:
                user_vault_dir = os.path.join(self.vaults_dir, f"vault_dnie_{self.user_id}")
                os.makedirs(user_vault_dir, exist_ok=True)
                self.db_file = os.path.join(user_vault_dir, "passwords.db.enc")
            
            return self.user_id
            
        except Exception as e:
            raise Exception(f"Error obteniendo ID del DNIe: {str(e)}")
    
    def _derive_key_from_certificate(self, certificate: bytes) -> bytes:
        """Derivar clave Fernet del certificado del DNIe"""
        derived = hashlib.pbkdf2_hmac(
            'sha256', 
            certificate, 
            b'dnie_vault_salt', 
            100000, 
            32
        )
        return base64.urlsafe_b64encode(derived)
    
    def load_db(self) -> dict:
        """Cargar base de datos (requiere autenticación previa)"""
        if not self.authenticated or not self.fernet:
            raise Exception("No autenticado. Llame a initialize_with_pin primero.")
                
        try:
            with open(self.db_file, 'rb') as f:
                ciphertext = f.read()
            plaintext = self.fernet.decrypt(ciphertext)
            return json.loads(plaintext.decode())
        except FileNotFoundError:
            return {"entries": []}
    
    def save_db(self, db_dict: dict):
        """Guardar base de datos (requiere autenticación previa)"""
        if not self.authenticated or not self.fernet:
            raise Exception("No autenticado. Llame a initialize_with_pin primero.")
        if not self.db_file:
            raise Exception("No se ha configurado archivo de base de datos")
            
        plaintext = json.dumps(db_dict).encode()
        ciphertext = self.fernet.encrypt(plaintext)
        with open(self.db_file, 'wb') as f:
            f.write(ciphertext)
    
    def add_password(self, service: str, username: str, password: str):
        """Añadir contraseña (usa sesión existente)"""
        db = self.load_db()
        db["entries"].append({
            "service": service,
            "username": username,
            "password": password
        })
        self.save_db(db)
    
    def list_entries(self):
        """Listar contraseñas (usa sesión existente)"""
        db = self.load_db()
        return db["entries"]
    
    def update_password(self, service: str, username: str, password: str):
        """Actualizar contraseña (usa sesión existente)"""
        db = self.load_db()
        for entry in db["entries"]:
            if entry["service"] == service and entry["username"] == username:
                entry["password"] = password
                self.save_db(db)
                return True
        return False
    
    def delete_password(self, service: str, username: str):
        """Eliminar contraseña (usa sesión existente)"""
        db = self.load_db()
        db["entries"] = [entry for entry in db["entries"] 
                        if not (entry["service"] == service and entry["username"] == username)]
        self.save_db(db)
    
    # ... (resto de métodos igual: list_users, get_user_info, etc.) ...
    
    def close(self):
        """Cerrar sesión DNIe"""
        if self.dnie_manager:
            self.dnie_manager.close()
            self.authenticated = False