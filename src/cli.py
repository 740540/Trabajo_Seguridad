# cli.py - Interfaz de línea de comandos actualizada
import click
import getpass
from crypto import CryptoManager

@click.group()
def cli():
    """Password Manager secured by DNIe (Multi-User)"""
    pass

@cli.command()
def init():
    """Initialize password manager with DNIe (multi-user)"""
    try:
        pin = getpass.getpass("Enter DNIe PIN: ")
        
        crypto = CryptoManager(multi_user=True)
        crypto.initialize_db(pin)
        
        click.echo("✅ Password manager initialized successfully with DNIe!")
        click.echo("🔐 Multi-user mode: Each DNIe has its own encrypted vault")
        crypto.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
@click.option('--service', prompt='Service')
@click.option('--username', prompt='Username')
@click.option('--password', prompt=True, hide_input=True)
def add(service, username, password):
    """Add password entry using DNIe authentication"""
    try:
        pin = getpass.getpass("Enter DNIe PIN: ")
        
        crypto = CryptoManager(multi_user=True)
        crypto.add_password(service, username, password, pin)
        
        click.echo("✅ Password added successfully!")
        crypto.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
def list():
    """List all password entries using DNIe authentication"""
    try:
        pin = getpass.getpass("Enter DNIe PIN: ")
        
        crypto = CryptoManager(multi_user=True)
        entries = crypto.list_entries(pin)
        
        if not entries:
            click.echo("📭 No password entries found")
        else:
            click.echo("🔐 Stored passwords:")
            for entry in entries:
                click.echo(f"  Service: {entry['service']}")
                click.echo(f"  Username: {entry['username']}")
                click.echo("  " + "-" * 30)
            
        crypto.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
def users():
    """List all DNIe users with vaults"""
    try:
        crypto = CryptoManager(multi_user=True)
        users = crypto.list_users()
        vaults_dir = crypto.get_vaults_directory()
        
        if users:
            click.echo(f"📁 Vaults directory: {vaults_dir}")
            click.echo("👥 DNIe Users with vaults:")
            for user_id in users:
                user_info = crypto.get_user_info(user_id)
                if user_info:
                    click.echo(f"  User: {user_id[:16]}...")
                    click.echo(f"  Vault: {user_info['vault_dir']}")
                    click.echo(f"  Data size: {user_info['entries_count']} bytes")
                    click.echo("  " + "-" * 40)
        else:
            click.echo(f"📁 Vaults directory: {vaults_dir}")
            click.echo("📭 No DNIe users found")
            
        crypto.close()
        
    except Exception as e:
        click.echo(f"❌ Error: {str(e)}")

@cli.command()
def status():
    """Check DNIe status and multi-user info"""
    try:
        from dnie import verificar_estado_dnie
        
        if verificar_estado_dnie():
            click.echo("✅ DNIe está conectado y listo para autenticación")
            
            crypto = CryptoManager(multi_user=True)
            users = crypto.list_users()
            crypto.close()
            
            click.echo(f"👥 Usuarios registrados: {len(users)}")
            click.echo("🔐 Modo: Multi-usuario (cada DNIe tiene su vault)")
        else:
            click.echo("❌ No se detectó ningún DNIe - por favor inserte su DNIe")
            
    except Exception as e:
        click.echo(f"❌ Error accediendo al DNIe: {str(e)}")

if __name__ == '__main__':
    cli()