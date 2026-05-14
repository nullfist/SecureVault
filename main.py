"""
Syntexchub Secure Vault — CLI Entry Point
Author: Syed

An interactive credential manager protected by Argon2id + AES encryption.
"""

import sys
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt

from vault.auth import AuthManager
from vault.storage import VaultStorage
from vault.crypto import VaultCrypto
from vault.generator import PasswordGenerator
from vault.audit import AuditLogger

console = Console()
audit = AuditLogger()

BANNER = r"""
[bold cyan]
 ╔═╗┌─┐┌─┐┬ ┬┬─┐┌─┐  ╦  ╦┌─┐┬ ┬┬  ┌┬┐
 ╚═╗├┤ │  │ │├┬┘├┤   ╚╗╔╝├─┤│ ││   │
 ╚═╝└─┘└─┘└─┘┴└─└─┘   ╚╝ ┴ ┴└─┘┴─┘ ┴
[/bold cyan]
[white] Encrypted Credential Manager — by Syed[/white]
"""


class VaultApp:
    def __init__(self):
        self.auth = AuthManager()
        self.storage = VaultStorage()
        self.key: bytes | None = None
        self.data: list = []

    # ── Startup ───────────────────────────────────────────
    def start(self):
        console.print(BANNER)

        if self.auth.is_locked():
            console.print("[bold red][LOCKED] Too many failed attempts. Delete data/auth.json to reset.[/bold red]")
            sys.exit(1)

        if not self.auth.is_setup():
            self._first_time_setup()
        else:
            self._login()

        self._menu()

    # ── First-time setup ──────────────────────────────────
    def _first_time_setup(self):
        console.print("[yellow]No vault found — creating a new one.[/yellow]\n")
        pw = Prompt.ask("[cyan]Set Master Password[/cyan]", password=True)
        confirm = Prompt.ask("[cyan]Confirm Master Password[/cyan]", password=True)
        if pw != confirm:
            console.print("[red]Passwords do not match. Exiting.[/red]")
            sys.exit(1)
        salt = self.auth.setup_master_password(pw)
        self.key = VaultCrypto.derive_key(pw, salt)
        self.data = []
        self.storage.save_vault(self.data, self.key)
        audit.log("Vault initialized (new master password set)")
        console.print("[green]Vault created successfully![/green]\n")

    # ── Login ─────────────────────────────────────────────
    def _login(self):
        while True:
            remaining = self.auth.remaining_attempts()
            if remaining <= 0:
                console.print("[bold red]Vault locked. Too many failed attempts.[/bold red]")
                audit.log("Vault locked after max failed attempts", "WARNING")
                sys.exit(1)

            pw = Prompt.ask(f"[cyan]Master Password ({remaining} attempts left)[/cyan]", password=True)
            ok, salt = self.auth.verify_password(pw)
            if ok:
                self.key = VaultCrypto.derive_key(pw, salt)
                try:
                    self.data = self.storage.load_vault(self.key)
                except ValueError as e:
                    console.print(f"[red]{e}[/red]")
                    sys.exit(1)
                audit.log("Successful login")
                console.print("[green]Access granted.[/green]\n")
                return
            else:
                audit.log("Failed login attempt", "WARNING")
                console.print("[red]Incorrect password.[/red]")

    # ── Main Menu ─────────────────────────────────────────
    def _menu(self):
        while True:
            console.print(Panel(
                "1. View Credentials\n"
                "2. Add Credential\n"
                "3. Search Credentials\n"
                "4. Update Credential\n"
                "5. Delete Credential\n"
                "6. Generate Password\n"
                "7. Export Vault (encrypted backup)\n"
                "8. View Audit Logs\n"
                "9. Exit",
                title="[bold cyan]VAULT MENU[/bold cyan]",
                border_style="cyan",
            ))
            choice = Prompt.ask("Select", choices=["1","2","3","4","5","6","7","8","9"])

            if choice == "1":   self._view()
            elif choice == "2": self._add()
            elif choice == "3": self._search()
            elif choice == "4": self._update()
            elif choice == "5": self._delete()
            elif choice == "6": self._gen_password()
            elif choice == "7": self._export()
            elif choice == "8": self._logs()
            elif choice == "9":
                console.print("[yellow]Vault locked. Stay safe! 🔒[/yellow]")
                sys.exit(0)

    # ── View ──────────────────────────────────────────────
    def _view(self):
        if not self.data:
            console.print("[yellow]Vault is empty.[/yellow]")
            return
        table = Table(title="Stored Credentials", show_lines=True)
        table.add_column("ID", style="dim", width=4)
        table.add_column("Service", style="cyan")
        table.add_column("Username", style="magenta")
        table.add_column("Password", style="green")
        table.add_column("Tags", style="yellow")
        table.add_column("Added", style="dim")
        for i, e in enumerate(self.data):
            table.add_row(str(i+1), e["service"], e["username"], "••••••••",
                          e.get("tags",""), e["date"])
        console.print(table)
        reveal = Prompt.ask("Enter ID to reveal password (or 'b' to go back)")
        if reveal.isdigit():
            idx = int(reveal) - 1
            if 0 <= idx < len(self.data):
                e = self.data[idx]
                console.print(Panel(f"[green]{e['password']}[/green]",
                                    title=f"{e['service']} — {e['username']}"))
                audit.log(f"Password revealed for {e['service']}")

    # ── Add ───────────────────────────────────────────────
    def _add(self):
        service  = Prompt.ask("Service (e.g. GitHub)")
        username = Prompt.ask("Username / Email")
        password = Prompt.ask("Password (blank = generate)", password=True, default="")
        if not password:
            password = PasswordGenerator.generate()
            ent = PasswordGenerator.estimate_entropy(password)
            console.print(f"[green]Generated:[/green] {password}  ({ent} bits — {PasswordGenerator.strength_label(ent)})")
        tags  = Prompt.ask("Tags (comma-separated)", default="")
        notes = Prompt.ask("Notes", default="")
        entry = {
            "service": service, "username": username, "password": password,
            "tags": tags, "notes": notes,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        }
        self.data.append(entry)
        self.storage.save_vault(self.data, self.key)
        audit.log(f"Added credential for {service}")
        console.print("[green]Saved.[/green]")

    # ── Search ────────────────────────────────────────────
    def _search(self):
        query = Prompt.ask("Search term").lower()
        hits = [(i, e) for i, e in enumerate(self.data)
                if query in e["service"].lower() or query in e.get("tags","").lower()
                or query in e["username"].lower()]
        if not hits:
            console.print("[yellow]No matches.[/yellow]")
            return
        table = Table(title=f"Search: '{query}'")
        table.add_column("ID"); table.add_column("Service"); table.add_column("Username")
        for i, e in hits:
            table.add_row(str(i+1), e["service"], e["username"])
        console.print(table)

    # ── Update ────────────────────────────────────────────
    def _update(self):
        self._view()
        idx_str = Prompt.ask("ID to update")
        if not idx_str.isdigit():
            return
        idx = int(idx_str) - 1
        if not (0 <= idx < len(self.data)):
            console.print("[red]Invalid ID.[/red]"); return
        e = self.data[idx]
        e["service"]  = Prompt.ask("Service",  default=e["service"])
        e["username"] = Prompt.ask("Username", default=e["username"])
        new_pw = Prompt.ask("New password (blank = keep)", password=True, default="")
        if new_pw:
            e["password"] = new_pw
        e["tags"]  = Prompt.ask("Tags",  default=e.get("tags",""))
        e["notes"] = Prompt.ask("Notes", default=e.get("notes",""))
        self.storage.save_vault(self.data, self.key)
        audit.log(f"Updated credential for {e['service']}")
        console.print("[green]Updated.[/green]")

    # ── Delete ────────────────────────────────────────────
    def _delete(self):
        self._view()
        idx_str = Prompt.ask("ID to delete")
        if not idx_str.isdigit():
            return
        idx = int(idx_str) - 1
        if 0 <= idx < len(self.data):
            removed = self.data.pop(idx)
            self.storage.save_vault(self.data, self.key)
            audit.log(f"Deleted credential for {removed['service']}")
            console.print(f"[green]Deleted {removed['service']}.[/green]")

    # ── Generate Password ─────────────────────────────────
    def _gen_password(self):
        length = int(Prompt.ask("Length", default="20"))
        pw = PasswordGenerator.generate(length=length)
        ent = PasswordGenerator.estimate_entropy(pw)
        lbl = PasswordGenerator.strength_label(ent)
        console.print(Panel(f"[green]{pw}[/green]\nEntropy: {ent} bits  |  Strength: [bold]{lbl}[/bold]",
                            title="Generated Password"))

    # ── Export ─────────────────────────────────────────────
    def _export(self):
        import shutil, os
        src = self.storage.storage_file
        dst = f"data/vault_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.enc"
        if os.path.exists(src):
            shutil.copy2(src, dst)
            audit.log(f"Vault exported to {dst}")
            console.print(f"[green]Backup saved to {dst}[/green]")
        else:
            console.print("[yellow]No vault file to export.[/yellow]")

    # ── Logs ──────────────────────────────────────────────
    def _logs(self):
        lines = audit.get_recent()
        if not lines:
            console.print("[yellow]No audit logs yet.[/yellow]")
            return
        console.print(Panel("\n".join(l.strip() for l in lines),
                            title="[yellow]Recent Audit Events[/yellow]"))


if __name__ == "__main__":
    try:
        VaultApp().start()
    except KeyboardInterrupt:
        console.print("\n[red]Session terminated.[/red]")
        sys.exit(0)
