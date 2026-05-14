"""
Syntexchub Secure Vault - Pygame Toolkit Launcher
Author: Syed (original) / Nifla (clone)
A glossy cyber‑security dashboard that simply launches the CLI vault.
"""

import pygame, sys, subprocess, os

pygame.init()
WIDTH, HEIGHT = 900, 600
screen = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption("Syntexchub Secure Vault – Toolkit")

# Colors (dark neon)
BG = (12, 12, 20)
ACCENT = (0, 200, 150)
WHITE = (220, 220, 230)
GRAY = (80, 80, 100)

font_title = pygame.font.SysFont("Consolas", 32, bold=True)
font_btn   = pygame.font.SysFont("Consolas", 22)
font_small = pygame.font.SysFont("Consolas", 14)

# Buttons
class Button:
    def __init__(self, txt, x, y, w, h):
        self.rect = pygame.Rect(x, y, w, h)
        self.txt = txt
        self.hover = False
    def draw(self, surf):
        col = ACCENT if self.hover else GRAY
        pygame.draw.rect(surf, col, self.rect, border_radius=6)
        txt_surf = font_btn.render(self.txt, True, WHITE)
        surf.blit(txt_surf, (self.rect.centerx - txt_surf.get_width()//2,
                             self.rect.centery - txt_surf.get_height()//2))
    def handle(self, ev):
        if ev.type == pygame.MOUSEMOTION:
            self.hover = self.rect.collidepoint(ev.pos)
        if ev.type == pygame.MOUSEBUTTONDOWN and self.hover:
            return True
        return False

run_btn = Button("▶  Launch Vault CLI", 300, 350, 300, 50)
quit_btn = Button("✕  Exit", 300, 430, 300, 50)

clock = pygame.time.Clock()
running = True
while running:
    for ev in pygame.event.get():
        if ev.type == pygame.QUIT:
            running = False
        if run_btn.handle(ev):
            # Locate the CLI entry point (main.py) relative to this file
            base_dir = os.path.dirname(os.path.abspath(__file__))
            cli_path = os.path.join(base_dir, "main.py")
            subprocess.Popen([sys.executable, cli_path], creationflags=subprocess.CREATE_NEW_CONSOLE)
        if quit_btn.handle(ev):
            running = False
    screen.fill(BG)
    # Title
    title = font_title.render("Syntexchub Secure Vault", True, ACCENT)
    screen.blit(title, (WIDTH//2 - title.get_width()//2, 120))
    subtitle = font_small.render("Secure Credential Management – Cyber‑grade Toolkit", True, WHITE)
    screen.blit(subtitle, (WIDTH//2 - subtitle.get_width()//2, 170))
    # Buttons
    run_btn.draw(screen)
    quit_btn.draw(screen)
    pygame.display.flip()
    clock.tick(30)

pygame.quit()
sys.exit()
