"""
LIHAT DB - Penampil Database Secret Diary (hanya-baca)
------------------------------------------------------
Menampilkan isi data/diary_multi.db dengan tampilan yang senada dengan aplikasi.
Data ditampilkan APA ADANYA (terenkripsi), tidak didekripsi.
Letakkan file ini di folder yang sama dengan diary_app.py lalu jalankan:
    python lihat_db.py
Shortcut: F11 = layar penuh, Esc = keluar dari layar penuh.
"""
import os
import sqlite3
from pathlib import Path
import tkinter as tk
from tkinter import ttk

BASE = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE, "data", "diary_multi.db")

# ---- tema (sama dengan aplikasi) ----
BG, CARD, BROWN, BROWN2 = "#F6EEDC", "#FFFBF2", "#4A2F27", "#6B4636"
GOLD, GOLD_D, ROSE = "#C8963E", "#B07F2C", "#B5485D"
TEXT, MUTED, BORDER = "#3B2A24", "#8A7566", "#E2D3B8"
FONT_H1 = ("Segoe Script", 20, "bold")
FONT_ISI = ("Segoe UI", 11)
FONT_KECIL = ("Segoe UI", 9)
FONT_MONO = ("Consolas", 10)

TABEL = {
    "users": {
        "label": "👤   Akun (users)",
        "info": "Password tidak disimpan sebagai teks, melainkan hash PBKDF2-SHA256 + salt.",
        "kolom": ("id", "username", "salt", "hash", "dibuat"),
        "sql": "SELECT id, username, salt, hash, dibuat FROM users ORDER BY id",
    },
    "entries": {
        "label": "📖   Catatan (entries)",
        "info": "Judul dan isi diary tersimpan sebagai ciphertext (Vigenere + LFSR, Base64).",
        "kolom": ("id", "pemilik", "tanggal", "judul_enc", "isi_enc"),
        "sql": ("SELECT e.id, COALESCE(u.username, '?'), e.tanggal, e.judul_enc, e.isi_enc "
                "FROM entries e LEFT JOIN users u ON u.id = e.user_id ORDER BY e.id"),
    },
    "blocks": {
        "label": "⛓   Blockchain (blocks)",
        "info": "Setiap blok menyimpan hash blok sebelumnya; mengubah data merusak rantai.",
        "kolom": ("idx", "ts", "data", "prev_hash", "nonce", "hash", "user_id"),
        "sql": "SELECT idx, ts, data, prev_hash, nonce, hash, user_id FROM blocks ORDER BY idx",
    },
}
LEBAR_KOLOM = {"id": 50, "idx": 50, "nonce": 70, "user_id": 70, "pemilik": 110, "username": 130}


def baca(sql):
    """Buka database dalam mode hanya-baca, ambil data, lalu langsung ditutup (tidak mengunci)."""
    if not os.path.exists(DB_FILE):
        raise FileNotFoundError(
            "Database belum ada.\nJalankan diary_app.py dan buat akun terlebih dahulu.")
    con = sqlite3.connect(Path(DB_FILE).as_uri() + "?mode=ro", uri=True)
    try:
        return con.execute(sql).fetchall()
    finally:
        con.close()


def tombol(parent, teks, cmd, warna=GOLD, hover=GOLD_D):
    b = tk.Button(parent, text=teks, command=cmd, bg=warna, fg="white", activebackground=hover,
                  activeforeground="white", relief="flat", bd=0, cursor="hand2",
                  font=("Segoe UI", 10, "bold"), padx=16, pady=9)
    b.bind("<Enter>", lambda e: b.config(bg=hover))
    b.bind("<Leave>", lambda e: b.config(bg=warna))
    return b


def tampil_error(judul, pesan):
    """Dialog error bertema diary."""
    win = tk.Toplevel(tk._default_root)
    win.withdraw()
    win.title(judul)
    win.configure(bg=CARD)
    win.resizable(False, False)
    head = tk.Frame(win, bg=ROSE)
    head.pack(fill="x")
    tk.Label(head, text="❌", bg=ROSE, fg="white", font=("Segoe UI Emoji", 22)).pack(
        side="left", padx=(22, 10), pady=14)
    tk.Label(head, text=judul, bg=ROSE, fg="white", font=("Segoe Script", 15, "bold")).pack(
        side="left", pady=14, padx=(0, 24))
    tk.Label(win, text=pesan, bg=CARD, fg=TEXT, font=FONT_ISI, justify="left", anchor="w",
             wraplength=380).pack(fill="x", padx=26, pady=(22, 8))
    bar = tk.Frame(win, bg=CARD)
    bar.pack(fill="x", padx=22, pady=(10, 20))
    btn = tombol(bar, "OK", win.destroy)
    btn.pack(side="right")
    win.bind("<Return>", lambda e: win.destroy())
    win.bind("<Escape>", lambda e: win.destroy())
    win.update_idletasks()
    p = tk._default_root
    w, h = win.winfo_reqwidth(), win.winfo_reqheight()
    if p.winfo_viewable():
        win.transient(p)
        x = p.winfo_rootx() + (p.winfo_width() - w) // 2
        y = p.winfo_rooty() + (p.winfo_height() - h) // 2
    else:                       # jendela utama belum tampil (error saat startup)
        x, y = (win.winfo_screenwidth() - w) // 2, (win.winfo_screenheight() - h) // 2
    win.geometry(f"+{max(x, 0)}+{max(y, 0)}")
    win.deiconify()
    try:
        win.wait_visibility()
        win.grab_set()
    except tk.TclError:
        pass
    win.focus_force()
    btn.focus_set()
    win.wait_window()


class Viewer(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secret Diary - Lihat Database")
        self.configure(bg=BG)
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        lebar, tinggi = min(1100, sw - 60), min(700, sh - 110)
        self.geometry(f"{lebar}x{tinggi}+{(sw - lebar) // 2}+{max((sh - tinggi) // 2 - 20, 0)}")
        self.minsize(min(900, lebar), min(560, tinggi))
        self.bind("<F11>", lambda e: self.attributes("-fullscreen",
                                                     not self.attributes("-fullscreen")))
        self.bind("<Escape>", lambda e: self.attributes("-fullscreen", False))

        self.aktif = "users"
        self.baris = {}
        self.nav = {}
        self.gaya()
        self.bangun()
        self.buka("users")

    def gaya(self):
        st = ttk.Style()
        st.theme_use("clam")
        st.configure("Treeview", background=CARD, fieldbackground=CARD, foreground=TEXT,
                     rowheight=30, borderwidth=0, font=FONT_ISI)
        st.configure("Treeview.Heading", background=BROWN2, foreground="white",
                     font=("Segoe UI", 10, "bold"), relief="flat", padding=6)
        st.map("Treeview", background=[("selected", GOLD)], foreground=[("selected", "white")])
        st.map("Treeview.Heading", background=[("active", BROWN)])
        st.configure("Vertical.TScrollbar", background=BORDER, troughcolor=CARD,
                     bordercolor=CARD, arrowcolor=BROWN2, relief="flat")

    def bangun(self):
        side = tk.Frame(self, bg=BROWN, width=250)
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Label(side, text="🗄 Lihat DB", bg=BROWN, fg="#F6E7C8",
                 font=("Segoe Script", 17, "bold")).pack(pady=(26, 2), padx=18, anchor="w")
        tk.Label(side, text="Mode hanya-baca", bg=BROWN, fg="#D9C3A5",
                 font=FONT_KECIL).pack(padx=20, anchor="w", pady=(0, 22))
        for kode, t in TABEL.items():
            b = tk.Button(side, text=t["label"], anchor="w", relief="flat", bd=0, bg=BROWN,
                          fg="#EAD9C6", activebackground=BROWN2, activeforeground="white",
                          font=("Segoe UI", 11), padx=22, pady=11, cursor="hand2",
                          command=lambda k=kode: self.buka(k))
            b.pack(fill="x")
            b.bind("<Enter>", lambda e, k=kode: self.nav[k].config(bg=BROWN2) if k != self.aktif else None)
            b.bind("<Leave>", lambda e, k=kode: self.nav[k].config(bg=BROWN) if k != self.aktif else None)
            self.nav[kode] = b
        bawah = tk.Frame(side, bg=BROWN)
        bawah.pack(side="bottom", fill="x", padx=18, pady=20)
        tombol(bawah, "⟳  Refresh", self.refresh).pack(fill="x", pady=(0, 8))
        tombol(bawah, "Tutup", self.destroy, ROSE, "#963A4C").pack(fill="x")

        isi = tk.Frame(self, bg=BG)
        isi.pack(side="left", fill="both", expand=True, padx=28, pady=22)
        self.l_judul = tk.Label(isi, text="", bg=BG, fg=BROWN, font=FONT_H1)
        self.l_judul.pack(anchor="w")
        self.l_info = tk.Label(isi, text="", bg=BG, fg=MUTED, font=FONT_ISI)
        self.l_info.pack(anchor="w", pady=(0, 12))

        # panel detail dipasang lebih dulu (bawah) supaya tetap terlihat di jendela kecil
        detail = tk.Frame(isi, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        detail.pack(side="bottom", fill="x", pady=(12, 0))
        tk.Label(detail, text="Detail baris terpilih (nilai lengkap)", bg=CARD, fg=MUTED,
                 font=FONT_KECIL).pack(anchor="w", padx=12, pady=(8, 0))
        self.t_detail = tk.Text(detail, height=7, wrap="char", font=FONT_MONO, bg=CARD, fg=TEXT,
                                relief="flat", padx=12, pady=6, state="disabled")
        self.t_detail.tag_config("k", foreground=GOLD_D, font=("Consolas", 10, "bold"))
        self.t_detail.pack(fill="x")

        kartu = tk.Frame(isi, bg=CARD, highlightthickness=1, highlightbackground=BORDER)
        kartu.pack(fill="both", expand=True)
        self.tree = ttk.Treeview(kartu, show="headings")
        sb = ttk.Scrollbar(kartu, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True, padx=6, pady=6)
        self.tree.bind("<<TreeviewSelect>>", self.pilih)

    def buka(self, kode):
        self.aktif = kode
        for k, b in self.nav.items():
            b.config(bg=GOLD if k == kode else BROWN, fg="white" if k == kode else "#EAD9C6",
                     font=("Segoe UI", 11, "bold" if k == kode else "normal"))
        self.refresh()

    def refresh(self):
        t = TABEL[self.aktif]
        self.l_judul.config(text=t["label"].split("   ")[1])
        self.l_info.config(text=t["info"])
        self.tree.delete(*self.tree.get_children())
        self.baris = {}
        self.tulis_detail()
        try:
            data = baca(t["sql"])
        except (FileNotFoundError, sqlite3.Error) as ex:
            tampil_error("Tidak bisa membaca database", str(ex))
            return
        kolom = t["kolom"]
        self.tree["columns"] = kolom
        for c in kolom:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=LEBAR_KOLOM.get(c, 190), minwidth=50, anchor="w")
        for row in data:
            tampil = [str(v) if len(str(v)) <= 48 else str(v)[:48] + "…" for v in row]
            self.baris[self.tree.insert("", "end", values=tampil)] = row
        self.l_info.config(text=f"{t['info']}   ({len(data)} baris)")

    def pilih(self, _):
        sel = self.tree.selection()
        if sel:
            self.tulis_detail(TABEL[self.aktif]["kolom"], self.baris[sel[0]])

    def tulis_detail(self, kolom=(), row=()):
        self.t_detail.config(state="normal")
        self.t_detail.delete("1.0", "end")
        for c, v in zip(kolom, row):
            self.t_detail.insert("end", f"{c}: ", "k")
            self.t_detail.insert("end", f"{v}\n")
        self.t_detail.config(state="disabled")


if __name__ == "__main__":
    Viewer().mainloop()