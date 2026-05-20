"""
AI Encryption Detector - Professional GUI (V10 XAI Edition)
===========================================================

Enterprise Features
-------------------
✓ Explainable AI (XAI)
✓ Evidence Visualization
✓ Risk Breakdown Panel
✓ Dual Entropy Graph
✓ ΔEntropy Shock Detection
✓ Smart Override Visualization
✓ Behavioral Analysis
✓ Multi-threaded Scanning
✓ mmap-safe Large File Support
✓ Directory Drill-down
✓ Interactive Risk Dashboard
✓ Commercial EDR-style Interface
"""

import os
import sys
import json
import mmap
import threading
import queue

import customtkinter as ctk

import matplotlib
matplotlib.use("Agg")

import numpy as np

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

# =========================================================
# PROJECT IMPORTS
# =========================================================

sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

from src.crypto_features import (
    calculate_shannon_entropy
)

from src.detect_encryption import (
    load_models,
    detect_file,
    GLOBAL_SCAN_LIMIT,
)

# =========================================================
# APPEARANCE
# =========================================================

ctk.set_appearance_mode("dark")

ctk.set_default_color_theme("blue")

# =========================================================
# COLORS
# =========================================================

BG_DARK = "#0d1117"

BG_CARD = "#161b22"

BG_SIDE = "#0d1117"

ACCENT = "#58a6ff"

GREEN = "#3fb950"

RED = "#f85149"

YELLOW = "#d29922"

BLUE = "#79c0ff"

TEXT_PRI = "#e6edf3"

TEXT_SEC = "#8b949e"

BORDER = "#30363d"

# =========================================================
# CONTROLLER
# =========================================================

class ScanController:

    def __init__(self):

        self.models_loaded = False

        self.model1 = None
        self.model2 = None
        self.le2 = None

        self.cols_s1 = None
        self.cols_s2 = None

        self.metadata = {}

    # =====================================================
    # LOAD MODELS
    # =====================================================

    def load(self):

        (
            self.model1,
            self.model2,
            self.le2,
            self.cols_s1,
            self.cols_s2
        ) = load_models()

        with open(
            "models/model_metadata.json",
            "r",
            encoding="utf-8"
        ) as f:

            self.metadata = json.load(f)

        self.models_loaded = True

    # =====================================================
    # SCAN FILE
    # =====================================================

    def scan_file(self, path):

        return detect_file(
            path,
            self.model1,
            self.model2,
            self.le2,
            self.cols_s1,
            self.cols_s2
        )

    # =====================================================
    # ENTROPY PROFILE
    # =====================================================

    def compute_entropy_profile(
        self,
        path,
        window=4096,
        step=2048,
        progress_cb=None
    ):

        fsize = os.path.getsize(path)

        scan_len = min(
            fsize,
            GLOBAL_SCAN_LIMIT
        )

        entropies = []

        offsets = []

        with open(path, "rb") as f:

            with mmap.mmap(
                f.fileno(),
                0,
                access=mmap.ACCESS_READ
            ) as mm:

                total_steps = max(
                    1,
                    (scan_len - window) // step
                )

                for idx, i in enumerate(
                    range(
                        0,
                        scan_len - window,
                        step
                    )
                ):

                    chunk = mm[i:i + window]

                    ent = calculate_shannon_entropy(
                        chunk
                    )

                    entropies.append(ent)

                    offsets.append(i / 1024)

                    if progress_cb and idx % 50 == 0:

                        progress_cb(
                            idx / total_steps
                        )

        return offsets, entropies

# =========================================================
# MAIN APP
# =========================================================

class App(ctk.CTk):

    def __init__(self):

        super().__init__()

        self.title(
            "🔬 AI Encryption Detector V10"
        )

        self.geometry("1450x860")

        self.minsize(1280, 760)

        self.configure(
            fg_color=BG_DARK
        )

        self.controller = ScanController()

        self.q = queue.Queue()

        self._current_canvas = None

        self.last_dir_results = None

        self._build_layout()

        self._load_models_async()

        self.after(
            120,
            self._poll_queue
        )

    # =====================================================
    # LAYOUT
    # =====================================================

    def _build_layout(self):

        self.sidebar = ctk.CTkFrame(
            self,
            width=280,
            fg_color=BG_SIDE,
            corner_radius=0,
            border_width=1,
            border_color=BORDER
        )

        self.sidebar.pack(
            side="left",
            fill="y"
        )

        self.sidebar.pack_propagate(False)

        self.right = ctk.CTkFrame(
            self,
            fg_color=BG_DARK,
            corner_radius=0
        )

        self.right.pack(
            side="left",
            fill="both",
            expand=True
        )

        self._build_sidebar()

        self._build_main()

    # =====================================================
    # SIDEBAR
    # =====================================================

    def _build_sidebar(self):

        logo = ctk.CTkLabel(
            self.sidebar,
            text="🔬 CryptoDetect",
            text_color=ACCENT,
            font=ctk.CTkFont(
                size=24,
                weight="bold"
            )
        )

        logo.pack(
            pady=(24, 4)
        )

        sub = ctk.CTkLabel(
            self.sidebar,
            text="Enterprise XAI Engine",
            text_color=TEXT_SEC,
            font=ctk.CTkFont(
                size=11
            )
        )

        sub.pack(
            pady=(0, 22)
        )

        self.btn_file = ctk.CTkButton(
            self.sidebar,
            text="📄 Scan File",
            height=42,
            fg_color=ACCENT,
            hover_color="#1f6feb",
            command=self._on_scan_file
        )

        self.btn_file.pack(
            fill="x",
            padx=18,
            pady=(8, 6)
        )

        self.btn_dir = ctk.CTkButton(
            self.sidebar,
            text="📁 Scan Directory",
            height=42,
            fg_color="#238636",
            hover_color="#2ea043",
            command=self._on_scan_dir
        )

        self.btn_dir.pack(
            fill="x",
            padx=18,
            pady=(0, 16)
        )

        self.model_info = ctk.CTkLabel(
            self.sidebar,
            text="Loading AI models...",
            justify="left",
            wraplength=220,
            text_color=TEXT_SEC,
            font=ctk.CTkFont(size=11)
        )

        self.model_info.pack(
            padx=18,
            pady=(20, 10)
        )

        self.status_label = ctk.CTkLabel(
            self.sidebar,
            text="● Offline",
            text_color=RED
        )

        self.status_label.pack(
            side="bottom",
            pady=20
        )

    # =====================================================
    # MAIN PANEL
    # =====================================================

    def _build_main(self):

        topbar = ctk.CTkFrame(
            self.right,
            height=52,
            fg_color=BG_CARD,
            corner_radius=0
        )

        topbar.pack(fill="x")

        topbar.pack_propagate(False)

        self.file_label = ctk.CTkLabel(
            topbar,
            text="No file selected",
            text_color=TEXT_SEC
        )

        self.file_label.pack(
            side="left",
            padx=18
        )

        self.progress = ctk.CTkProgressBar(
            topbar,
            width=240
        )

        self.progress.pack(
            side="right",
            padx=18
        )

        self.progress.set(0)

        self.content = ctk.CTkScrollableFrame(
            self.right,
            fg_color=BG_DARK
        )

        self.content.pack(
            fill="both",
            expand=True,
            padx=14,
            pady=12
        )

        self.welcome = ctk.CTkLabel(
            self.content,
            text="🔬 Select a file or directory to begin analysis",
            text_color=TEXT_SEC,
            font=ctk.CTkFont(size=18)
        )

        self.welcome.pack(
            pady=140
        )

    # =====================================================
    # HELPERS
    # =====================================================

    def _card(self, parent):

        return ctk.CTkFrame(
            parent,
            fg_color=BG_CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER
        )

    def _clear_content(self):

        if self._current_canvas:

            self._current_canvas.get_tk_widget().destroy()

            self._current_canvas = None

        for w in self.content.winfo_children():

            w.destroy()

    def _kv_row(
        self,
        parent,
        key,
        value,
        color=TEXT_PRI
    ):

        row = ctk.CTkFrame(
            parent,
            fg_color="transparent"
        )

        row.pack(
            fill="x",
            padx=18,
            pady=3
        )

        ctk.CTkLabel(
            row,
            text=key,
            width=220,
            anchor="w",
            text_color=TEXT_SEC
        ).pack(side="left")

        ctk.CTkLabel(
            row,
            text=str(value),
            anchor="w",
            text_color=color,
            font=ctk.CTkFont(
                weight="bold"
            )
        ).pack(side="left")

    # =====================================================
    # LOAD MODELS
    # =====================================================

    def _load_models_async(self):

        def job():

            try:

                self.controller.load()

                self.q.put((
                    "models_ok",
                    self.controller.metadata
                ))

            except Exception as e:

                self.q.put((
                    "error",
                    str(e)
                ))

        threading.Thread(
            target=job,
            daemon=True
        ).start()

    # =====================================================
    # POLL
    # =====================================================

    def _poll_queue(self):

        try:

            while True:

                msg = self.q.get_nowait()

                self._handle_msg(msg)

        except queue.Empty:

            pass

        self.after(
            120,
            self._poll_queue
        )

    # =====================================================
    # HANDLE MSG
    # =====================================================

    def _handle_msg(self, msg):

        tag = msg[0]

        if tag == "models_ok":

            meta = msg[1]

            self.model_info.configure(
                text=(
                    f"Version: {meta.get('version', '?')}\n"
                    f"Stage1 Features: {len(self.controller.cols_s1)}\n"
                    f"Stage2 Features: {len(self.controller.cols_s2)}"
                )
            )

            self.status_label.configure(
                text="● Online",
                text_color=GREEN
            )

        elif tag == "scan_done":

            self.progress.set(1.0)

            self._show_result(
                msg[1],
                msg[2]
            )

        elif tag == "dir_done":

            self.progress.set(1.0)

            self._show_dir_results(
                msg[1]
            )

        elif tag == "progress":

            self.progress.set(msg[1])

        elif tag == "error":

            self._show_error(msg[1])

    # =====================================================
    # FILE
    # =====================================================

    def _on_scan_file(self):

        self.last_dir_results = None

        path = ctk.filedialog.askopenfilename()

        if not path:
            return

        self._start_scan(path)

    # =====================================================
    # DIRECTORY
    # =====================================================

    def _on_scan_dir(self):

        d = ctk.filedialog.askdirectory()

        if not d:
            return

        self.last_dir_results = None

        self._clear_content()

        def job():

            results = []

            files = []

            for root, _, fnames in os.walk(d):

                for fn in fnames:

                    files.append(
                        os.path.join(root, fn)
                    )

            total = max(len(files), 1)

            for idx, fp in enumerate(files):

                try:

                    r = self.controller.scan_file(fp)

                    r["_filepath"] = fp

                    results.append(r)

                except Exception as e:

                    results.append({
                        "file": os.path.basename(fp),
                        "error": str(e)
                    })

                self.q.put((
                    "progress",
                    (idx + 1) / total
                ))

            self.q.put((
                "dir_done",
                results
            ))

        threading.Thread(
            target=job,
            daemon=True
        ).start()

    # =====================================================
    # START SCAN
    # =====================================================

    def _start_scan(self, path):

        self._clear_content()

        self.file_label.configure(
            text=path
        )

        loading = ctk.CTkLabel(
            self.content,
            text="⏳ Scanning...",
            text_color=YELLOW,
            font=ctk.CTkFont(
                size=20,
                weight="bold"
            )
        )

        loading.pack(
            pady=80
        )

        def job():
            self.q.put(("progress", 0.15))

            try:
                # Chạy backend
                result = self.controller.scan_file(path)
                
                self.q.put(("progress", 0.70))

                try:
                    offsets, ents = self.controller.compute_entropy_profile(path)
                except Exception:
                    offsets, ents = [], []

                self.q.put((
                    "scan_done",
                    result,
                    (offsets, ents)
                ))

            except Exception as e:
                # NẾU BACKEND LỖI, IN RA TERMINAL VÀ BÁO LÊN GUI
                import traceback
                traceback.print_exc() 
                self.q.put((
                    "error",
                    f"System Error: {str(e)}"
                ))

        threading.Thread(
            target=job,
            daemon=True
        ).start()

        def job():

            self.q.put(("progress", 0.15))

            result = self.controller.scan_file(path)

            self.q.put(("progress", 0.70))

            try:

                offsets, ents = (
                    self.controller.compute_entropy_profile(path)
                )

            except Exception:

                offsets, ents = [], []

            self.q.put((
                "scan_done",
                result,
                (offsets, ents)
            ))

        threading.Thread(
            target=job,
            daemon=True
        ).start()

    # =====================================================
    # SHOW RESULT
    # =====================================================

    def _show_result(
        self,
        r,
        entropy_data
    ):

        self._clear_content()

        if self.last_dir_results is not None:

            btn_back = ctk.CTkButton(
                self.content,
                text="⬅ Quay lại danh sách",
                fg_color=BG_CARD,
                hover_color=BORDER,
                text_color=TEXT_PRI,
                command=self._on_back_to_dir
            )

            btn_back.pack(
                anchor="w",
                pady=(0, 10)
            )

        if "error" in r:

            self._show_error(r["error"])

            return

        encrypted = r.get(
            "encrypted",
            False
        )

        # =================================================
        # VERDICT CARD
        # =================================================

        card = self._card(self.content)

        card.pack(
            fill="x",
            pady=(0, 10)
        )

        verdict = (
            "🔒 ENCRYPTED"
            if encrypted
            else "✅ SAFE"
        )

        color = (
            RED
            if encrypted
            else GREEN
        )

        ctk.CTkLabel(
            card,
            text=verdict,
            text_color=color,
            font=ctk.CTkFont(
                size=30,
                weight="bold"
            )
        ).pack(
            pady=(18, 10)
        )

        self._kv_row(
            card,
            "File",
            r.get("file", "?")
        )

        self._kv_row(
            card,
            "Size",
            f"{r.get('size', 0):,} bytes"
        )

        if encrypted:

            self._kv_row(
                card,
                "Behavior Type",
                r.get("behavior_type", "?"),
                ACCENT
            )

            risk = r.get(
                "risk_level",
                0
            )

            risk_color = (
                RED if risk >= 0.85
                else YELLOW if risk >= 0.6
                else GREEN
            )

            self._kv_row(
                card,
                "Final Risk",
                f"{risk:.4f}",
                risk_color
            )

            self._kv_row(
                card,
                "Encrypted Probability",
                f"{r.get('prob_enc', 0):.4f}",
                RED
            )

        else:

            self._kv_row(
                card,
                "Probability Safe",
                f"{r.get('prob_safe', 0):.4f}",
                GREEN
            )

        # =================================================
        # EVIDENCE PANEL
        # =================================================

        evidence = r.get(
            "evidence",
            []
        )

        if evidence:

            ev_card = self._card(self.content)

            ev_card.pack(
                fill="x",
                pady=(0, 10)
            )

            ctk.CTkLabel(
                ev_card,
                text="🧠 Explainable AI Evidence",
                text_color=ACCENT,
                font=ctk.CTkFont(
                    size=17,
                    weight="bold"
                )
            ).pack(
                pady=(16, 10)
            )

            for ev in evidence:

                sev = ev.get(
                    "severity",
                    "low"
                )

                if sev == "high":

                    c = RED

                    icon = "🚨"

                elif sev == "medium":

                    c = YELLOW

                    icon = "⚠️"

                else:

                    c = BLUE

                    icon = "ℹ️"

                text = ev.get(
                    "description",
                    "unknown evidence"
                )

                lbl = ctk.CTkLabel(
                    ev_card,
                    text=f"{icon} {text}",
                    text_color=c,
                    justify="left",
                    anchor="w"
                )

                lbl.pack(
                    anchor="w",
                    padx=20,
                    pady=3
                )

        # =================================================
        # RISK BREAKDOWN
        # =================================================

        rb = r.get(
            "risk_breakdown",
            {}
        )

        if rb:

            risk_card = self._card(self.content)

            risk_card.pack(
                fill="x",
                pady=(0, 10)
            )

            ctk.CTkLabel(
                risk_card,
                text="📊 Risk Breakdown",
                text_color=ACCENT,
                font=ctk.CTkFont(
                    size=17,
                    weight="bold"
                )
            ).pack(
                pady=(16, 10)
            )

            rows = [

                (
                    "AI Risk",
                    rb.get("ai_risk", 0)
                ),

                (
                    "Behavior Score",
                    rb.get("behavior_score", 0)
                ),

                (
                    "Structural Damage",
                    rb.get("structural_damage", 0)
                ),

                (
                    "Semantic Anomaly",
                    rb.get("semantic_anomaly", 0)
                ),

                (
                    "Final Risk",
                    rb.get("final_risk", 0)
                ),
            ]

            for k, v in rows:

                row = ctk.CTkFrame(
                    risk_card,
                    fg_color="transparent"
                )

                row.pack(
                    fill="x",
                    padx=16,
                    pady=4
                )

                ctk.CTkLabel(
                    row,
                    text=k,
                    width=200,
                    anchor="w",
                    text_color=TEXT_SEC
                ).pack(side="left")

                bar = ctk.CTkProgressBar(
                    row,
                    width=260
                )

                bar.pack(
                    side="left",
                    padx=8
                )

                bar.set(min(v, 1.0))

                color_text = (
                    RED if v >= 0.8
                    else YELLOW if v >= 0.5
                    else GREEN
                )

                ctk.CTkLabel(
                    row,
                    text=f"{v:.4f}",
                    text_color=color_text
                ).pack(side="left")

        # =================================================
        # ENTROPY PROFILE
        # =================================================

        ep = r.get(
            "entropy_profile",
            {}
        )

        if ep:

            ep_card = self._card(self.content)

            ep_card.pack(
                fill="x",
                pady=(0, 10)
            )

            ctk.CTkLabel(
                ep_card,
                text="🌡️ Entropy Profile",
                text_color=ACCENT,
                font=ctk.CTkFont(
                    size=17,
                    weight="bold"
                )
            ).pack(
                pady=(16, 10)
            )

            metrics = [

                ("Entropy Mean", ep.get("mean", 0)),
                ("Entropy Std", ep.get("std", 0)),
                ("Entropy Range", ep.get("range", 0)),
                ("Entropy Peaks", ep.get("spike_count", 0)),
                ("High Entropy Ratio", ep.get("high_entropy_ratio", 0)),
                ("Low Entropy Ratio", ep.get("low_entropy_ratio", 0)),
            ]

            for k, v in metrics:

                self._kv_row(
                    ep_card,
                    k,
                    f"{v:.4f}"
                )

        # =================================================
        # DISTRIBUTION
        # =================================================

        dist = r.get(
            "algorithm_distribution",
            {}
        )

        if dist:

            dist_card = self._card(self.content)

            dist_card.pack(
                fill="x",
                pady=(0, 10)
            )

            ctk.CTkLabel(
                dist_card,
                text="📈 Behavioral Distribution",
                text_color=ACCENT,
                font=ctk.CTkFont(
                    size=17,
                    weight="bold"
                )
            ).pack(
                pady=(16, 10)
            )

            for algo, ratio in dist.items():

                row = ctk.CTkFrame(
                    dist_card,
                    fg_color="transparent"
                )

                row.pack(
                    fill="x",
                    padx=16,
                    pady=4
                )

                ctk.CTkLabel(
                    row,
                    text=algo,
                    width=180,
                    anchor="w"
                ).pack(side="left")

                bar = ctk.CTkProgressBar(
                    row
                )

                bar.pack(
                    side="left",
                    fill="x",
                    expand=True,
                    padx=8
                )

                bar.set(ratio)

                ctk.CTkLabel(
                    row,
                    text=f"{ratio * 100:.1f}%"
                ).pack(side="left")

        # =================================================
        # ENTROPY CHART
        # =================================================

        offsets, ents = entropy_data

        if offsets and ents:

            chart_card = self._card(self.content)

            chart_card.pack(
                fill="x",
                pady=(0, 10)
            )

            ctk.CTkLabel(
                chart_card,
                text="📉 Entropy & ΔEntropy Analysis",
                text_color=ACCENT,
                font=ctk.CTkFont(
                    size=17,
                    weight="bold"
                )
            ).pack(
                pady=(16, 6)
            )

            self._draw_entropy_chart(
                chart_card,
                offsets,
                ents
            )

    # =====================================================
    # ENTROPY CHART
    # =====================================================

    def _draw_entropy_chart(
        self,
        parent,
        offsets,
        entropies
    ):

        fig = Figure(
            figsize=(11, 4),
            dpi=100,
            facecolor=BG_CARD
        )

        ax = fig.add_subplot(111)

        ax.set_facecolor(BG_DARK)

        x = np.array(offsets)

        y = np.array(entropies)

        delta = np.abs(
            np.diff(y)
        )

        delta = np.insert(
            delta,
            0,
            0
        )

        # =================================================
        # MAIN ENTROPY
        # =================================================

        ax.plot(
            x,
            y,
            linewidth=1.6,
            label="Entropy"
        )

        ax.fill_between(
            x,
            y,
            alpha=0.15
        )

        # =================================================
        # DELTA ENTROPY
        # =================================================

        ax.plot(
            x,
            delta,
            linestyle="--",
            linewidth=1.0,
            alpha=0.9,
            label="ΔEntropy"
        )

        # =================================================
        # RISK ZONES
        # =================================================

        ax.axhspan(
            0,
            4.5,
            color=GREEN,
            alpha=0.04
        )

        ax.axhspan(
            4.5,
            7.0,
            color=YELLOW,
            alpha=0.05
        )

        ax.axhspan(
            7.0,
            8.2,
            color=RED,
            alpha=0.06
        )

        xmax = x[-1] if len(x) else 1

        ax.text(
            xmax * 0.98,
            2.0,
            "SAFE",
            color=GREEN,
            ha="right",
            alpha=0.5
        )

        ax.text(
            xmax * 0.98,
            5.6,
            "SUSPICIOUS",
            color=YELLOW,
            ha="right",
            alpha=0.5
        )

        ax.text(
            xmax * 0.98,
            7.6,
            "ENCRYPTED",
            color=RED,
            ha="right",
            alpha=0.6
        )

        ax.set_ylim(0, 8.2)

        ax.set_xlabel(
            "Offset (KB)"
        )

        ax.set_ylabel(
            "Entropy"
        )

        ax.grid(alpha=0.12)

        ax.legend()

        fig.tight_layout()

        canvas = FigureCanvasTkAgg(
            fig,
            master=parent
        )

        canvas.draw()

        canvas.get_tk_widget().pack(
            fill="x",
            padx=12,
            pady=10
        )

        self._current_canvas = canvas

    # =====================================================
    # DIRECTORY RESULTS
    # =====================================================

    def _show_dir_results(self, results):

        self.last_dir_results = results

        self._clear_content()

        summary = self._card(self.content)

        summary.pack(
            fill="x",
            pady=(0, 10)
        )

        enc_count = sum(
            1 for r in results
            if r.get("encrypted")
        )

        safe_count = sum(
            1 for r in results
            if "encrypted" in r
            and not r["encrypted"]
        )

        self._kv_row(
            summary,
            "Total Files",
            len(results)
        )

        self._kv_row(
            summary,
            "Encrypted",
            enc_count,
            RED
        )

        self._kv_row(
            summary,
            "Safe",
            safe_count,
            GREEN
        )

        for r in results:

            fname = r.get(
                "file",
                "?"
            )

            if r.get("encrypted"):

                risk = r.get(
                    "risk_level",
                    0
                )

                behavior = r.get(
                    "behavior_type",
                    "Unknown"
                )

                text = (
                    f"🔒 {fname}    "
                    f"{behavior}    "
                    f"{risk:.2f}"
                )

                color = RED

            else:

                text = f"✅ {fname}"

                color = GREEN

            btn = ctk.CTkButton(
                self.content,
                text=text,
                fg_color="transparent",
                hover_color=BG_CARD,
                text_color=color,
                anchor="w",
                command=lambda f=r.get("_filepath"): self._start_scan(f)
            )

            btn.pack(
                fill="x",
                pady=2
            )

    # =====================================================
    # BACK TO DIR
    # =====================================================

    def _on_back_to_dir(self):

        if self.last_dir_results is not None:

            self._show_dir_results(self.last_dir_results)

    # =====================================================
    # ERROR
    # =====================================================

    def _show_error(self, msg):

        self._clear_content()

        if self.last_dir_results is not None:

            btn_back = ctk.CTkButton(
                self.content,
                text="⬅ Quay lại danh sách",
                fg_color=BG_CARD,
                hover_color=BORDER,
                text_color=TEXT_PRI,
                command=self._on_back_to_dir
            )

            btn_back.pack(
                anchor="w",
                pady=(0, 10)
            )

        card = self._card(self.content)

        card.pack(
            fill="x",
            pady=20
        )

        ctk.CTkLabel(
            card,
            text=f"❌ {msg}",
            text_color=RED,
            font=ctk.CTkFont(
                size=15
            )
        ).pack(
            pady=20
        )

# =========================================================
# MAIN
# =========================================================

def main():

    app = App()

    app.mainloop()

# =========================================================
# ENTRY
# =========================================================

if __name__ == "__main__":

    main()