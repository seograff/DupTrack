import os
import sys
import hashlib
from collections import defaultdict
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
from datetime import datetime
import csv
from PIL import Image, ImageTk

# --- Configuración ---
EXTENSIONES_POSIBLES = [".exe", ".msi", ".rar", ".zip", ".7z"]

# --- Función para rutas de recursos dentro del exe ---
def resource_path(relative_path):
    """ Devuelve la ruta absoluta para recursos empaquetados """
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- Funciones ---
def calcular_hash(ruta_archivo, algoritmo="md5"):
    hash_func = hashlib.md5() if algoritmo == "md5" else hashlib.sha256()
    try:
        with open(ruta_archivo, "rb") as f:
            while chunk := f.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        print(f"No se pudo leer {ruta_archivo}: {e}")
        return None

def guardar_duplicados(tree):
    if not tree.get_children():
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV", "*.csv"), ("Texto", "*.txt")],
                                             title="Guardar duplicados como CSV o TXT")
    if not file_path:
        return
    with open(file_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, delimiter=',' if file_path.endswith(".csv") else '\t')
        writer.writerow(["Nombre/Archivo", "Ruta completa", "Tamaño", "Fecha modificación"])
        for parent in tree.get_children():
            nombre_dup = tree.item(parent, "values")[0]
            for child in tree.get_children(parent):
                ruta, size, mod_time = tree.item(child, "values")
                writer.writerow([nombre_dup, ruta, size, mod_time])
    messagebox.showinfo("Guardado completado", f"Duplicados guardados en {file_path}")

def actualizar_barra(progress_var, progress_label, valor):
    progress_var.set(valor)
    progress_label.config(text=f"{valor:.1f}%")
    root.update_idletasks()

def hilo_busqueda(carpeta, algoritmo, extensiones_seleccionadas, progress_var, progress_label, tree):
    archivos = defaultdict(list)
    archivos_relevantes = []

    for ruta_directorio, _, nombres_archivos in os.walk(carpeta):
        for nombre in nombres_archivos:
            if nombre.lower().endswith(tuple(extensiones_seleccionadas)):
                archivos_relevantes.append(os.path.join(ruta_directorio, nombre))

    total = len(archivos_relevantes)
    for idx, ruta_completa in enumerate(archivos_relevantes, 1):
        archivo_hash = calcular_hash(ruta_completa, algoritmo)
        if archivo_hash:
            archivos[archivo_hash].append(ruta_completa)
        progress = (idx / total) * 100
        actualizar_barra(progress_var, progress_label, progress)

    duplicados = {k: v for k, v in archivos.items() if len(v) > 1}

    tree.delete(*tree.get_children())
    for archivo_hash, rutas in duplicados.items():
        nombre_amigable = os.path.basename(rutas[0])
        parent = tree.insert("", "end", values=(nombre_amigable, "", ""), tags=("hash",))
        for r in rutas:
            try:
                size = os.path.getsize(r)
                size_kb = f"{size/1024:.2f} KB"
                mod_time = datetime.fromtimestamp(os.path.getmtime(r)).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                size_kb = "N/A"
                mod_time = "N/A"
            tree.insert(parent, "end", values=(r, size_kb, mod_time), tags=("archivo",))

    actualizar_barra(progress_var, progress_label, 100)
    buscar_btn.config(state="normal")
    guardar_duplicados(tree)
    actualizar_barra(progress_var, progress_label, 0)

def ejecutar_busqueda():
    carpeta = carpeta_var.get()
    if not carpeta:
        messagebox.showwarning("Aviso", "Selecciona una carpeta.")
        return
    extensiones_seleccionadas = [ext for ext, var in check_vars.items() if var.get()]
    if not extensiones_seleccionadas:
        messagebox.showwarning("Aviso", "Selecciona al menos una extensión.")
        return
    algoritmo = hash_var.get()
    buscar_btn.config(state="disabled")
    threading.Thread(target=hilo_busqueda, args=(carpeta, algoritmo, extensiones_seleccionadas,
                                                 progress_var, progress_label, tree), daemon=True).start()

def seleccionar_carpeta():
    carpeta = filedialog.askdirectory()
    if carpeta:
        carpeta_var.set(carpeta)

def borrar_seleccionados():
    selected_items = tree.selection()
    if not selected_items:
        messagebox.showinfo("Info", "No hay elementos seleccionados.")
        return
    confirm = messagebox.askyesno("Confirmar", "¿Deseas eliminar los archivos seleccionados?")
    if not confirm:
        return
    eliminados = 0
    for item in selected_items:
        if tree.parent(item):
            ruta = tree.item(item, "values")[0]
            try:
                os.remove(ruta)
                eliminados += 1
            except Exception as e:
                print(f"No se pudo eliminar {ruta}: {e}")
    messagebox.showinfo("Eliminación completada", f"Se eliminaron {eliminados} archivos.")
    ejecutar_busqueda()

def borrar_todos_duplicados():
    confirm = messagebox.askyesno("Confirmar", "¿Deseas eliminar todos los duplicados dejando uno por grupo?")
    if not confirm:
        return
    eliminados = 0
    for parent in tree.get_children():
        children = tree.get_children(parent)
        for child in children[1:]:
            ruta = tree.item(child, "values")[0]
            try:
                os.remove(ruta)
                eliminados += 1
            except Exception as e:
                print(f"No se pudo eliminar {ruta}: {e}")
    messagebox.showinfo("Eliminación completada", f"Se eliminaron {eliminados} archivos.")
    ejecutar_busqueda()

def ordenar_treeview(tv, col, reverse):
    l = [(tv.set(k, col), k) for k in tv.get_children('')]
    try:
        l.sort(key=lambda t: float(t[0].split()[0]) if 'KB' in t[0] else t[0], reverse=reverse)
    except Exception:
        l.sort(reverse=reverse)
    for index, (val, k) in enumerate(l):
        tv.move(k, '', index)
    tv.heading(col, command=lambda: ordenar_treeview(tv, col, not reverse))

def aplicar_hover(boton, color_normal, color_hover):
    boton.bind("<Enter>", lambda e: boton.config(bg=color_hover))
    boton.bind("<Leave>", lambda e: boton.config(bg=color_normal))

def agregar_resaltado(tv):
    def on_enter(event):
        item = tv.identify_row(event.y)
        if item:
            tv.tag_configure("hover", background="#d1f0d1")
            tv.item(item, tags=("hover",))
    def on_leave(event):
        for item in tv.get_children():
            tags = tv.item(item, "tags")
            if "hover" in tags:
                tv.item(item, tags=("hash" if "hash" in tags else "archivo",))
    tv.bind("<Motion>", on_enter)
    tv.bind("<Leave>", on_leave)

# --- GUI ---
root = tk.Tk()
root.title("DupTrack - by SEO_GRAFF")
root.geometry("1200x750")
root.minsize(1100, 700)
root.config(bg="#ecf0f1")
try:
    root.iconbitmap(resource_path("logo.ico"))
except:
    pass

carpeta_var = tk.StringVar()
hash_var = tk.StringVar(value="md5")
check_vars = {}

main_frame = tk.Frame(root, bg="#ecf0f1")
main_frame.pack(fill="both", expand=True)

# Panel lateral
side_panel = tk.Frame(main_frame, width=220, bg="#bdc3c7")
side_panel.pack(side="left", fill="y")
try:
    img = Image.open(resource_path("logo.png")).resize((120,120), Image.ANTIALIAS)
    logo_img = ImageTk.PhotoImage(img)
    tk.Label(side_panel, image=logo_img, bg="#bdc3c7").pack(pady=20)
except:
    pass

buscar_btn = tk.Button(side_panel, text="Buscar duplicados", command=ejecutar_busqueda,
                       bg="#3498db", fg="white", relief="raised", width=18)
buscar_btn.pack(pady=10)
aplicar_hover(buscar_btn, "#3498db", "#2980b9")

borrar_sel_btn = tk.Button(side_panel, text="Borrar seleccionados", command=borrar_seleccionados,
                           bg="#7F8C8D", fg="white", relief="raised", width=18)
borrar_sel_btn.pack(pady=10)
aplicar_hover(borrar_sel_btn, "#7F8C8D", "#636e72")

borrar_todos_btn = tk.Button(side_panel, text="Borrar todos duplicados", command=borrar_todos_duplicados,
                             bg="#7F8C8D", fg="white", relief="raised", width=18)
borrar_todos_btn.pack(pady=10)
aplicar_hover(borrar_todos_btn, "#7F8C8D", "#636e72")

# Frame principal
content_frame = tk.Frame(main_frame, bg="#ecf0f1")
content_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

top_frame = tk.Frame(content_frame, bg="#ecf0f1")
top_frame.pack(fill="x")
tk.Label(top_frame, text="Carpeta:", bg="#ecf0f1").pack(side="left")
tk.Entry(top_frame, textvariable=carpeta_var, width=60).pack(side="left", padx=5)
sel_btn = tk.Button(top_frame, text="Seleccionar", command=seleccionar_carpeta)
sel_btn.pack(side="left", padx=5)
aplicar_hover(sel_btn, sel_btn['bg'], "#bdc3c7")

frame_ext = tk.LabelFrame(content_frame, text="Extensiones a buscar", bg="#ecf0f1")
frame_ext.pack(fill="x", pady=5)
for ext in EXTENSIONES_POSIBLES:
    var = tk.BooleanVar(value=True)
    tk.Checkbutton(frame_ext, text=ext, variable=var, bg="#ecf0f1").pack(side="left", padx=5)
    check_vars[ext] = var

# Barra de progreso
progress_frame = tk.Frame(content_frame, bg="#ecf0f1")
progress_frame.pack(fill="x", pady=5)
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=800, mode="determinate", variable=progress_var)
progress_bar.pack(fill="x")
progress_label = tk.Label(progress_frame, text="0.0%", bg="#ecf0f1")
progress_label.place(relx=0.5, rely=0.5, anchor="center")

# Treeview
frame_tree = tk.Frame(content_frame, bg="#ecf0f1")
frame_tree.pack(fill="both", expand=True, pady=5)
columns = ("Nombre/Archivo", "Tamaño", "Fecha modificación")
tree = ttk.Treeview(frame_tree, columns=columns, show="tree headings")
tree.pack(side="left", fill="both", expand=True)
for col in columns:
    tree.heading(col, text=col, command=lambda c=col: ordenar_treeview(tree, c, False))
tree.column("Nombre/Archivo", width=600)
tree.column("Tamaño", width=120)
tree.column("Fecha modificación", width=180)
tree.tag_configure("hash", background="#d0e1ff")
tree.tag_configure("archivo", background="#f7f7f7")
agregar_resaltado(tree)

scrollbar_v = tk.Scrollbar(frame_tree, orient="vertical", command=tree.yview)
scrollbar_v.pack(side="right", fill="y")
tree.configure(yscrollcommand=scrollbar_v.set)
scrollbar_h = tk.Scrollbar(content_frame, orient="horizontal", command=tree.xview)
scrollbar_h.pack(fill="x")
tree.configure(xscrollcommand=scrollbar_h.set)

footer_label = tk.Label(root, text="Desarrollado por SEO_GRAFF", font=("Arial", 9, "italic"), bg="#ecf0f1")
footer_label.pack(side="bottom", pady=5)

root.mainloop()
