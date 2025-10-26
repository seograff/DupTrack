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
import multiprocessing # <-- Nueva Importación
from itertools import repeat

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
def calcular_hash_proceso(ruta_archivo, algoritmo="md5"):
    """
    Función optimizada para ser llamada por el pool de multiprocessing.
    Devuelve la ruta y el hash calculado.
    """
    hash_func = hashlib.md5() if algoritmo == "md5" else hashlib.sha256()
    try:
        # Bloque de lectura aumentado para mejor rendimiento en E/S
        with open(ruta_archivo, "rb") as f:
            while chunk := f.read(65536): # 64KB de bloque
                hash_func.update(chunk)
        return ruta_archivo, hash_func.hexdigest()
    except Exception as e:
        print(f"No se pudo leer {ruta_archivo}: {e}")
        return ruta_archivo, None

def guardar_duplicados(tree):
    if not tree.get_children():
        messagebox.showinfo("Aviso", "No hay duplicados para guardar.")
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
            # El primer valor en el padre es el nombre amigable
            nombre_dup = tree.item(parent, "values")[0] 
            for child in tree.get_children(parent):
                # El primer valor en el hijo es la ruta completa
                ruta, size, mod_time = tree.item(child, "values") 
                writer.writerow([nombre_dup, ruta, size, mod_time])
    messagebox.showinfo("Guardado completado", f"Duplicados guardados en {file_path}")

def actualizar_barra(progress_var, progress_label, valor, mensaje=""):
    """ Actualiza la barra de progreso y el texto de la etiqueta """
    if valor < 0: valor = 0
    if valor > 100: valor = 100
    
    progress_var.set(valor)
    # Si hay mensaje, lo muestra junto al porcentaje, sino solo el porcentaje
    texto = f"{valor:.1f}%"
    if mensaje:
         texto += f" ({mensaje})"
    progress_label.config(text=texto)
    root.update_idletasks()

# Refactorizada para usar multiprocessing y filtro de tamaño
def hilo_busqueda(carpeta, algoritmo, extensiones_seleccionadas, progress_var, progress_label, tree):
    
    buscar_btn.config(state="disabled")
    archivos_por_tamano = defaultdict(list)
    archivos_a_hashear = []
    
    # 1. Escaneo inicial y agrupamiento por tamaño
    actualizar_barra(progress_var, progress_label, 5, "Escaneando archivos...")
    
    for ruta_directorio, _, nombres_archivos in os.walk(carpeta):
        for nombre in nombres_archivos:
            ruta_completa = os.path.join(ruta_directorio, nombre)
            if nombre.lower().endswith(tuple(extensiones_seleccionadas)):
                try:
                    tamano = os.path.getsize(ruta_completa)
                    archivos_por_tamano[tamano].append(ruta_completa)
                except Exception as e:
                    print(f"No se pudo obtener tamaño de {ruta_completa}: {e}")

    # 2. Aplicar filtro de tamaño y preparar lista para hashear
    for tamano, rutas in archivos_por_tamano.items():
        if len(rutas) > 1 and tamano > 0: # Solo archivos con al menos un duplicado potencial y no vacíos
            archivos_a_hashear.extend(rutas)

    total_a_hashear = len(archivos_a_hashear)
    duplicados = defaultdict(list)
    
    if total_a_hashear == 0:
        messagebox.showinfo("Búsqueda", "No se encontraron duplicados potenciales (por tamaño) o archivos relevantes.")
        tree.delete(*tree.get_children())
        actualizar_barra(progress_var, progress_label, 0)
        buscar_btn.config(state="normal")
        return
    
    # 3. Cálculo de Hash usando Multiprocessing (Aceleración clave)
    actualizar_barra(progress_var, progress_label, 10, f"Calculando Hash en {total_a_hashear} archivos...")

    try:
        # Usa un pool de procesos con el número de CPUs
        with multiprocessing.Pool(processes=os.cpu_count()) as pool:
            # map recibe una función y un iterable. repeat se usa para pasar el mismo 'algoritmo'
            resultados = pool.imap_unordered(calcular_hash_proceso, zip(archivos_a_hashear, repeat(algoritmo)))
            
            for idx, (ruta_completa, archivo_hash) in enumerate(resultados, 1):
                if archivo_hash:
                    duplicados[archivo_hash].append(ruta_completa)
                
                # Actualizar progreso en la UI (en el hilo de búsqueda)
                progress = 10 + (idx / total_a_hashear) * 85 # 85% para esta fase
                actualizar_barra(progress_var, progress_label, progress, f"{idx}/{total_a_hashear} hasheados")

    except Exception as e:
        messagebox.showerror("Error de Multiprocessing", f"Ocurrió un error en el pool de procesos: {e}")
        actualizar_barra(progress_var, progress_label, 0)
        buscar_btn.config(state="normal")
        return

    # 4. Procesamiento final y llenado de Treeview
    duplicados_finales = {k: v for k, v in duplicados.items() if len(v) > 1}
    tree.delete(*tree.get_children())
    
    for archivo_hash, rutas in duplicados_finales.items():
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

    actualizar_barra(progress_var, progress_label, 100, "Búsqueda finalizada")
    
    # Re-habilitar botón
    buscar_btn.config(state="normal")
    # Mostrar resultados en CSV/TXT
    if duplicados_finales:
        guardar_duplicados(tree)
    else:
        messagebox.showinfo("Búsqueda", "No se encontraron archivos duplicados.")
    
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
    
    # Se sigue usando threading para NO bloquear la UI mientras corre la búsqueda multiproceso.
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
    
    # Filtrar solo elementos hijos (archivos)
    archivos_a_borrar = []
    for item in selected_items:
        if tree.parent(item):
            # El primer valor es la ruta completa
            archivos_a_borrar.append(tree.item(item, "values")[0]) 
    
    if not archivos_a_borrar:
        messagebox.showinfo("Info", "Selecciona archivos individuales (elementos en el segundo nivel).")
        return
        
    confirm = messagebox.askyesno("Confirmar", f"¿Deseas eliminar los {len(archivos_a_borrar)} archivos seleccionados?")
    if not confirm:
        return
        
    eliminados = 0
    for ruta in archivos_a_borrar:
        try:
            os.remove(ruta)
            eliminados += 1
        except Exception as e:
            print(f"No se pudo eliminar {ruta}: {e}")
            
    messagebox.showinfo("Eliminación completada", f"Se eliminaron {eliminados} archivos.")
    # Ejecutar búsqueda de nuevo para actualizar el Treeview
    ejecutar_busqueda()

def borrar_todos_duplicados():
    confirm = messagebox.askyesno("Confirmar", "¿Deseas eliminar todos los duplicados dejando UNO por grupo?")
    if not confirm:
        return
    
    eliminados = 0
    for parent in tree.get_children():
        children = tree.get_children(parent)
        # Recorre todos los hijos excepto el primero (índice 0)
        for child in children[1:]:
            # El primer valor es la ruta completa
            ruta = tree.item(child, "values")[0] 
            try:
                os.remove(ruta)
                eliminados += 1
            except Exception as e:
                print(f"No se pudo eliminar {ruta}: {e}")
                
    messagebox.showinfo("Eliminación completada", f"Se eliminaron {eliminados} archivos.")
    # Ejecutar búsqueda de nuevo para actualizar el Treeview
    ejecutar_busqueda()

def ordenar_treeview(tv, col, reverse):
    l = [(tv.set(k, col), k) for k in tv.get_children('')]
    # Intenta ordenar por número (para el tamaño) o por string
    def sort_key(t):
        val = t[0]
        if 'KB' in val:
            try:
                return float(val.split()[0])
            except ValueError:
                return val
        return val

    try:
        l.sort(key=sort_key, reverse=reverse)
    except Exception:
        l.sort(reverse=reverse)
        
    for index, (val, k) in enumerate(l):
        tv.move(k, '', index)
        
    # Re-asigna el comando para alternar la dirección de ordenamiento
    tv.heading(col, command=lambda: ordenar_treeview(tv, col, not reverse))

def aplicar_hover(boton, color_normal, color_hover):
    boton.bind("<Enter>", lambda e: boton.config(bg=color_hover))
    boton.bind("<Leave>", lambda e: boton.config(bg=color_normal))

def agregar_resaltado(tv):
    def on_enter(event):
        item = tv.identify_row(event.y)
        if item:
            # Aplicar color de hover solo si es un archivo o un hash (para no superponer)
            tags = tv.item(item, "tags")
            if "archivo" in tags or "hash" in tags:
                tv.tag_configure("hover", background="#d1f0d1")
                tv.item(item, tags=("hover", "archivo" if "archivo" in tags else "hash"))
                
    def on_leave(event):
        # Restaurar los tags originales al salir
        for item in tv.get_children():
            tags = tv.item(item, "tags")
            if "hover" in tags:
                # Determinar si el tag original era 'hash' o 'archivo'
                original_tag = "hash" if "hash" in tags else "archivo"
                tv.item(item, tags=(original_tag,))
                
    tv.bind("<Motion>", on_enter)
    tv.bind("<Leave>", on_leave)

# --- GUI ---
root = tk.Tk()
root.title("DupTrack - by SEO_GRAFF")
root.geometry("1200x750")
root.minsize(1100, 700)
root.config(bg="#ecf0f1")
try:
    # Se asume que logo.ico está en la ruta de recursos
    root.iconbitmap(resource_path("logo.ico"))
except:
    pass

carpeta_var = tk.StringVar()
# Se permite al usuario elegir el algoritmo de hash
hash_var = tk.StringVar(value="md5") 
check_vars = {}

main_frame = tk.Frame(root, bg="#ecf0f1")
main_frame.pack(fill="both", expand=True)

# Panel lateral
side_panel = tk.Frame(main_frame, width=220, bg="#bdc3c7")
side_panel.pack(side="left", fill="y")
try:
    # Se asume que logo.png está en la ruta de recursos
    img = Image.open(resource_path("logo.png")).resize((120,120), Image.Resampling.LANCZOS) # Uso de Resampling.LANCZOS
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

# Algoritmo de Hash Selector
frame_hash = tk.LabelFrame(side_panel, text="Algoritmo de Hash", bg="#bdc3c7", fg="black")
frame_hash.pack(pady=10, padx=5, fill="x")
tk.Radiobutton(frame_hash, text="MD5 (Rápido)", variable=hash_var, value="md5", bg="#bdc3c7").pack(anchor="w")
tk.Radiobutton(frame_hash, text="SHA256 (Seguro)", variable=hash_var, value="sha256", bg="#bdc3c7").pack(anchor="w")


# Frame principal
content_frame = tk.Frame(main_frame, bg="#ecf0f1")
content_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)

top_frame = tk.Frame(content_frame, bg="#ecf0f1")
top_frame.pack(fill="x")
tk.Label(top_frame, text="Carpeta:", bg="#ecf0f1").pack(side="left")
tk.Entry(top_frame, textvariable=carpeta_var, width=60).pack(side="left", padx=5, fill="x", expand=True)
sel_btn = tk.Button(top_frame, text="Seleccionar", command=seleccionar_carpeta)
sel_btn.pack(side="left", padx=5)
aplicar_hover(sel_btn, sel_btn['bg'], "#bdc3c7")

frame_ext = tk.LabelFrame(content_frame, text="Extensiones a buscar", bg="#ecf0f1")
frame_ext.pack(fill="x", pady=5)
for ext in EXTENSIONES_POSIBLES:
    # Por defecto, todos seleccionados
    var = tk.BooleanVar(value=True) 
    tk.Checkbutton(frame_ext, text=ext, variable=var, bg="#ecf0f1").pack(side="left", padx=5)
    check_vars[ext] = var

# Barra de progreso
progress_frame = tk.Frame(content_frame, bg="#ecf0f1")
progress_frame.pack(fill="x", pady=5)
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(progress_frame, orient="horizontal", length=800, mode="determinate", variable=progress_var)
progress_bar.pack(fill="x")
# Se centra el texto sobre la barra
progress_label = tk.Label(progress_frame, text="0.0%", bg="#ecf0f1") 
progress_label.place(relx=0.5, rely=0.5, anchor="center")

# Treeview
frame_tree = tk.Frame(content_frame, bg="#ecf0f1")
frame_tree.pack(fill="both", expand=True, pady=5)
columns = ("Ruta completa", "Tamaño", "Fecha modificación") # Cambiado para mostrar ruta completa en columna
tree = ttk.Treeview(frame_tree, columns=columns, show="tree headings")
tree.pack(side="left", fill="both", expand=True)

# Encabezados y comandos de ordenamiento
tree.heading("#0", text="Nombre/Archivo", anchor="w")
tree.column("#0", width=400) # Columna de árbol
for col in columns:
    tree.heading(col, text=col, command=lambda c=col: ordenar_treeview(tree, c, False))
tree.column("Ruta completa", width=600, stretch=tk.YES)
tree.column("Tamaño", width=120, stretch=tk.NO)
tree.column("Fecha modificación", width=180, stretch=tk.NO)

# Etiquetas (Tags) para el resaltado
tree.tag_configure("hash", background="#d0e1ff", font=("Arial", 10, "bold")) # Padre/Hash
tree.tag_configure("archivo", background="#f7f7f7") # Hijo/Archivo
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
