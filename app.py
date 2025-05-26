import tkinter as tk
from tkinter import filedialog, ttk, messagebox
import sqlite3
import os
from datetime import datetime
import subprocess
import tempfile
import time

DB_PATH = 'csd.db'


def insert_algoritmi_default():
    algoritmi_default = [
        ('AES', 'simetric', 'Advanced Encryption Standard'),
        ('DES', 'simetric', 'Data Encryption Standard'),
        ('ChaCha20', 'simetric', 'Stream cipher developed by Daniel J. Bernstein'),
        ('RSA', 'asimetric', 'Rivest–Shamir–Adleman cryptosystem'),
        ('AES(GNU PG)', 'simetric','Advanced Encryption Standard'),
        ('3DES(GNU PG)', 'simetric', 'Data Encryption Standard'),
        ('RSA(GNU PG)', 'asimetric', 'Rivest–Shamir–Adleman cryptosystem')]

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for nume, tip, descriere in algoritmi_default:
        cursor.execute("SELECT COUNT(*) FROM Algoritmi WHERE nume = ?", (nume,))
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO Algoritmi (nume, tip, descriere)
                VALUES (?, ?, ?)
            """, (nume, tip, descriere))
    conn.commit()
    conn.close()


def get_fisiere_from_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, nume_original FROM Fisiere")
    fisiere = cursor.fetchall()
    conn.close()
    return fisiere


def insert_fisier_in_db(filepath):
    if not os.path.isfile(filepath):
        messagebox.showerror("Eroare", "Fișierul nu există.")
        return

    nume_original = os.path.basename(filepath)
    dimensiune = os.path.getsize(filepath)
    cale_fisier = filepath
    data_crearii = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO Fisiere (cale_fisier, nume_original, dimensiune, stare, data_crearii)
        VALUES (?, ?, ?, ?, ?)
    """, (cale_fisier, nume_original, dimensiune, 'decriptat', data_crearii))
    conn.commit()
    conn.close()

    messagebox.showinfo("Succes", f"Fisierul '{nume_original}' a fost adăugat.")
    update_dropdown()


def selecteaza_fisier():
    filepath = filedialog.askopenfilename()
    if filepath:
        insert_fisier_in_db(filepath)


def update_dropdown():
    fisiere = get_fisiere_from_db()
    dropdown['values'] = [f"{f[0]} - {f[1]}" for f in fisiere]
    if fisiere:
        dropdown.current(0)


def get_algoritmi_from_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, nume, tip FROM Algoritmi")
    algoritmi = cursor.fetchall()
    conn.close()
    return algoritmi


def update_algoritmi_dropdown():
    algoritmi = get_algoritmi_from_db()
    algoritm_combobox['values'] = [f"{a[0]} - {a[1]} ({a[2]})" for a in algoritmi]
    if algoritmi:
        algoritm_combobox.current(0)


def get_chei_from_db(algoritm_id, fisier_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, tip_cheie, valoare_cheie1, valoare_cheie2 
        FROM Chei
        WHERE algoritm_id = ? AND fisier_id = ?
    """, (algoritm_id, fisier_id))
    chei = cursor.fetchall()
    conn.close()
    return chei


def update_chei_dropdown(event=None):
    try:
        selected_alg = algoritm_combobox.get()
        algoritm_id = int(selected_alg.split(" - ")[0])
        selected_fisier = dropdown.get()
        fisier_id = int(selected_fisier.split(" - ")[0])
    except:
        cheie_combobox.set("Selectie invalida")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT tip FROM Algoritmi WHERE id = ?", (algoritm_id,))
    result = cursor.fetchone()
    conn.close()

    if result:
        tip_alg = result[0]
        if tip_alg == "simetric":
            btn_adauga_cheie.config(state="normal", bg="white")
            btn_genereaza_chei.config(state="disabled", bg="lightgray")
        else:
            btn_adauga_cheie.config(state="disabled", bg="lightgray")
            btn_genereaza_chei.config(state="normal", bg="white")

    chei = get_chei_from_db(algoritm_id, fisier_id)
    print(chei)
    cheie_combobox['values'] = [
        f"{c[0]} - {c[1]}: {c[2][:10]}..." for c in chei
    ]
    if chei:
        cheie_combobox.current(0)
    else:
        cheie_combobox.set("Fara chei disponibile")


# def genereaza_chei_asimetrice():
#     try:
#         algoritm_id = int(algoritm_combobox.get().split(" - ")[0])
#         fisier_id = int(dropdown.get().split(" - ")[0])
#     except:
#         messagebox.showerror("Eroare", "Selecteaza un algoritm si un fisier.")
#         return
#
#     try:
#         with tempfile.NamedTemporaryFile(delete=False) as priv_file, \
#                 tempfile.NamedTemporaryFile(delete=False) as pub_file:
#
#             priv_path = priv_file.name
#             pub_path = pub_file.name
#
#         subprocess.run(["openssl", "genrsa", "-out", priv_path, "2048"], check=True)
#
#         subprocess.run(["openssl", "rsa", "-in", priv_path, "-pubout", "-out", pub_path], check=True)
#
#         with open(priv_path, "r") as f:
#             private_key = f.read()
#
#         with open(pub_path, "r") as f:
#             public_key = f.read()
#
#         conn = sqlite3.connect(DB_PATH)
#         cursor = conn.cursor()
#         cursor.execute("""
#             INSERT INTO Chei (algoritm_id, fisier_id, tip_cheie, valoare_cheie1, valoare_cheie2, observatii)
#             VALUES (?, ?, ?, ?, ?, ?)
#         """, (algoritm_id, fisier_id, "asimetric", public_key, private_key, "Generat cu OpenSSL"))
#         conn.commit()
#         conn.close()
#
#         update_chei_dropdown()
#         messagebox.showinfo("Succes", "Cheile asimetrice au fost generate și salvate cu succes.")
#
#     except subprocess.CalledProcessError as e:
#         messagebox.showerror("Eroare OpenSSL", f"A apărut o eroare la generarea cheilor:\n{e}")
#     except Exception as e:
#         messagebox.showerror("Eroare", f"Eroare neașteptată:\n{e}")
def genereaza_chei_asimetrice():
    try:
        algoritm_id = int(algoritm_combobox.get().split(" - ")[0])
        fisier_id = int(dropdown.get().split(" - ")[0])
    except:
        messagebox.showerror("Eroare", "Selectează un algoritm și un fișier.")
        return

    try:
        if algoritm_id == 4:
            with tempfile.NamedTemporaryFile(delete=False) as priv_file, \
                    tempfile.NamedTemporaryFile(delete=False) as pub_file:

                priv_path = priv_file.name
                pub_path = pub_file.name

            subprocess.run(["openssl", "genrsa", "-out", priv_path, "2048"], check=True)
            subprocess.run(["openssl", "rsa", "-in", priv_path, "-pubout", "-out", pub_path], check=True)

            with open(priv_path, "r") as f:
                private_key = f.read()
            with open(pub_path, "r") as f:
                public_key = f.read()

            observatii = "Chei generate cu OpenSSL"

        elif algoritm_id == 8:
            nume_utilizator = "razvan"
            email_utilizator = f"razvan-adrian.hordila@student.tuiasi.ro"

            batch_config = f"""
            %no-protection
            Key-Type: RSA
            Key-Length: 2048
            Subkey-Type: RSA
            Subkey-Length: 2048
            Name-Real: {nume_utilizator}
            Name-Email: {email_utilizator}
            Expire-Date: 0
            %commit
            """

            with tempfile.NamedTemporaryFile("w+", delete=False) as f:
                f.write(batch_config)
                config_path = f.name

            subprocess.run(["gpg", "--batch", "--gen-key", config_path], check=True)

            pub_export = subprocess.check_output(["gpg", "--armor", "--export", email_utilizator])
            priv_export = subprocess.check_output(["gpg", "--armor", "--export-secret-key", email_utilizator])

            public_key = pub_export.decode("utf-8")
            private_key = priv_export.decode("utf-8")

            observatii = f"Chei generate cu GnuPG pentru {email_utilizator}"

        else:
            messagebox.showerror("Eroare", f"Algoritm ID necunoscut: {algoritm_id}")
            return

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Chei (algoritm_id, fisier_id, tip_cheie, valoare_cheie1, valoare_cheie2, observatii)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            algoritm_id, fisier_id, "asimetric",
            public_key, private_key, observatii
        ))
        conn.commit()
        conn.close()

        update_chei_dropdown()
        messagebox.showinfo("Succes", "Cheile au fost generate și salvate cu succes.")

    except subprocess.CalledProcessError as e:
        messagebox.showerror("Eroare subprocess", f"A apărut o eroare la generarea cheilor:\n{e}")
    except Exception as e:
        messagebox.showerror("Eroare", f"Eroare neașteptată:\n{e}")


def open_add_key_window():
    try:
        algoritm_id = int(algoritm_combobox.get().split(" - ")[0])
        fisier_id = int(dropdown.get().split(" - ")[0])
    except:
        messagebox.showerror("Eroare", "Selectează un algoritm și un fișier.")
        return

    window = tk.Toplevel(root)
    window.title("Adauga Cheie Simetrica")
    window.geometry("700x300")

    tk.Label(window, text="Valoare Cheie:").pack()
    entry_cheie1 = tk.Entry(window, width=50)
    entry_cheie1.pack(pady=5)

    tk.Label(window, text="Observatii:").pack()
    entry_obs = tk.Entry(window, width=50)
    entry_obs.pack(pady=5)

    def salveaza_cheia():
        cheie1 = entry_cheie1.get().strip()
        observatii = entry_obs.get().strip() or None

        if not cheie1:
            messagebox.showerror("Eroare", "Valoarea cheii este obligatorie.")
            return

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT tip FROM Algoritmi WHERE id = ?", (algoritm_id,))
        rezultat = cursor.fetchone()
        if not rezultat or rezultat[0] != "simetric":
            messagebox.showerror("Eroare", "Algoritmul nu este de tip simetric.")
            conn.close()
            return

        cursor.execute("""
            INSERT INTO Chei (algoritm_id, fisier_id, tip_cheie, valoare_cheie1, observatii)
            VALUES (?, ?, ?, ?, ?)
        """, (algoritm_id, fisier_id, "simetric", cheie1, observatii))

        conn.commit()
        conn.close()
        window.destroy()
        update_chei_dropdown()
        messagebox.showinfo("Succes", "Cheia a fost adăugată cu succes.")

    tk.Button(window, text="Salveaza", command=salveaza_cheia).pack(pady=10)


def cripteaza_fisier():
    try:
        fisier_id = int(dropdown.get().split(" - ")[0])
        algoritm_id = int(algoritm_combobox.get().split(" - ")[0])
        cheie_id = int(cheie_combobox.get().split(" - ")[0])
        print(algoritm_id)
    except:
        messagebox.showerror("Eroare", "Asigură-te că ai selectat fișierul, algoritmul și cheia.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT cale_fisier, nume_original FROM Fisiere WHERE id = ?", (fisier_id,))
    fisier_data = cursor.fetchone()
    if not fisier_data:
        messagebox.showerror("Eroare", "Fișierul nu a fost găsit.")
        conn.close()
        return

    cale_input = fisier_data[0]
    nume_original = fisier_data[1]
    nume_criptat = f"{os.path.splitext(nume_original)[0]}_criptat.enc"
    cale_output = os.path.join(os.path.dirname(cale_input), nume_criptat)

    cursor.execute("SELECT valoare_cheie1 FROM Chei WHERE id = ?", (cheie_id,))
    cheie_data = cursor.fetchone()
    if not cheie_data:
        messagebox.showerror("Eroare", "Cheia nu a fost găsită.")
        conn.close()
        return
    cheie = cheie_data[0]

    conn.close()

    start_time = time.time()

    try:
        match algoritm_id:
            case 1:
                subprocess.run([
                    "openssl", "enc", "-aes-256-cbc", "-pbkdf2",
                    "-in", cale_input, "-out", cale_output, "-pass", f"pass:{cheie}"
                ], check=True)
            case 2:
                subprocess.run([
                    "openssl", "enc", "-des-ede-cbc", "-pbkdf2",
                    "-in", cale_input, "-out", cale_output, "-pass", f"pass:{cheie}"
                ], check=True)
            case 3:
                subprocess.run([
                    "openssl", "enc", "-chacha20", "-pbkdf2",
                    "-in", cale_input, "-out", cale_output, "-pass", f"pass:{cheie}"
                ], check=True)
            case 4:
                with open("public.pem", "w") as file:
                    file.write(cheie)
                subprocess.run([
                    "openssl", "pkeyutl", "-encrypt",
                    "-in", cale_input, "-pubin", "-inkey", "public.pem",
                    "-out", cale_output
                ], check=True)

            case 6:
                subprocess.run([
                    "gpg", "--symmetric", "--cipher-algo", "AES256",
                    "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", cheie,
                    "--output", cale_output, cale_input
                ])

            case 7:
                subprocess.run([
                    "gpg", "--symmetric", "--cipher-algo", "3DES","--allow-old-cipher-algos",
                    "--batch", "--yes", "--pinentry-mode", "loopback",
                    "--passphrase", cheie, "--output", cale_output, cale_input
                ])
            case 8:
                with open("public.asc", "w") as file:
                    file.write(cheie)

                subprocess.run(["gpg", "--import", "public.asc"], check=True)

                subprocess.run([
                    "gpg", "--encrypt", "--recipient", "razvan-adrian.hordila@student.tuiasi.ro",
                    "--output", cale_output, cale_input
                ], check=True)

        durata = int((time.time() - start_time) * 1000)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE Fisiere SET nume_fisier_criptat = ?, stare = 'criptat', data_actualizarii = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (cale_output, fisier_id))

        cursor.execute("""
            INSERT INTO Operatii (fisier_id, algoritm_id, cheie_id, tip_operatie, durata, rezultat)
            VALUES (?, ?, ?, 'criptare', ?, 1)
        """, (fisier_id, algoritm_id, cheie_id, durata))

        conn.commit()
        conn.close()

        messagebox.showinfo("Succes", f"Fisierul a fost criptat cu succes ca: {nume_criptat}")
        update_dropdown()

    except subprocess.CalledProcessError as e:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        durata = int((time.time() - start_time) * 1000)

        cursor.execute("""
            INSERT INTO Operatii (fisier_id, algoritm_id, cheie_id, tip_operatie, durata, rezultat, mesaj_eroare)
            VALUES (?, ?, ?, 'criptare', ?, 0, ?)
        """, (fisier_id, algoritm_id, cheie_id, durata, str(e)))
        conn.commit()
        conn.close()

        messagebox.showerror("Eroare criptare", f"Eroare la criptarea fișierului:\n{e}")


def decripteaza_fisier():
    try:
        fisier_id = int(dropdown.get().split(" - ")[0])
        algoritm_id = int(algoritm_combobox.get().split(" - ")[0])
        cheie_id = int(cheie_combobox.get().split(" - ")[0])
    except:
        messagebox.showerror("Eroare", "Selecteaza fisierul, algoritmul si cheia.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT nume_fisier_criptat FROM Fisiere WHERE id = ?", (fisier_id,))
    result = cursor.fetchone()
    if not result or not result[0]:
        messagebox.showerror("Eroare", "Fisierul criptat nu este disponibil.")
        conn.close()
        return
    cale_input = result[0]

    cursor.execute("SELECT valoare_cheie1 FROM Chei WHERE id = ?", (cheie_id,))
    cheie_data = cursor.fetchone()
    if not cheie_data:
        messagebox.showerror("Eroare", "Cheia nu a fost găsită.")
        conn.close()
        return
    cheie = cheie_data[0]

    cursor.execute("SELECT valoare_cheie2 FROM Chei WHERE id = ?", (cheie_id,))
    cheie_data = cursor.fetchone()
    if not cheie_data:
        messagebox.showerror("Eroare", "Cheia nu a fost găsită.")
        conn.close()
        return
    cheiePriv = cheie_data[0]

    conn.close()

    with tempfile.NamedTemporaryFile(delete=False) as out_file:
        cale_output = out_file.name

    start_time = time.time()
    try:
        match algoritm_id:
            case 1:
                subprocess.run([
                    "openssl", "enc", "-d", "-aes-256-cbc", "-pbkdf2",
                    "-in", cale_input, "-out", cale_output, "-pass", f"pass:{cheie}"
                ], check=True)
            case 2:
                subprocess.run([
                    "openssl", "enc", "-d", "-des-ede-cbc", "-pbkdf2",
                    "-in", cale_input, "-out", cale_output, "-pass", f"pass:{cheie}"
                ], check=True)
            case 3:
                subprocess.run([
                    "openssl", "enc", "-d", "-chacha20", "-pbkdf2",
                    "-in", cale_input, "-out", cale_output, "-pass", f"pass:{cheie}"
                ], check=True)
            case 4:
                with open("private.pem", "w") as file:
                    file.write(cheiePriv)
                subprocess.run([
                    "openssl", "pkeyutl", "-decrypt",
                    "-in", cale_input, "-inkey", "private.pem",
                    "-out", cale_output
                ], check=True)
            case 6:
                subprocess.run([
                    "gpg", "--decrypt", "--cipher-algo", "AES256",
                    "--batch", "--yes", "--pinentry-mode", "loopback","--passphrase", cheie,
                    "--output", cale_output, cale_input
                ])
            case 7:
                subprocess.run([
                    "gpg", "--decrypt", "--cipher-algo", "3DES",

                    "--batch", "--yes", "--pinentry-mode", "loopback","--passphrase", cheie,
                    "--output", cale_output, cale_input
                ])
            case 8:
                with open("private.asc", "w") as file:
                    file.write(cheiePriv)

                subprocess.run(["gpg", "--import", "private.asc"], check=True)

                subprocess.run([
                    "gpg", "--batch", "--yes", "--pinentry-mode", "loopback",
                    "--output", cale_output,
                    "--decrypt", cale_input
                ], check=True)
        with open(cale_output, "r", encoding='utf-8', errors='replace') as f:
            continut = f.read()

        durata = int((time.time() - start_time) * 1000)

        text_decriptat.delete(1.0, tk.END)
        text_decriptat.insert(tk.END, continut)

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Operatii (fisier_id, algoritm_id, cheie_id, tip_operatie, durata, rezultat)
            VALUES (?, ?, ?, 'decriptare', ?, 1)
        """, (fisier_id, algoritm_id, cheie_id, durata))
        conn.commit()
        conn.close()

        update_log_text()

        messagebox.showinfo("Succes", "Fisierul a fost decriptat cu succes.")

    except subprocess.CalledProcessError as e:
        durata = int((time.time() - start_time) * 1000)
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO Operatii (fisier_id, algoritm_id, cheie_id, tip_operatie, durata, rezultat, mesaj_eroare)
            VALUES (?, ?, ?, 'decriptare', ?, 0, ?)
        """, (fisier_id, algoritm_id, cheie_id, durata, str(e)))
        conn.commit()
        conn.close()

        update_log_text()
        messagebox.showerror("Eroare", f"Decriptarea a esuat:\n{e}")


def update_log_text():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT O.id, F.nume_original, A.nume, O.tip_operatie, O.durata, O.rezultat, COALESCE(O.mesaj_eroare, 'OK')
        FROM Operatii O
        JOIN Fisiere F ON O.fisier_id = F.id
        JOIN Algoritmi A ON O.algoritm_id = A.id
        ORDER BY O.id DESC LIMIT 10
    """)
    operatii = cursor.fetchall()
    conn.close()

    text_loguri.delete(1.0, tk.END)
    for op in operatii:
        status = "SUCCES" if op[5] == 1 else "EȘEC"
        text_loguri.insert(tk.END,
                           f"[#{op[0]}] {op[3].upper()} | {op[1]} | Alg: {op[2]} | {op[4]} ms | {status} | Msg: {op[6]}\n"
                           )


root = tk.Tk()
root.title("Manager Fișiere Criptate")
root.geometry("2000x800")
root.resizable(True, True)
left_frame = tk.Frame(root)
left_frame.pack(side="left", padx=10, pady=10, anchor="n")

right_frame = tk.Frame(root)
right_frame.pack(side="left", padx=10, pady=10, anchor="n")
btn_adauga = tk.Button(left_frame, text="Adauga Fisier", command=selecteaza_fisier)
btn_adauga.pack(pady=10)

label_selectie = tk.Label(left_frame, text="Selecteaza fisier pentru criptare/decriptare:")
label_selectie.pack()

dropdown = ttk.Combobox(left_frame, width=50)
dropdown.pack(pady=5)
label_alg = tk.Label(left_frame, text="Selecteaza algoritmul de criptare/decriptare:")
label_alg.pack()

algoritm_combobox = ttk.Combobox(left_frame, width=50)
algoritm_combobox.pack(pady=5)

label_cheie = tk.Label(left_frame, text="Selecteaza cheia:")
label_cheie.pack()

btn_adauga_cheie = tk.Button(left_frame, text="Adauga Cheie", command=lambda: open_add_key_window())
btn_adauga_cheie.pack(pady=5)

btn_genereaza_chei = tk.Button(left_frame, text="Genereaza Chei", command=lambda: genereaza_chei_asimetrice())
btn_genereaza_chei.pack(pady=5)

cheie_combobox = ttk.Combobox(left_frame, width=50)
cheie_combobox.pack(pady=5)

algoritm_combobox.bind("<<ComboboxSelected>>", update_chei_dropdown)
dropdown.bind("<<ComboboxSelected>>", update_chei_dropdown)

btn_cripteaza = tk.Button(left_frame, text="Cripteaza", command=lambda: cripteaza_fisier())
btn_cripteaza.pack(pady=10)

btn_decripteaza = tk.Button(left_frame, text="Decripteaza", command=lambda: decripteaza_fisier())
btn_decripteaza.pack(pady=5)

label_decriptat = tk.Label(right_frame, text="Continut fisier decriptat:")
label_decriptat.pack(anchor="w")
scroll_decriptat = tk.Scrollbar(right_frame)
scroll_decriptat.pack(side="right", fill="y")

text_decriptat = tk.Text(right_frame, height=10, width=70, yscrollcommand=scroll_decriptat.set)
text_decriptat.pack(pady=5)

#
label_log = tk.Label(right_frame, text="Log operatii:")
label_log.pack()
scroll_loguri = tk.Scrollbar(right_frame)
scroll_loguri.pack(side="right", fill="y")

text_loguri = tk.Text(right_frame, height=10, width=70, bg="white", fg="black", yscrollcommand=scroll_loguri.set)
text_loguri.pack(pady=5)

insert_algoritmi_default()
update_algoritmi_dropdown()
update_dropdown()
update_chei_dropdown()
root.mainloop()
