import random
import smtplib
import socket
import string
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.utils import parseaddr
from functools import lru_cache
from io import BytesIO

import dns.resolver
import pandas as pd
import streamlit as st
from email_validator import EmailNotValidError, validate_email


# =========================
# CONFIGURACION GENERAL
# =========================

CONTACT_LIMIT = 25000

ROLE_PREFIXES = {
    "admin",
    "administracion",
    "administrator",
    "billing",
    "contact",
    "contacto",
    "correo",
    "facturacion",
    "finance",
    "hello",
    "hola",
    "info",
    "mail",
    "marketing",
    "no-reply",
    "noreply",
    "office",
    "postmaster",
    "recepcion",
    "sales",
    "soporte",
    "support",
    "ventas",
    "webmaster",
}

FREE_PROVIDERS = {
    "gmail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "icloud.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
}

COMMON_DOMAIN_TYPOS = {
    "gmial.com": "gmail.com",
    "gmai.com": "gmail.com",
    "gmail.con": "gmail.com",
    "gmail.co": "gmail.com",
    "hotmial.com": "hotmail.com",
    "hotmal.com": "hotmail.com",
    "hotmai.com": "hotmail.com",
    "hotmail.con": "hotmail.com",
    "outlok.com": "outlook.com",
    "outloo.com": "outlook.com",
    "outlook.con": "outlook.com",
    "yaho.com": "yahoo.com",
    "yahoo.con": "yahoo.com",
}

DISPOSABLE_DOMAINS = {
    "10minutemail.com",
    "tempmail.com",
    "guerrillamail.com",
    "mailinator.com",
    "yopmail.com",
    "trashmail.com",
    "sharklasers.com",
    "getnada.com",
    "temp-mail.org",
}


# =========================
# ESTILO VISUAL
# =========================

def yellow_note(text):
    st.markdown(
        f"""
        <div style="
            background-color: #fff59d;
            color: #000000;
            padding: 10px 12px;
            border-radius: 8px;
            margin-top: 6px;
            margin-bottom: 14px;
            font-size: 14px;
            line-height: 1.45;
            font-weight: 500;
            border-left: 5px solid #fbc02d;
        ">
            {text}
        </div>
        """,
        unsafe_allow_html=True
    )


# =========================
# TIEMPOS ESTIMADOS
# =========================

def estimate_time_range(contact_count, enable_smtp, enable_catchall):
    if contact_count <= 0:
        return "Sin contactos"

    if not enable_smtp:
        if contact_count <= 500:
            return "Menos de 1 minuto"
        if contact_count <= 2000:
            return "1 a 3 minutos"
        if contact_count <= 10000:
            return "3 a 10 minutos"
        return "10 a 25 minutos"

    if enable_smtp and not enable_catchall:
        if contact_count <= 500:
            return "3 a 10 minutos"
        if contact_count <= 2000:
            return "10 a 30 minutos"
        if contact_count <= 10000:
            return "45 minutos a 3 horas"
        return "2 a 6 horas"

    if enable_smtp and enable_catchall:
        if contact_count <= 500:
            return "5 a 15 minutos"
        if contact_count <= 2000:
            return "20 a 60 minutos"
        if contact_count <= 10000:
            return "1.5 a 5 horas"
        return "4 a 10 horas"

    return "Variable"


# =========================
# FUNCIONES DE LIMPIEZA
# =========================

def clean_email(raw_value):
    if pd.isna(raw_value):
        return ""

    text = str(raw_value).strip()
    text = text.replace("mailto:", "").strip()

    parsed_name, parsed_email = parseaddr(text)
    if parsed_email:
        text = parsed_email

    text = text.strip().lower()
    text = text.replace(" ", "")

    return text


def get_domain(email):
    if "@" not in email:
        return ""
    return email.split("@")[-1].strip().lower()


def get_local_part(email):
    if "@" not in email:
        return ""
    return email.split("@")[0].strip().lower()


def is_role_email(email):
    local = get_local_part(email)
    return local in ROLE_PREFIXES


def is_disposable_domain(domain):
    return domain in DISPOSABLE_DOMAINS


def domain_typo_suggestion(domain):
    return COMMON_DOMAIN_TYPOS.get(domain, "")


def validate_syntax(email):
    try:
        result = validate_email(
            email,
            check_deliverability=False,
            allow_smtputf8=False
        )
        return True, result.normalized, ""
    except EmailNotValidError as e:
        return False, email, str(e)


# =========================
# DNS / MX
# =========================

@lru_cache(maxsize=50000)
def get_dns_info(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6

    info = {
        "domain_exists": False,
        "has_mx": False,
        "mx_records": [],
        "has_a_or_aaaa": False,
        "dns_status": "NO_VERIFICADO",
        "dns_error": "",
    }

    if not domain:
        info["dns_status"] = "SIN_DOMINIO"
        return info

    try:
        mx_answers = resolver.resolve(domain, "MX")
        mx_records = []

        for rdata in mx_answers:
            mx_records.append(
                (
                    int(rdata.preference),
                    str(rdata.exchange).rstrip(".")
                )
            )

        mx_records = sorted(mx_records, key=lambda x: x[0])

        info["domain_exists"] = True
        info["has_mx"] = len(mx_records) > 0
        info["mx_records"] = mx_records
        info["dns_status"] = "MX_OK"

    except dns.resolver.NXDOMAIN:
        info["domain_exists"] = False
        info["dns_status"] = "DOMINIO_NO_EXISTE"
        info["dns_error"] = "NXDOMAIN"
        return info

    except dns.resolver.NoAnswer:
        info["domain_exists"] = True
        info["dns_status"] = "SIN_MX"

    except dns.resolver.Timeout:
        info["domain_exists"] = None
        info["dns_status"] = "TIMEOUT_DNS"
        info["dns_error"] = "Timeout consultando MX"

    except Exception as e:
        info["domain_exists"] = None
        info["dns_status"] = "ERROR_DNS"
        info["dns_error"] = str(e)

    try:
        resolver.resolve(domain, "A")
        info["has_a_or_aaaa"] = True
        if info["domain_exists"] is False:
            info["domain_exists"] = True
    except Exception:
        try:
            resolver.resolve(domain, "AAAA")
            info["has_a_or_aaaa"] = True
            if info["domain_exists"] is False:
                info["domain_exists"] = True
        except Exception:
            pass

    return info


# =========================
# SMTP
# =========================

def interpret_smtp_code(code):
    if 200 <= code < 300:
        return "ACEPTADO"

    if code in [550, 551, 552, 553, 554]:
        return "RECHAZADO"

    if code in [421, 450, 451, 452]:
        return "TEMPORAL"

    if 400 <= code < 500:
        return "TEMPORAL"

    if 500 <= code < 600:
        return "RECHAZADO"

    return "INCIERTO"


def smtp_rcpt_check(
    email,
    mx_records,
    from_email,
    helo_domain,
    timeout_seconds=8,
    max_mx_to_try=2
):
    if not mx_records:
        return {
            "smtp_status": "NO_PROBADO",
            "smtp_code": "",
            "smtp_message": "Sin MX disponible",
            "smtp_server": "",
        }

    last_error = ""

    for _, mx_host in mx_records[:max_mx_to_try]:
        try:
            with smtplib.SMTP(mx_host, 25, timeout=timeout_seconds) as server:
                server.set_debuglevel(0)

                try:
                    server.ehlo(helo_domain)
                except Exception:
                    server.helo(helo_domain)

                mail_code, mail_msg = server.mail(from_email)

                if int(mail_code) >= 400:
                    return {
                        "smtp_status": "INCIERTO",
                        "smtp_code": mail_code,
                        "smtp_message": f"MAIL FROM rechazado: {mail_msg}",
                        "smtp_server": mx_host,
                    }

                rcpt_code, rcpt_msg = server.rcpt(email)

                try:
                    server.rset()
                except Exception:
                    pass

                return {
                    "smtp_status": interpret_smtp_code(int(rcpt_code)),
                    "smtp_code": rcpt_code,
                    "smtp_message": rcpt_msg.decode(errors="ignore") if isinstance(rcpt_msg, bytes) else str(rcpt_msg),
                    "smtp_server": mx_host,
                }

        except (socket.timeout, TimeoutError):
            last_error = f"Timeout conectando a {mx_host}:25"

        except smtplib.SMTPServerDisconnected:
            last_error = f"Servidor desconectó la sesión: {mx_host}"

        except smtplib.SMTPConnectError as e:
            last_error = f"Error de conexión SMTP con {mx_host}: {e}"

        except smtplib.SMTPHeloError as e:
            last_error = f"Error HELO/EHLO con {mx_host}: {e}"

        except OSError as e:
            last_error = f"Error de red con {mx_host}: {e}"

        except Exception as e:
            last_error = f"Error SMTP con {mx_host}: {e}"

    return {
        "smtp_status": "INCIERTO",
        "smtp_code": "",
        "smtp_message": last_error or "No se pudo completar la prueba SMTP",
        "smtp_server": "",
    }


def random_fake_email(domain):
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
    return f"noexiste-{token}@{domain}"


@lru_cache(maxsize=50000)
def catchall_check_cached(domain, mx_records_text, from_email, helo_domain, timeout_seconds):
    mx_records = []

    for part in mx_records_text.split("|"):
        if not part:
            continue

        preference, host = part.split(",", 1)
        mx_records.append((int(preference), host))

    fake_email = random_fake_email(domain)

    result = smtp_rcpt_check(
        fake_email,
        mx_records,
        from_email,
        helo_domain,
        timeout_seconds=timeout_seconds,
        max_mx_to_try=2,
    )

    if result["smtp_status"] == "ACEPTADO":
        return {
            "catchall_status": "SI",
            "catchall_detail": f"Aceptó correo inventado: {fake_email}",
        }

    if result["smtp_status"] == "RECHAZADO":
        return {
            "catchall_status": "NO",
            "catchall_detail": "Rechazó correo inventado",
        }

    return {
        "catchall_status": "INCIERTO",
        "catchall_detail": result.get("smtp_message", "No se pudo confirmar catch all"),
    }


def mx_records_to_text(mx_records):
    return "|".join([f"{pref},{host}" for pref, host in mx_records])


# =========================
# SCORE Y RECOMENDACION
# =========================

def build_score_and_recommendation(row):
    score = 100
    reasons = []

    if row["duplicado"] == "SI":
        score -= 25
        reasons.append("Duplicado")

    if row["formato_valido"] == "NO":
        return 0, "NO ENVIAR", "Formato inválido"

    if row["dominio_temporal"] == "SI":
        score -= 45
        reasons.append("Dominio temporal o desechable")

    if row["posible_error_dominio"]:
        score -= 30
        reasons.append(f"Posible error de dominio: {row['posible_error_dominio']}")

    if row["dominio_existe"] == "NO":
        return 0, "NO ENVIAR", "Dominio no existe"

    if row["mx"] == "NO":
        score -= 45
        reasons.append("Sin MX")

    if row["correo_generico"] == "SI":
        score -= 10
        reasons.append("Correo genérico o departamental")

    if row["proveedor_gratuito"] == "SI":
        score -= 5
        reasons.append("Proveedor gratuito")

    smtp_status = row["smtp_status"]

    if smtp_status == "RECHAZADO":
        return 5, "NO ENVIAR", "Servidor SMTP rechazó el destinatario"

    if smtp_status == "TEMPORAL":
        score -= 30
        reasons.append("Error temporal SMTP")

    if smtp_status == "INCIERTO":
        score -= 20
        reasons.append("SMTP incierto o bloqueado")

    if smtp_status == "NO_PROBADO":
        score -= 15
        reasons.append("SMTP no probado")

    if row["catchall"] == "SI":
        score -= 25
        reasons.append("Dominio catch all")

    if row["catchall"] == "INCIERTO":
        score -= 10
        reasons.append("Catch all incierto")

    score = max(0, min(100, score))

    if score >= 85:
        recommendation = "ENVIAR"
    elif score >= 70:
        recommendation = "ENVIAR CON CUIDADO"
    elif score >= 50:
        recommendation = "INCIERTO"
    elif score >= 30:
        recommendation = "RIESGO ALTO"
    else:
        recommendation = "NO ENVIAR"

    return score, recommendation, "; ".join(reasons) if reasons else "Sin alertas fuertes"


# =========================
# ANALISIS PRINCIPAL
# =========================

def analyze_one_email(
    raw_email,
    is_duplicate,
    enable_smtp,
    enable_catchall,
    from_email,
    helo_domain,
    timeout_seconds
):
    clean = clean_email(raw_email)

    base_row = {
        "email_original": raw_email,
        "email_limpio": clean,
        "duplicado": "SI" if is_duplicate else "NO",
        "formato_valido": "NO",
        "formato_error": "",
        "dominio": "",
        "dominio_existe": "NO",
        "mx": "NO",
        "mx_records": "",
        "dns_status": "",
        "dns_error": "",
        "correo_generico": "NO",
        "proveedor_gratuito": "NO",
        "dominio_temporal": "NO",
        "posible_error_dominio": "",
        "smtp_status": "NO_PROBADO",
        "smtp_code": "",
        "smtp_message": "",
        "smtp_server": "",
        "catchall": "NO_PROBADO",
        "catchall_detalle": "",
        "score": 0,
        "recomendacion": "NO ENVIAR",
        "motivos": "",
    }

    if not clean:
        base_row["formato_error"] = "Celda vacía"
        base_row["motivos"] = "Celda vacía"
        return base_row

    syntax_ok, normalized, syntax_error = validate_syntax(clean)

    if not syntax_ok:
        base_row["formato_error"] = syntax_error
        base_row["motivos"] = "Formato inválido"
        return base_row

    clean = normalized.lower()
    domain = get_domain(clean)

    base_row["email_limpio"] = clean
    base_row["formato_valido"] = "SI"
    base_row["dominio"] = domain
    base_row["correo_generico"] = "SI" if is_role_email(clean) else "NO"
    base_row["proveedor_gratuito"] = "SI" if domain in FREE_PROVIDERS else "NO"
    base_row["dominio_temporal"] = "SI" if is_disposable_domain(domain) else "NO"
    base_row["posible_error_dominio"] = domain_typo_suggestion(domain)

    dns_info = get_dns_info(domain)

    domain_exists = dns_info["domain_exists"]

    if domain_exists is True:
        base_row["dominio_existe"] = "SI"
    elif domain_exists is False:
        base_row["dominio_existe"] = "NO"
    else:
        base_row["dominio_existe"] = "INCIERTO"

    base_row["mx"] = "SI" if dns_info["has_mx"] else "NO"
    base_row["mx_records"] = ", ".join([host for _, host in dns_info["mx_records"]])
    base_row["dns_status"] = dns_info["dns_status"]
    base_row["dns_error"] = dns_info["dns_error"]

    if enable_smtp and dns_info["has_mx"]:
        smtp_result = smtp_rcpt_check(
            clean,
            dns_info["mx_records"],
            from_email,
            helo_domain,
            timeout_seconds=timeout_seconds,
            max_mx_to_try=2,
        )

        base_row["smtp_status"] = smtp_result["smtp_status"]
        base_row["smtp_code"] = smtp_result["smtp_code"]
        base_row["smtp_message"] = smtp_result["smtp_message"]
        base_row["smtp_server"] = smtp_result["smtp_server"]

        if enable_catchall:
            mx_text = mx_records_to_text(dns_info["mx_records"])

            catchall_result = catchall_check_cached(
                domain,
                mx_text,
                from_email,
                helo_domain,
                timeout_seconds,
            )

            base_row["catchall"] = catchall_result["catchall_status"]
            base_row["catchall_detalle"] = catchall_result["catchall_detail"]
        else:
            base_row["catchall"] = "NO_PROBADO"

    score, recommendation, reasons = build_score_and_recommendation(base_row)

    base_row["score"] = score
    base_row["recomendacion"] = recommendation
    base_row["motivos"] = reasons

    return base_row


def dataframe_to_excel_bytes(df):
    output = BytesIO()

    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="resultado")

        worksheet = writer.sheets["resultado"]

        for column_cells in worksheet.columns:
            max_length = 0
            column_letter = column_cells[0].column_letter

            for cell in column_cells:
                try:
                    max_length = max(max_length, len(str(cell.value)))
                except Exception:
                    pass

            worksheet.column_dimensions[column_letter].width = min(max_length + 2, 45)

    return output.getvalue()


# =========================
# STREAMLIT UI
# =========================

st.set_page_config(
    page_title="Validador de correos para campañas",
    layout="wide",
)

st.title("Validador de correos para campañas")
st.caption("Limpieza y validación de listas antes de enviar campañas masivas.")

st.warning(
    "Importante: ningún método puede confirmar al 100% que un correo está activo sin enviar un correo real. "
    "Esta app calcula una seguridad probable usando formato, DNS, MX, SMTP, catch all y reglas de riesgo."
)

yellow_note(
    "Objetivo de la app: ayudarte a reducir rebotes antes de mandar una campaña. "
    "El resultado correcto no es una garantía absoluta, sino una recomendación de riesgo basada en varias pruebas."
)

uploaded_file = st.file_uploader(
    "Sube tu archivo CSV o Excel",
    type=["csv", "xlsx"],
)

if uploaded_file:
    try:
        if uploaded_file.name.lower().endswith(".csv"):
            df = pd.read_csv(uploaded_file)
        else:
            df = pd.read_excel(uploaded_file)

        total_rows = len(df)

        if total_rows > CONTACT_LIMIT:
            st.error(
                f"El archivo tiene {total_rows:,} contactos. "
                f"El límite recomendado por hoja es de {CONTACT_LIMIT:,} contactos. "
                "Divide la lista en archivos más pequeños para evitar bloqueos, errores o resultados incompletos."
            )
            st.stop()

        st.success(f"Archivo cargado correctamente: {total_rows:,} filas")

        email_column = st.selectbox(
            "Selecciona la columna donde están los correos",
            options=df.columns,
        )

        st.markdown("## Configuración del análisis")

        yellow_note(
            "Configuración recomendada para una primera prueba: SMTP activado, catch all activado, "
            "timeout en 8 segundos, velocidad en 6 y limitar el análisis a 100 o 500 contactos. "
            "Después, si todo funciona bien, puedes analizar la base completa."
        )

        with st.expander("Configuración avanzada", expanded=True):
            st.markdown("### Ajustes del análisis")

            yellow_note(
                "Aquí puedes decidir qué tan profundo quieres revisar los correos. "
                "Mientras más pruebas actives, mayor seguridad probable tendrás, pero también tardará más el análisis."
            )

            enable_smtp = st.checkbox(
                "Activar prueba SMTP sin enviar correo",
                value=True,
            )

            yellow_note(
                "Qué hace esto: intenta preguntarle al servidor del correo si ese destinatario parece válido, "
                "sin mandar un correo real. Es una de las pruebas más útiles, pero también es de las más lentas. "
                "Algunos servidores pueden bloquearla y devolver un resultado incierto."
            )

            enable_catchall = st.checkbox(
                "Detectar dominios catch all",
                value=True,
            )

            yellow_note(
                "Qué significa catch all: algunos dominios aceptan cualquier correo, aunque el buzón no exista realmente. "
                "Esta prueba intenta detectar eso usando un correo inventado del mismo dominio. "
                "Si el dominio es catch all, el resultado será menos confiable."
            )

            from_email = st.text_input(
                "Correo FROM para la prueba SMTP",
                value="verificador@tudominio.com",
            )

            yellow_note(
                "Qué va aquí: debes poner un correo real de tu propio dominio. "
                "Ejemplo: contacto@tuempresa.com. "
                "Este correo solo se usa para presentarse ante el servidor durante la validación. "
                "No uses un correo inventado ni un dominio que no te pertenece."
            )

            helo_domain = st.text_input(
                "Dominio HELO/EHLO",
                value="tudominio.com",
            )

            yellow_note(
                "Qué va aquí: solo el dominio de tu empresa, sin arroba. "
                "Ejemplo: tuempresa.com. "
                "Normalmente debe coincidir con el dominio del correo FROM. "
                "Si tu correo FROM es contacto@tuempresa.com, aquí pondrías tuempresa.com."
            )

            timeout_seconds = st.slider(
                "Timeout por intento SMTP, en segundos",
                min_value=3,
                max_value=20,
                value=8,
            )

            yellow_note(
                "Qué significa esto: es el tiempo máximo que la app esperará una respuesta del servidor por cada intento SMTP. "
                "Si lo pones muy bajo, algunos correos pueden salir como inciertos aunque sí sean buenos. "
                "Si lo pones muy alto, el análisis tardará más. Recomendado: entre 6 y 8 segundos."
            )

            max_workers = st.slider(
                "Velocidad de análisis",
                min_value=1,
                max_value=20,
                value=6,
            )

            yellow_note(
                "Qué significa esto: es cuántos correos se revisan al mismo tiempo. "
                "Más alto significa más rápido, pero también aumenta el riesgo de bloqueos, respuestas erróneas o resultados inciertos. "
                "Recomendado para campañas reales: entre 4 y 8."
            )

            limit_rows = st.number_input(
                "Limitar cantidad de filas a analizar. Usa 0 para analizar todas.",
                min_value=0,
                value=0,
            )

            yellow_note(
                "Para qué sirve esto: si quieres probar primero una parte de tu base, aquí puedes limitar cuántos contactos analizar. "
                "Ejemplo: pon 100 o 500 para una prueba rápida. "
                "Si dejas 0, la app analizará todos los contactos del archivo."
            )

        contacts_to_analyze = total_rows if limit_rows == 0 else min(total_rows, int(limit_rows))
        estimated_time = estimate_time_range(contacts_to_analyze, enable_smtp, enable_catchall)

        st.subheader("Capacidad y tiempo estimado")

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Contactos detectados", f"{total_rows:,}")
        c2.metric("Límite por archivo", f"{CONTACT_LIMIT:,}")
        c3.metric("Contactos a analizar", f"{contacts_to_analyze:,}")
        c4.metric("Tiempo estimado", estimated_time)

        yellow_note(
            "Los tiempos son aproximados. Las pruebas SMTP y catch all pueden tardar más porque dependen de servidores externos. "
            "Si muchos servidores no responden rápido, el análisis puede tardar más de lo estimado."
        )

        with st.expander("Ver tabla de tiempos promedio"):
            st.markdown(
                """
| Cantidad de contactos | Sin SMTP | Con SMTP | Con SMTP + catch all |
|---:|---:|---:|---:|
| 1 a 500 | Menos de 1 minuto | 3 a 10 minutos | 5 a 15 minutos |
| 501 a 2,000 | 1 a 3 minutos | 10 a 30 minutos | 20 a 60 minutos |
| 2,001 a 10,000 | 3 a 10 minutos | 45 minutos a 3 horas | 1.5 a 5 horas |
| 10,001 a 25,000 | 10 a 25 minutos | 2 a 6 horas | 4 a 10 horas |
                """
            )

        if contacts_to_analyze > 2000 and enable_smtp:
            st.info(
                "Este archivo puede tardar bastante por las pruebas SMTP. "
                "Si es la primera prueba, puedes limitar el análisis a 100, 500 o 2,000 contactos."
            )

        if enable_smtp:
            sender_ok, _, sender_error = validate_syntax(from_email)

            if not sender_ok:
                st.error(f"El correo FROM no es válido: {sender_error}")
                st.stop()

            if "@" not in from_email:
                st.error("El correo FROM debe tener dominio.")
                st.stop()

            if "tudominio.com" in from_email or helo_domain == "tudominio.com":
                st.warning(
                    "Aún tienes valores de ejemplo en el correo FROM o en el dominio HELO/EHLO. "
                    "Cámbialos por datos reales de tu dominio para obtener resultados más confiables."
                )

        preview_df = df[[email_column]].head(10)

        st.subheader("Vista previa")
        st.dataframe(preview_df, use_container_width=True)

        if st.button("Analizar correos", type="primary"):
            work_df = df.copy()

            if limit_rows and limit_rows > 0:
                work_df = work_df.head(int(limit_rows)).copy()

            raw_emails = work_df[email_column].tolist()
            cleaned_emails = [clean_email(x) for x in raw_emails]

            seen = set()
            duplicates = []

            for email in cleaned_emails:
                if email and email in seen:
                    duplicates.append(True)
                else:
                    duplicates.append(False)
                    if email:
                        seen.add(email)

            progress = st.progress(0)
            status_text = st.empty()

            results = []
            total = len(raw_emails)

            start_time = time.time()

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = []

                for raw_email, duplicate in zip(raw_emails, duplicates):
                    futures.append(
                        executor.submit(
                            analyze_one_email,
                            raw_email,
                            duplicate,
                            enable_smtp,
                            enable_catchall,
                            from_email,
                            helo_domain,
                            timeout_seconds,
                        )
                    )

                for i, future in enumerate(as_completed(futures), start=1):
                    try:
                        results.append(future.result())
                    except Exception as e:
                        results.append({
                            "email_original": "",
                            "email_limpio": "",
                            "duplicado": "",
                            "formato_valido": "NO",
                            "formato_error": str(e),
                            "dominio": "",
                            "dominio_existe": "INCIERTO",
                            "mx": "NO",
                            "mx_records": "",
                            "dns_status": "ERROR",
                            "dns_error": str(e),
                            "correo_generico": "",
                            "proveedor_gratuito": "",
                            "dominio_temporal": "",
                            "posible_error_dominio": "",
                            "smtp_status": "INCIERTO",
                            "smtp_code": "",
                            "smtp_message": str(e),
                            "smtp_server": "",
                            "catchall": "INCIERTO",
                            "catchall_detalle": "",
                            "score": 0,
                            "recomendacion": "INCIERTO",
                            "motivos": str(e),
                        })

                    progress.progress(i / total)
                    status_text.text(f"Analizando {i:,} de {total:,} correos...")

            elapsed = round(time.time() - start_time, 2)

            result_df = pd.DataFrame(results)

            order_map = {
                "ENVIAR": 1,
                "ENVIAR CON CUIDADO": 2,
                "INCIERTO": 3,
                "RIESGO ALTO": 4,
                "NO ENVIAR": 5,
            }

            result_df["orden"] = result_df["recomendacion"].map(order_map).fillna(99)
            result_df = result_df.sort_values(by=["orden", "score"], ascending=[True, False])
            result_df = result_df.drop(columns=["orden"])

            st.success(f"Análisis terminado en {elapsed} segundos")

            st.subheader("Resumen")

            r1, r2, r3, r4, r5 = st.columns(5)

            r1.metric("Total", len(result_df))
            r2.metric("Enviar", int((result_df["recomendacion"] == "ENVIAR").sum()))
            r3.metric("Con cuidado", int((result_df["recomendacion"] == "ENVIAR CON CUIDADO").sum()))
            r4.metric("Inciertos", int((result_df["recomendacion"] == "INCIERTO").sum()))
            r5.metric("No enviar", int((result_df["recomendacion"] == "NO ENVIAR").sum()))

            yellow_note(
                "Recomendación de uso: manda primero solo a los contactos marcados como ENVIAR. "
                "Los de ENVIAR CON CUIDADO pueden ir en una segunda tanda pequeña. "
                "Los INCIERTOS conviene revisarlos manualmente. "
                "Los de NO ENVIAR deben eliminarse de la campaña."
            )

            st.subheader("Resultado")
            st.dataframe(result_df, use_container_width=True)

            excel_bytes = dataframe_to_excel_bytes(result_df)

            st.download_button(
                label="Descargar resultado en Excel",
                data=excel_bytes,
                file_name="correos_validados.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

    except Exception as e:
        st.error(f"No se pudo procesar el archivo: {e}")
