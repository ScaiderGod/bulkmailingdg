import random
import re
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
# FUNCIONES DE LIMPIEZA
# =========================

def clean_email(raw_value):
    if pd.isna(raw_value):
        return ""

    text = str(raw_value).strip()
    text = text.replace("mailto:", "").strip()

    # Si viene como "Nombre <correo@dominio.com>"
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
            mx_records.append((int(rdata.preference), str(rdata.exchange).rstrip(".")))

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

    # Revisión adicional A/AAAA.
    # No reemplaza MX, pero ayuda a saber si el dominio existe.
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


def smtp_rcpt_check(email, mx_records, from_email, helo_domain, timeout_seconds=8, max_mx_to_try=2):
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
        reasons.append("Dominio temporal/desechable")

    if row["posible_error_dominio"]:
        score -= 30
        reasons.append(f"Posible typo de dominio: {row['posible_error_dominio']}")

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

def analyze_one_email(raw_email, is_duplicate, enable_smtp, enable_catchall, from_email, helo_domain, timeout_seconds):
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
    page_icon="📧",
    layout="wide",
)

st.title("Validador de correos para campañas")
st.caption("Limpieza y validación de listas antes de enviar campañas masivas.")

st.warning(
    "Importante: ningún método puede confirmar al 100% que un correo está activo sin enviar un correo real. "
    "Esta app calcula una seguridad probable usando formato, DNS, MX, SMTP, catch all y reglas de riesgo."
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

        st.success(f"Archivo cargado correctamente: {len(df)} filas")

        email_column = st.selectbox(
            "Selecciona la columna donde están los correos",
            options=df.columns,
        )

        with st.expander("Configuración avanzada", expanded=True):
            enable_smtp = st.checkbox(
                "Activar prueba SMTP sin enviar correo",
                value=True,
            )

            enable_catchall = st.checkbox(
                "Detectar dominios catch all",
                value=True,
            )

            from_email = st.text_input(
                "Correo FROM para la prueba SMTP",
                value="verificador@tudominio.com",
                help="Usa un correo real de tu dominio. No uses correos falsos como gmail.com si no te pertenecen.",
            )

            helo_domain = st.text_input(
                "Dominio HELO/EHLO",
                value="tudominio.com",
                help="Idealmente debe ser el dominio del correo FROM.",
            )

            timeout_seconds = st.slider(
                "Timeout por intento SMTP, en segundos",
                min_value=3,
                max_value=20,
                value=8,
            )

            max_workers = st.slider(
                "Velocidad de análisis",
                min_value=1,
                max_value=20,
                value=6,
                help="Más velocidad puede causar bloqueos o respuestas inciertas. Para campañas reales, 4 a 8 es razonable.",
            )

            limit_rows = st.number_input(
                "Limitar cantidad de filas a analizar. Usa 0 para analizar todas.",
                min_value=0,
                value=0,
            )

        if enable_smtp:
            sender_ok, _, sender_error = validate_syntax(from_email)

            if not sender_ok:
                st.error(f"El correo FROM no es válido: {sender_error}")
                st.stop()

            if "@" not in from_email:
                st.error("El correo FROM debe tener dominio.")
                st.stop()

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
                    status_text.text(f"Analizando {i} de {total} correos...")

            elapsed = round(time.time() - start_time, 2)

            result_df = pd.DataFrame(results)

            # Orden sugerido para limpiar antes de campaña
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

            c1, c2, c3, c4, c5 = st.columns(5)

            c1.metric("Total", len(result_df))
            c2.metric("Enviar", int((result_df["recomendacion"] == "ENVIAR").sum()))
            c3.metric("Con cuidado", int((result_df["recomendacion"] == "ENVIAR CON CUIDADO").sum()))
            c4.metric("Inciertos", int((result_df["recomendacion"] == "INCIERTO").sum()))
            c5.metric("No enviar", int((result_df["recomendacion"] == "NO ENVIAR").sum()))

            st.subheader("Resultado")
            st.dataframe(result_df, use_container_width=True)

            excel_bytes = dataframe_to_excel_bytes(result_df)

            st.download_button(
                label="Descargar resultado en Excel",
                data=excel_bytes,
                file_name="correos_validados.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

            st.info(
                "Recomendación práctica: para una campaña grande, primero manda solo a los que digan ENVIAR. "
                "Los de ENVIAR CON CUIDADO mándalos en una segunda tanda pequeña. "
                "Los INCIERTOS revísalos manualmente o mándalos con mucho cuidado. "
                "Los NO ENVIAR elimínalos."
            )

    except Exception as e:
        st.error(f"No se pudo procesar el archivo: {e}")
