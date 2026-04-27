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

CONTACT_LIMIT = 1_000_000

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
    "gmal.com": "gmail.com",
    "gmail.cm": "gmail.com",
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

def estimate_time_range(contact_count, unique_domain_count):
    if contact_count <= 0:
        return "Sin contactos"

    if contact_count <= 2_000:
        return "Menos de 1 a 3 minutos"

    if contact_count <= 25_000:
        return "3 a 10 minutos"

    if contact_count <= 100_000:
        return "10 a 30 minutos"

    if contact_count <= 500_000:
        return "30 minutos a 2 horas"

    return "1 a 4 horas"


# =========================
# LIMPIEZA Y VALIDACION
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
        return True, result.normalized.lower(), ""
    except EmailNotValidError as e:
        return False, email, str(e)


# =========================
# DNS / MX
# =========================

@lru_cache(maxsize=500_000)
def get_dns_info(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6

    info = {
        "domain_exists": False,
        "has_mx": False,
        "mx_records": "",
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
            exchange = str(rdata.exchange).rstrip(".")
            preference = int(rdata.preference)

            if exchange == "":
                info["domain_exists"] = True
                info["has_mx"] = False
                info["mx_records"] = ""
                info["dns_status"] = "NULL_MX"
                info["dns_error"] = "El dominio declara que no acepta correo"
                return info

            mx_records.append((preference, exchange))

        mx_records = sorted(mx_records, key=lambda x: x[0])

        info["domain_exists"] = True
        info["has_mx"] = len(mx_records) > 0
        info["mx_records"] = ", ".join([host for _, host in mx_records])
        info["dns_status"] = "MX_OK"

    except dns.resolver.NXDOMAIN:
        info["domain_exists"] = False
        info["has_mx"] = False
        info["dns_status"] = "DOMINIO_NO_EXISTE"
        info["dns_error"] = "El dominio no existe"
        return info

    except dns.resolver.NoAnswer:
        info["domain_exists"] = True
        info["has_mx"] = False
        info["dns_status"] = "SIN_MX"
        info["dns_error"] = "El dominio existe, pero no tiene registros MX"

    except dns.resolver.Timeout:
        info["domain_exists"] = None
        info["has_mx"] = False
        info["dns_status"] = "TIMEOUT_DNS"
        info["dns_error"] = "Timeout consultando DNS"

    except Exception as e:
        info["domain_exists"] = None
        info["has_mx"] = False
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


def preload_dns_for_domains(domains, max_workers):
    results = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(get_dns_info, domain): domain
            for domain in domains
            if domain
        }

        for future in as_completed(future_map):
            domain = future_map[future]
            try:
                results[domain] = future.result()
            except Exception as e:
                results[domain] = {
                    "domain_exists": None,
                    "has_mx": False,
                    "mx_records": "",
                    "has_a_or_aaaa": False,
                    "dns_status": "ERROR_DNS",
                    "dns_error": str(e),
                }

    return results


# =========================
# SCORE Y RECOMENDACION
# =========================

def build_score_and_recommendation(row):
    score = 100
    reasons = []

    if row["duplicado"] == "SI":
        return 20, "NO ENVIAR", "Duplicado"

    if row["formato_valido"] == "NO":
        return 0, "NO ENVIAR", "Formato inválido"

    if row["dominio_temporal"] == "SI":
        return 15, "NO ENVIAR", "Dominio temporal o desechable"

    if row["posible_error_dominio"]:
        score -= 35
        reasons.append(f"Posible error de dominio. Sugerencia: {row['posible_error_dominio']}")

    if row["dominio_existe"] == "NO":
        return 0, "NO ENVIAR", "Dominio no existe"

    if row["dominio_existe"] == "INCIERTO":
        score -= 25
        reasons.append("No se pudo confirmar si el dominio existe")

    if row["mx"] == "NO":
        if row["dns_status"] in ["DOMINIO_NO_EXISTE", "NULL_MX", "SIN_MX"]:
            return 10, "NO ENVIAR", "Dominio sin correo configurado o sin MX"
        score -= 35
        reasons.append("No se pudo confirmar MX")

    if row["correo_generico"] == "SI":
        score -= 10
        reasons.append("Correo genérico o departamental")

    if row["proveedor_gratuito"] == "SI":
        score -= 5
        reasons.append("Proveedor gratuito")

    score = max(0, min(100, score))

    if score >= 85:
        recommendation = "ENVIAR PROBABLE"
    elif score >= 65:
        recommendation = "ENVIAR CON CUIDADO"
    elif score >= 40:
        recommendation = "REVISAR"
    else:
        recommendation = "NO ENVIAR"

    return score, recommendation, "; ".join(reasons) if reasons else "Pasó las pruebas técnicas básicas"


# =========================
# ANALISIS PRINCIPAL
# =========================

def analyze_one_email(raw_email, is_duplicate, dns_cache):
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

    clean = normalized
    domain = get_domain(clean)

    base_row["email_limpio"] = clean
    base_row["formato_valido"] = "SI"
    base_row["dominio"] = domain
    base_row["correo_generico"] = "SI" if is_role_email(clean) else "NO"
    base_row["proveedor_gratuito"] = "SI" if domain in FREE_PROVIDERS else "NO"
    base_row["dominio_temporal"] = "SI" if is_disposable_domain(domain) else "NO"
    base_row["posible_error_dominio"] = domain_typo_suggestion(domain)

    dns_info = dns_cache.get(domain)

    if not dns_info:
        dns_info = get_dns_info(domain)

    domain_exists = dns_info["domain_exists"]

    if domain_exists is True:
        base_row["dominio_existe"] = "SI"
    elif domain_exists is False:
        base_row["dominio_existe"] = "NO"
    else:
        base_row["dominio_existe"] = "INCIERTO"

    base_row["mx"] = "SI" if dns_info["has_mx"] else "NO"
    base_row["mx_records"] = dns_info["mx_records"]
    base_row["dns_status"] = dns_info["dns_status"]
    base_row["dns_error"] = dns_info["dns_error"]

    score, recommendation, reasons = build_score_and_recommendation(base_row)

    base_row["score"] = score
    base_row["recomendacion"] = recommendation
    base_row["motivos"] = reasons

    return base_row


# =========================
# EXPORTACIONES
# =========================

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


def dataframe_to_csv_bytes(df):
    return df.to_csv(index=False).encode("utf-8-sig")


# =========================
# STREAMLIT UI
# =========================

st.set_page_config(
    page_title="Limpieza segura de correos",
    layout="wide",
)

st.title("Limpieza segura de correos para campañas")
st.caption("Validación rápida sin SMTP y sin riesgo para tu dominio.")

st.warning(
    "Esta versión no usa SMTP. No envía correos, no se conecta a servidores como remitente "
    "y no usa tu dominio para hacer pruebas. Sirve para limpieza técnica masiva antes de una campaña."
)

yellow_note(
    "Qué sí valida esta app: formato, duplicados, dominio, registros MX, dominios inexistentes, "
    "posibles errores de escritura, dominios temporales y correos genéricos."
)

yellow_note(
    "Qué no puede confirmar: si el buzón exacto existe o está activo. "
    "Ejemplo: puede confirmar que empresa.com recibe correo, pero no puede confirmar al 100% "
    "que juan@empresa.com exista."
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
                f"El límite de esta versión es de {CONTACT_LIMIT:,} contactos por archivo."
            )
            st.stop()

        st.success(f"Archivo cargado correctamente: {total_rows:,} filas")

        email_column = st.selectbox(
            "Selecciona la columna donde están los correos",
            options=df.columns,
        )

        st.markdown("## Configuración de limpieza")

        yellow_note(
            "Esta configuración es segura porque no usa SMTP. "
            "Puedes usarla para limpiar listas grandes sin exponer tu dominio a bloqueos por pruebas de servidor."
        )

        with st.expander("Configuración", expanded=True):
            limit_rows = st.number_input(
                "Limitar cantidad de filas a analizar. Usa 0 para analizar todas.",
                min_value=0,
                value=0,
            )

            yellow_note(
                "Para qué sirve: si quieres probar primero una parte de tu base, escribe 100, 500 o 2,000. "
                "Si lo dejas en 0, se analizará todo el archivo."
            )

            dns_workers = st.slider(
                "Velocidad de revisión de dominios",
                min_value=1,
                max_value=50,
                value=15,
            )

            yellow_note(
                "Qué significa: es cuántos dominios se revisan al mismo tiempo. "
                "Como esta versión no usa SMTP, el riesgo es mucho menor. "
                "Recomendado: 10 a 20. Si tu internet o servidor va lento, usa 5 a 10."
            )

        work_df = df.copy()

        if limit_rows and limit_rows > 0:
            work_df = work_df.head(int(limit_rows)).copy()

        contacts_to_analyze = len(work_df)

        cleaned_preview = [clean_email(x) for x in work_df[email_column].head(5000).tolist()]
        preview_domains = sorted(set([get_domain(x) for x in cleaned_preview if "@" in x]))

        estimated_time = estimate_time_range(contacts_to_analyze, len(preview_domains))

        st.subheader("Capacidad y tiempo estimado")

        c1, c2, c3, c4 = st.columns(4)

        c1.metric("Contactos en archivo", f"{total_rows:,}")
        c2.metric("Límite seguro", f"{CONTACT_LIMIT:,}")
        c3.metric("Contactos a analizar", f"{contacts_to_analyze:,}")
        c4.metric("Tiempo estimado", estimated_time)

        yellow_note(
            "El tiempo depende principalmente de cuántos dominios únicos tenga tu lista. "
            "Por ejemplo, 100,000 correos de pocos dominios puede ser rápido. "
            "100,000 correos con miles de dominios diferentes puede tardar más."
        )

        with st.expander("Ver tabla de tiempos promedio"):
            st.markdown(
                """
| Cantidad de contactos | Tiempo aproximado sin SMTP |
|---:|---:|
| 1 a 2,000 | Menos de 1 a 3 minutos |
| 2,001 a 25,000 | 3 a 10 minutos |
| 25,001 a 100,000 | 10 a 30 minutos |
| 100,001 a 500,000 | 30 minutos a 2 horas |
| 500,001 a 1,000,000 | 1 a 4 horas |
                """
            )

        st.subheader("Vista previa")
        st.dataframe(work_df[[email_column]].head(10), use_container_width=True)

        if st.button("Analizar correos", type="primary"):
            start_time = pd.Timestamp.now()

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

            valid_domains = []
            for email in cleaned_emails:
                if "@" in email:
                    domain = get_domain(email)
                    if domain:
                        valid_domains.append(domain)

            unique_domains = sorted(set(valid_domains))

            st.info(f"Dominios únicos detectados para revisar: {len(unique_domains):,}")

            progress_domains = st.progress(0)
            domain_status = st.empty()

            dns_cache = {}

            if unique_domains:
                completed = 0

                with ThreadPoolExecutor(max_workers=dns_workers) as executor:
                    future_map = {
                        executor.submit(get_dns_info, domain): domain
                        for domain in unique_domains
                    }

                    total_domains = len(future_map)

                    for future in as_completed(future_map):
                        domain = future_map[future]

                        try:
                            dns_cache[domain] = future.result()
                        except Exception as e:
                            dns_cache[domain] = {
                                "domain_exists": None,
                                "has_mx": False,
                                "mx_records": "",
                                "has_a_or_aaaa": False,
                                "dns_status": "ERROR_DNS",
                                "dns_error": str(e),
                            }

                        completed += 1
                        progress_domains.progress(completed / total_domains)
                        domain_status.text(
                            f"Revisando dominios: {completed:,} de {total_domains:,}"
                        )

            progress_emails = st.progress(0)
            email_status = st.empty()

            results = []
            total_emails = len(raw_emails)

            for i, (raw_email, duplicate) in enumerate(zip(raw_emails, duplicates), start=1):
                results.append(
                    analyze_one_email(
                        raw_email=raw_email,
                        is_duplicate=duplicate,
                        dns_cache=dns_cache,
                    )
                )

                if i % 1000 == 0 or i == total_emails:
                    progress_emails.progress(i / total_emails)
                    email_status.text(f"Clasificando correos: {i:,} de {total_emails:,}")

            result_df = pd.DataFrame(results)

            order_map = {
                "ENVIAR PROBABLE": 1,
                "ENVIAR CON CUIDADO": 2,
                "REVISAR": 3,
                "NO ENVIAR": 4,
            }

            result_df["orden"] = result_df["recomendacion"].map(order_map).fillna(99)
            result_df = result_df.sort_values(by=["orden", "score"], ascending=[True, False])
            result_df = result_df.drop(columns=["orden"])

            end_time = pd.Timestamp.now()
            elapsed_seconds = round((end_time - start_time).total_seconds(), 2)

            st.success(f"Análisis terminado en {elapsed_seconds} segundos")

            st.subheader("Resumen")

            r1, r2, r3, r4, r5 = st.columns(5)

            r1.metric("Total", len(result_df))
            r2.metric("Enviar probable", int((result_df["recomendacion"] == "ENVIAR PROBABLE").sum()))
            r3.metric("Con cuidado", int((result_df["recomendacion"] == "ENVIAR CON CUIDADO").sum()))
            r4.metric("Revisar", int((result_df["recomendacion"] == "REVISAR").sum()))
            r5.metric("No enviar", int((result_df["recomendacion"] == "NO ENVIAR").sum()))

            yellow_note(
                "Cómo usar el resultado: primero manda campaña solo a los contactos marcados como ENVIAR PROBABLE. "
                "Los de ENVIAR CON CUIDADO pueden mandarse en una tanda pequeña. "
                "Los de REVISAR conviene validarlos manualmente. "
                "Los de NO ENVIAR elimínalos de la campaña."
            )

            st.subheader("Resultado")
            st.dataframe(result_df, use_container_width=True)

            csv_bytes = dataframe_to_csv_bytes(result_df)

            st.download_button(
                label="Descargar resultado en CSV",
                data=csv_bytes,
                file_name="correos_limpios.csv",
                mime="text/csv",
            )

            if len(result_df) <= 200_000:
                excel_bytes = dataframe_to_excel_bytes(result_df)

                st.download_button(
                    label="Descargar resultado en Excel",
                    data=excel_bytes,
                    file_name="correos_limpios.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                )
            else:
                st.info(
                    "Para archivos muy grandes se recomienda descargar en CSV. "
                    "Excel puede tardar demasiado o pesar mucho con más de 200,000 filas."
                )

    except Exception as e:
        st.error(f"No se pudo procesar el archivo: {e}")
