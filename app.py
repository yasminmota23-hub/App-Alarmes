import streamlit as st
import requests
from datetime import datetime

# === CONFIGURAÇÕES ===
BASE_URL = "https://api.maas-moura.com"

# === LOGIN ===
def obter_token(email, senha):
    url = f"{BASE_URL}/auth/login"
    payload = {"email": email, "password": senha}
    r = requests.post(url, json=payload)
    if r.status_code == 200:
        return r.json().get("access_token")
    return None

# === CONSULTA DE ALARMES ===
def consultar_alarmes(site_id, token):
    url = f"{BASE_URL}/alarms/findOpenAlarmsById/{site_id}"
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(url, headers=headers)
    if r.status_code != 200:
        return None
    try:
        data = r.json()
        if not data:
            return "vazio"
        elif isinstance(data, list) and "alertName" not in data[0]:
            return "invalido"
        else:
            return data
    except:
        return None

# === INTERFACE ===
st.set_page_config(page_title="Consulta de Alarmes", page_icon="🚨")
st.title("🚨 Consulta de Alarmes - MOURA")

with st.form("login_form"):
    email = st.text_input("📧 E-mail")
    senha = st.text_input("🔒 Senha", type="password")
    site_id = st.text_input("🏷️ ID do Site (ex: PEFCX)").strip().upper()
    submitted = st.form_submit_button("Consultar")

if submitted:
    with st.spinner("🔄 Consultando..."):
        token = obter_token(email, senha)
        if token:
            resultado = consultar_alarmes(site_id, token)
            if resultado == "vazio":
                st.success("✅ Site válido, mas sem alarmes ativos.")
            elif resultado == "invalido":
                st.error("❌ Site inválido ou resposta inesperada da API.")
            elif isinstance(resultado, list):
                st.info(f"🔎 {len(resultado)} alarme(s) encontrado(s):")
                for alarme in resultado:
                    data_formatada = datetime.fromisoformat(
                        alarme["startDate"].replace("Z", "+00:00")
                    ).strftime("%d/%m/%Y %H:%M:%S")
                    st.warning(
                        f"[{alarme['alertLevel'].upper()}] {alarme['alertName']} - desde {data_formatada} (Cód. {alarme['alertCode']})"
                    )
            else:
                st.error("❌ Erro ao processar resposta da API.")
        else:
            st.error("❌ Falha no login. Verifique e-mail e senha.")
