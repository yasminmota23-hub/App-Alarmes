import streamlit as st
import requests
from datetime import datetime

# === CONFIGURAÇÕES ===
BASE_URL = "https://api.maas-moura.com"
EMAIL = "yasmin.mota@grupomoura.com"   # 🔁 SUBSTITUA PELO SEU E-MAIL
SENHA = "Yasmim@2023"     # 🔁 SUBSTITUA PELA SUA SENHA

# === LOGIN ===
def obter_token():
    url = f"{BASE_URL}/auth/login"
    payload = {"email": EMAIL, "password": SENHA}
    r = requests.post(url, json=payload)
    if r.status_code == 200:
        return r.json().get("token")
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

# === INTERFACE STREAMLIT ===
st.set_page_config(page_title="Consulta de Alarmes", page_icon="🚨")
st.title("🚨 Consulta de Alarmes - MOURA")

site_id = st.text_input("🏷️ Digite o ID do site (ex: PEFCX)").strip().upper()

if st.button("Consultar"):
    with st.spinner("🔄 Fazendo login e consultando..."):
        token = obter_token()
        if token:
            resultado = consultar_alarmes(site_id, token)
            if resultado == "vazio":
                st.success("✅ Site sem alarmes ativos ou inexistente.")
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
            st.error("❌ Erro no login automático. Verifique e-mail/senha no código.")
