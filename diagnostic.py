"""
DIAGNOSTIC: Run this as your main Streamlit app temporarily to debug tab issues.
Replace 'app.py' as the main module in Streamlit Cloud settings, or rename this to app.py.
"""
import streamlit as st
import sys
import importlib

st.set_page_config(page_title="SIEM Diagnostic", layout="wide")
st.title("🔧 SIEM App Diagnostic")

# 1. Python version
st.markdown(f"**Python:** `{sys.version}`")

# 2. Test all imports
imports_status = {}
for mod_name in ["yaml", "pandas", "requests", "sigma", "sigma.rule", "sigma.backends.splunk"]:
    try:
        importlib.import_module(mod_name)
        imports_status[mod_name] = "✅ OK"
    except Exception as e:
        imports_status[mod_name] = f"❌ {type(e).__name__}: {e}"

st.markdown("### Import Status")
for mod, status in imports_status.items():
    st.markdown(f"- `{mod}`: {status}")

# 3. Test DetectionEngine import
st.markdown("### DetectionEngine Import")
try:
    from utils.detection_engine import DetectionEngine
    st.success("✅ DetectionEngine imported successfully")
    
    engine = DetectionEngine()
    st.success("✅ DetectionEngine() instantiated")
except Exception as e:
    import traceback
    st.error(f"❌ {type(e).__name__}: {e}")
    st.code(traceback.format_exc())

# 4. Test tab rendering
st.markdown("### Tab Rendering Test")
tab1, tab2, tab3, tab4, tab5, tab6, tab7 = st.tabs([
    "Tab 1", "Tab 2", "Tab 3", "Tab 4", "Tab 5", "Tab 6", "🛡️ Detection"
])

with tab1:
    st.write("Tab 1 works")
with tab2:
    st.write("Tab 2 works")
with tab3:
    st.write("Tab 3 works")
with tab4:
    st.write("Tab 4 works")
with tab5:
    st.write("Tab 5 works")
with tab6:
    st.write("Tab 6 works")
with tab7:
    st.write("🛡️ Tab 7 (Detection) works!")
    st.markdown("If you can see this, the tab rendering is fine.")
    st.markdown("The issue is likely in the detection engine code within app.py.")

# 5. File system check
st.markdown("### File System")
import os
files_to_check = [
    "app.py",
    "utils/__init__.py",
    "utils/detection_engine.py",
    "utils/kb_loader.py",
    "utils/ai_client.py",
    "utils/usecase_loader.py",
    "requirements.txt",
]
for f in files_to_check:
    exists = os.path.exists(f)
    size = os.path.getsize(f) if exists else 0
    st.markdown(f"- `{f}`: {'✅' if exists else '❌'} ({size} bytes)")
