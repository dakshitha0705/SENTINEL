"""Reports & Evaluation: verified incident reports and exports, the evaluation lab, and the offline evidence.
Reporting and evaluation are separate views; every number in Evaluation is read from a results/*.json file."""
from __future__ import annotations

import streamlit as st

from . import evaluation, reports, system_settings
from ..state import S

VIEWS = ["Report", "Evaluation", "Offline evidence"]


def render():
    if S.get("re_view") not in VIEWS:
        S.re_view = "Report"
    view = st.segmented_control("View", VIEWS, key="re_view", label_visibility="collapsed",
                                format_func=lambda v: {"Report": ":material/description: Report",
                                                       "Evaluation": ":material/monitoring: Evaluation",
                                                       "Offline evidence": ":material/wifi_off: Offline evidence"}[v]) or "Report"
    if view == "Report":
        reports.render()
    elif view == "Evaluation":
        evaluation.render()
    else:
        st.caption("Two different things: the *0 external connections* indicator is a live socket check of SENTINEL, Ollama "
                   "and NEXUS; the runs below were recorded by scripts/offline_check.py, and are labelled “offline test” "
                   "only when the internet was unreachable before and after the run (Wi-Fi physically off).")
        system_settings.offline_validation()
