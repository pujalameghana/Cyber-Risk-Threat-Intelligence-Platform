# cyberisk_platform/dashboard/content_pages/scan_history_content.py
import streamlit as st
import pandas as pd
import sys, os
from datetime import datetime
import plotly.express as px # Added for history charts
from dotenv import load_dotenv 
load_dotenv()

# Add the project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from modules.database import load_history, load_scan_by_id
from modules.analyser import _classify # For classifying max_risk_score in history

# Chart colors to match dark theme (defined here for global use)
CHART_BG = "#1e2130"
GRID_COL = "#2d3148"
FONT_COL = "#e2e8f0"

def render_page():
    st.title('📜 Scan History')
    st.caption('Browse and load past scan reports from the database.')

    history_df = load_history()

    if history_df.empty:
        st.info('No scan history found. Run a scan from the main page to start building your history!')
        return # Exit early if no history

    # Add Overall KPIs for History Page
    st.subheader('History Overview')
    total_scans = len(history_df)
    total_hosts_all_scans = history_df['total_hosts'].sum()
    avg_max_risk = history_df['max_risk_score'].mean().round(1) if not history_df.empty else 0.0
    highest_recorded_risk = history_df['max_risk_score'].max().round(1) if not history_df.empty else 0.0

    kpi_cols = st.columns(4)
    kpi_cols[0].metric('Total Scans', total_scans)
    kpi_cols[1].metric('Total Hosts (Cumulative)', total_hosts_all_scans)
    kpi_cols[2].metric('Avg Max Risk Score', avg_max_risk)
    kpi_cols[3].metric('Highest Risk Recorded', highest_recorded_risk, 
                       delta=_classify(highest_recorded_risk), delta_color='inverse') # Use delta_color for severity indication
    st.divider()

    # Chart 1: Max Risk Score Trend Over Time
    st.subheader('📈 Max Risk Score Trend')
    fig_risk_trend = px.line(history_df.sort_values('scan_time'), x='scan_time', y='max_risk_score',
                             title='Max Risk Score Over Time',
                             labels={'scan_time': 'Scan Time', 'max_risk_score': 'Max Risk Score'},
                             markers=True)
    fig_risk_trend.update_layout(height=350, margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL,
                                 xaxis=dict(gridcolor=GRID_COL), yaxis=dict(gridcolor=GRID_COL))
    st.plotly_chart(fig_risk_trend, width='stretch')
    st.divider()

    st.subheader('Past Scans Table')
    # Use st.container with a fixed height for scrolling if the table is too long
    with st.container(height=300, border=True):
        st.dataframe(
            history_df[['id', 'scan_time', 'targets', 'total_hosts', 'total_ports', 'high_risk', 'max_risk_score']].set_index('id'),
            width='stretch',
            selection_mode="single-row",
            column_config={
                "scan_time": st.column_config.DatetimeColumn(
                    "Scan Time", format="YYYY-MM-DD HH:mm:ss"
                ),
                "targets": st.column_config.TextColumn("Targets"),
                "total_hosts": st.column_config.NumberColumn("Hosts"),
                "total_ports": st.column_config.NumberColumn("Ports"),
                "high_risk": st.column_config.NumberColumn("High/Critical Ports"),
                "max_risk_score": st.column_config.NumberColumn("Max Risk", format="%.1f"),
            }
        )

    selected_id_from_session = st.session_state.get('selected_scan_id')
    scan_ids = history_df['id'].tolist()
    default_index = 0
    if selected_id_from_session in scan_ids:
        default_index = scan_ids.index(selected_id_from_session)
    elif scan_ids:
        default_index = 0

    selected_scan_id_from_dropdown = st.selectbox(
        'Select a Scan ID to view details:',
        options=scan_ids,
        index=default_index,
        format_func=lambda x: f"Scan ID: {x} - {history_df[history_df['id'] == x]['scan_time'].iloc[0]} - {history_df[history_df['id'] == x]['targets'].iloc[0]}"
    )
    
    st.session_state.selected_scan_id = selected_scan_id_from_dropdown

    if st.button(f'Load Scan ID {st.session_state.selected_scan_id} into Current View', type='primary', width='stretch'):
        with st.spinner(f'Loading full results for Scan ID {st.session_state.selected_scan_id}...'):
            full_scan_df = load_scan_by_id(st.session_state.selected_scan_id)
            if not full_scan_df.empty:
                st.session_state.df = full_scan_df
                st.session_state.scan_time = history_df[history_df['id'] == st.session_state.selected_scan_id]['scan_time'].iloc[0]
                st.session_state.last_refreshed = datetime.now().strftime('%d %b %Y  %H:%M:%S')
                st.success(f'Scan ID {st.session_state.selected_scan_id} loaded successfully! Navigating to "Analysis" page.')
                st.session_state.current_page = "Analysis" # Navigate to Analysis page
                st.rerun() 
            else:
                st.error(f'Failed to load data for Scan ID {st.session_state.selected_scan_id}. It might be corrupted or missing.')
