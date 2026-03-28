# cyberrisk_platform/dashboard/content_pages/analysis_content.py
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import sys, os
import pandas as pd
from dotenv import load_dotenv 
load_dotenv()

# Add the project root to Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..'))
from modules.analyser import build_host_summary, generate_summary
from modules.emailer import send_alert_email

# ── Credentials (for email sending) ───────────────────────────────────────────
GMAIL_SENDER    = os.environ.get('GMAIL_SENDER', '')
GMAIL_PASSWORD  = os.environ.get('GMAIL_PASSWORD', '')
GMAIL_RECIPIENT = os.environ.get('GMAIL_RECIPIENT', '')

# Chart colors to match dark theme (defined here for global use)
CHART_BG = "#1e2130"
GRID_COL = "#2d3148"
FONT_COL = "#e2e8f0"

def render_page():
    st.title('🔍 Security Analysis')
    st.caption('Comprehensive insights into your scanned network\'s security posture.')

    df = st.session_state.get('df')
    scan_time = st.session_state.get('scan_time', 'N/A')

    if df is None or df.empty:
        st.info('No scan data loaded yet. Run a scan from the main page or load from scan history.')
        return

    host_sum = build_host_summary(df) # This DataFrame contains all aggregated host info
    summary  = generate_summary(df, host_sum)

    # ── Header and KPIs (Consistent with mockups) ────────────────────────────────────────────────
    # Dynamic Target Name Header
    target_names = ', '.join(df['ip'].unique()) if not df['ip'].empty else 'No Targets'
    st.subheader(f'Analysis for Target(s): **{target_names}**')

    # Banner : critical condition
    st.markdown(
        f'<div style="background:{summary["colour"]};padding:20px;'
        f'border-radius:8px;text-align:center;">'
        f'<h2 style="color:white;margin:0;">'
        f'Security Posture: {summary["posture"]}</h2></div>',
        unsafe_allow_html=True
    )
    st.divider()

    # KPIs
    kpi_cols = st.columns(5)
    kpi_cols[0].metric('🖥️ Hosts Scanned',  summary['total_hosts'])
    kpi_cols[1].metric('🔓 Open Ports',     summary['total_ports'])
    kpi_cols[2].metric('🚨 Critical Hosts', summary['crit_hosts'])
    kpi_cols[3].metric('⚠️ High Risk Hosts', summary['high_hosts'])
    kpi_cols[4].metric('🦠 VT Flagged',     summary['vt_flagged'])
    st.divider()

    # ── Key Findings and Immediate Actions (Top N) ────────────────────────────────────────────────
    st.subheader('📋 Key Findings')
    for finding in summary['findings']:
        st.markdown(f'- {finding}')
    st.divider()

    st.subheader('🚀 Immediate Actions')
    st.caption('Prioritized remediation tasks for critical and high-risk findings.')

    action_df = (
        df.sort_values('risk_score', ascending=False)
          .drop_duplicates(subset=['ip', 'service', 'recommendation'])
          [['ip','port','service','risk_score','severity','recommendation']]
          .head(7)
    )

    if not action_df.empty:
        for _, row in action_df.iterrows():
            sev_colour = {
                'Critical': '#dc2626', 'High': '#ea580c',
                'Medium':   '#ca8a04', 'Low':  '#16a34a'
            }.get(row['severity'], '#6b7280')
            
            with st.expander(
                f"[{row['severity']}] **{row['ip']}:{row['port']}** ({row['service']}) — Risk: **{row['risk_score']}**",
                expanded=(row['severity'] in ['Critical', 'High'])
            ):
                st.markdown(
                    f'<span style="color:{sev_colour};font-weight:bold;">'
                    f'Action:</span> {row["recommendation"]}',
                    unsafe_allow_html=True
                )
    else:
        st.info('No specific immediate actions identified for this scan. Great job!')
    st.divider()

    # ── Email Report Section (Placed earlier for visibility) ──────────────────────────────────────
    st.subheader("📧 Send Report Email")
    email_ready = bool(GMAIL_SENDER and GMAIL_PASSWORD and GMAIL_RECIPIENT)

    if not email_ready:
        st.warning("⚠️ Email credentials are incomplete. Please set GMAIL_SENDER, GMAIL_PASSWORD (App Password), and GMAIL_RECIPIENT in your environment variables to enable email reports.")

    send_email_button_label = (
        f"Send Report Email ({summary['posture']})"
    )

    send_btn = st.button(
        send_email_button_label,
        type="primary",
        disabled=not email_ready,
        width='stretch'
    )

    if send_btn and email_ready:
        with st.spinner("Sending report email..."):
            result = send_alert_email(GMAIL_SENDER, GMAIL_PASSWORD, GMAIL_RECIPIENT, df, scan_time, summary)
        if result is True:
            st.success(f"✅ Report email sent successfully to {GMAIL_RECIPIENT}!")
        else:
            st.error(f"❌ Failed to send email: {result}")
            st.caption("Common fixes: Check your Gmail App Password is correct (16 characters, no spaces), make sure 2-Step Verification is ON for your Gmail account, and confirm recipient email is valid.")
    st.divider()

    # ── Interactive Charts (Optimized for space, removed two charts) ──────────────────────────────────
    st.subheader('📈 Visualized Insights')
    st.caption('Hover for details • Drag to zoom • Double-click to reset • Click legend to toggle.')

    # Row 1 of Charts (2 columns)
    chart_cols_1 = st.columns(2)

    with chart_cols_1[0]:
        st.markdown("##### Total Risk per IP")
        fig_total_risk_ip = px.bar(host_sum, x="ip", y="max_risk", 
                                      color="max_risk", color_continuous_scale="Viridis", text="max_risk",
                                      labels={"ip": "IP Address", "max_risk": "Total Risk Score (Max)"},
                                      hover_data={"overall_severity": True, "services": True, "malicious": True, "avg_risk": True})
        fig_total_risk_ip.update_traces(textposition="outside")
        fig_total_risk_ip.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20), showlegend=False, 
                                        paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL, 
                                        xaxis_title="IP Address", yaxis_title="Total Risk Score",
                                        xaxis=dict(gridcolor=GRID_COL), yaxis=dict(gridcolor=GRID_COL))
        st.plotly_chart(fig_total_risk_ip, width='stretch')

    with chart_cols_1[1]:
        st.markdown("##### Risk Score by Service")
        service_risk_avg = df.groupby('service')['risk_score'].mean().reset_index(name='Avg Risk Score')
        service_risk_avg = service_risk_avg.sort_values('Avg Risk Score', ascending=False).head(10)
        
        fig_risk_by_service = px.bar(service_risk_avg, x="service", y="Avg Risk Score",
                                     color="Avg Risk Score", color_continuous_scale="Plasma", text="Avg Risk Score",
                                     labels={"service": "Service Name", "Avg Risk Score": "Average Risk Score"},
                                     hover_data=["service", "Avg Risk Score"])
        fig_risk_by_service.update_traces(textposition="outside")
        fig_risk_by_service.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20), showlegend=False,
                                          paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL,
                                          xaxis_title="Service Name", yaxis_title="Average Risk Score",
                                          xaxis=dict(gridcolor=GRID_COL), yaxis=dict(gridcolor=GRID_COL))
        st.plotly_chart(fig_risk_by_service, width='stretch')

    # Row 2 of Charts (2 columns)
    # This row will now contain Top 10 Services Exposed and Top Riskiest Products/Versions
    chart_cols_2 = st.columns(2)

    with chart_cols_2[0]:
        st.markdown("##### Top 10 Services Exposed")
        service_counts = df[df['state'] == 'open']['service'].value_counts().nlargest(10).reset_index(name='Count')
        service_counts.columns = ['Service', 'Count']
        fig_services_exposed = px.bar(service_counts, x="Count", y="Service", orientation="h",
                                      color="Count", color_continuous_scale="Purples", text="Count",
                                      labels={"Count": "Number of Times Exposed", "Service": "Service Name"},
                                      hover_data=["Count", "Service"])
        fig_services_exposed.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20), showlegend=False, paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL,
                                           yaxis=dict(categoryorder="total ascending", gridcolor=GRID_COL), xaxis=dict(gridcolor=GRID_COL))
        st.plotly_chart(fig_services_exposed, width='stretch')
        
    with chart_cols_2[1]:
        st.markdown("##### Top Riskiest Products/Versions")
        risky_products = df[df['product'] != ''].copy()
        if not risky_products.empty:
            product_risk = risky_products.groupby(['product', 'version'])['risk_score'].mean().reset_index(name='Avg Risk')
            product_risk['Product (Version)'] = product_risk['product'] + (product_risk['version'].apply(lambda x: f' ({x})' if x else ''))
            product_risk = product_risk.sort_values('Avg Risk', ascending=False).head(10)
            
            fig_product_risk = px.bar(product_risk, x="Avg Risk", y="Product (Version)", orientation="h",
                                      color="Avg Risk", color_continuous_scale="Viridis", text="Avg Risk",
                                      labels={"Avg Risk": "Average Risk Score", "Product (Version)": "Product and Version"},
                                      hover_data=["Avg Risk", "Product (Version)"])
            fig_product_risk.update_layout(height=300, margin=dict(l=20, r=20, t=30, b=20), showlegend=False, paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL,
                                           yaxis=dict(categoryorder="total ascending", gridcolor=GRID_COL), xaxis=dict(gridcolor=GRID_COL))
            st.plotly_chart(fig_product_risk, width='stretch')
        else:
            st.info("No product/version data to display.")

    st.divider() # Divider after the bar charts

    # Row 3 of Charts (1 column for the heatmap)
    # The Correlation Heatmap now takes its own full row.
    st.subheader('🔥 Risk-Based Correlation Heatmap')
    st.caption('Identifies how closely different risk metrics are related. Red indicates strong positive correlation.')

    correlation_cols = ['risk_score', 'exposure_score', 'threat_score', 'context_score', 'malicious_reports']
    
    valid_correlation_cols = [col for col in correlation_cols if col in df.columns and pd.api.types.is_numeric_dtype(df[col])]
    
    if len(valid_correlation_cols) >= 2:
        correlation_matrix = df[valid_correlation_cols].corr()

        fig_corr_heatmap = px.imshow(correlation_matrix,
                                      text_auto=".2f",
                                      aspect="auto",
                                      color_continuous_scale=[(0, "green"), (0.5, "yellow"), (1, "red")],
                                      labels=dict(color="Correlation"),
                                      x=correlation_matrix.columns, y=correlation_matrix.index)
        fig_corr_heatmap.update_xaxes(side="bottom")
        fig_corr_heatmap.update_layout(height=500, margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor=CHART_BG, plot_bgcolor=CHART_BG, font_color=FONT_COL,
                                       xaxis_showgrid=False, yaxis_showgrid=False,
                                       xaxis_tickangle=-45)
        st.plotly_chart(fig_corr_heatmap, width='stretch')
    else:
        st.info("Insufficient numeric data to generate a correlation heatmap.")
    st.divider()


    # ── TABLES (At the very bottom, fixed height for scrolling) ───────────────────
    st.subheader('📋 Raw Scan Data Tables')
    st.caption('Detailed Nmap and VirusTotal output. Use the internal scrollbars to navigate.')

    # Host Summary Table
    st.markdown("##### Host Summary (Aggregated per IP)")
    with st.container(height=300, border=True):
        st.dataframe(
            host_sum.set_index('ip')[['open_ports', 'max_risk', 'avg_risk', 'overall_severity',
                                    'critical_count', 'high_count', 'malicious', 'country', 'services']],
            width='stretch',
            column_config={
                "open_ports": st.column_config.NumberColumn("Open Ports", width="small"),
                "max_risk": st.column_config.NumberColumn("Max Risk", format="%.1f", width="small"),
                "avg_risk": st.column_config.NumberColumn("Avg Risk", format="%.1f", width="small"),
                "overall_severity": st.column_config.TextColumn("Overall Severity", width="small"),
                "critical_count": st.column_config.NumberColumn("Critical Ports", width="small"),
                "high_count": st.column_config.NumberColumn("High Ports", width="small"),
                "malicious": st.column_config.NumberColumn("VT Malicious", width="small"),
                "country": st.column_config.TextColumn("Country", width="small"),
                "services": st.column_config.TextColumn("Services", width="large"),
            }
        )

    # Detailed Risk Overview Table
    st.markdown("##### Detailed Scan Entries (All Ports/Services)")
    with st.container(height=400, border=True): # Use a container with fixed height
        st.dataframe(
            df[['ip', 'port', 'protocol', 'state', 'service', 'product', 'version', 'severity', 'risk_score',
                'malicious_reports', 'suspicious_count', 'harmless_count', 'community_score', 'country', 'network', 'categories', 'recommendation']]
            .sort_values('risk_score', ascending=False)
            .reset_index(drop=True),
            width='stretch',
            column_config={
                "ip": st.column_config.TextColumn("IP", width="small"),
                "port": st.column_config.TextColumn("Port", width="tiny"),
                "protocol": st.column_config.TextColumn("Proto", width="tiny"),
                "state": st.column_config.TextColumn("State", width="tiny"),
                "service": st.column_config.TextColumn("Service", width="small"),
                "product": st.column_config.TextColumn("Product", width="small"),
                "version": st.column_config.TextColumn("Version", width="small"),
                "severity": st.column_config.TextColumn("Severity", width="small"),
                "risk_score": st.column_config.NumberColumn("Risk Score", format="%.1f", width="small"),
                "malicious_reports": st.column_config.NumberColumn("VT Malicious", width="small"),
                "suspicious_count": st.column_config.NumberColumn("VT Suspicious", width="small"),
                "harmless_count": st.column_config.NumberColumn("VT Harmless", width="small"),
                "community_score": st.column_config.NumberColumn("VT Community", width="small"),
                "country": st.column_config.TextColumn("Country", width="small"),
                "network": st.column_config.TextColumn("Network", width="small"),
                "categories": st.column_config.TextColumn("VT Categories", width="medium"),
                "recommendation": st.column_config.TextColumn("Recommendation", width="large"),
            }
        )
