"""
Drop here for future readings: https://www.searchenginejournal.com/python-analysis-server-log-files/412898/
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import re
import io

st.set_page_config(page_title="Log Analyzer", layout="wide")

st.title("📊 Server Log Analyzer")
st.write("Upload your Nginx/Apache log file to get started. Credits: https://www.alessandro-dandrea.com/")

# File uploader
uploaded_file = st.file_uploader("Choose a log file", type="txt")

if uploaded_file is not None:
    # Read file
    stringio = io.StringIO(uploaded_file.getvalue().decode("utf-8"))
    lines = stringio.readlines()

    # Parsing logic
    log_pattern = r'(?P<ip>\S+) - - \[(?P<timestamp>.*?)\] "(?P<request>.*?)" (?P<status>\d+) (?P<size>\S+) "(?P<referrer>.*?)" "(?P<user_agent>.*?)"'
    
    data = []
    for line in lines:
        match = re.search(log_pattern, line)
        if match:
            data.append(match.groupdict())

    df = pd.DataFrame(data)
    
    # Cleaning
    df['timestamp'] = pd.to_datetime(df['timestamp'].str.split(' ').str[0], format='%d/%b/%Y:%H:%M:%S', errors='coerce')
    df['status'] = pd.to_numeric(df['status'])
    df['size'] = pd.to_numeric(df['size'].replace('-', '0'))
    df['url'] = df['request'].str.split(' ').str[1]

    user_agents = sorted(df['user_agent'].unique())

    def format_user_agent(ua):
        return ua if len(ua) <= 80 else f"{ua[:77]}..."

    with st.sidebar:
        st.header("Filters")
        selected_agents = st.multiselect(
            "User agents",
            options=user_agents,
            default=[],
            placeholder="All user agents",
            format_func=format_user_agent,
            help="Select one or more user agents. Leave empty to include all entries.",
        )

    if selected_agents:
        df_view = df[df['user_agent'].isin(selected_agents)]
        st.success(
            f"Showing {len(df_view)} of {len(df)} log entries "
            f"for {len(selected_agents)} selected user agent(s)."
        )
    else:
        df_view = df
        st.success(f"Parsed {len(df)} lines successfully!")

    if df_view.empty:
        st.warning("No log entries match the selected user agents.")
    else:
        # Layout for charts
        col1, col2 = st.columns(2)

        with col1:
            fig1 = px.pie(df_view, names='status', title="Response Status Codes")
            st.plotly_chart(fig1, width='stretch')

        with col2:
            df_time = df_view.set_index('timestamp').resample('h').size().reset_index(name='requests')
            fig2 = px.line(df_time, x='timestamp', y='requests', title="Requests per Hour")
            st.plotly_chart(fig2, width='stretch')

        top_urls = df_view['url'].value_counts().head(10).reset_index()
        top_urls.columns = ['url', 'count']

        st.write("### Top 10 Requested URLs")
        fig3 = px.bar(
            top_urls,
            x='count',
            y='url',
            orientation='h',
            labels={'count': 'Requests', 'url': 'URL'},
        )
        fig3.update_layout(
            yaxis={'categoryorder': 'total ascending'},
            xaxis={'range': [0, top_urls['count'].max() * 1.05]},
        )
        st.plotly_chart(fig3, width='stretch')

        user_agent_counts = df_view['user_agent'].value_counts().reset_index()
        user_agent_counts.columns = ['user_agent', 'count']

        st.write("### User Agent Hits")
        st.dataframe(user_agent_counts, width='stretch')

        st.write("### Raw Data")
        st.dataframe(df_view)