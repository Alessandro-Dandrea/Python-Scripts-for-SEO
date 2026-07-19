import streamlit as st
import pandas as pd
import plotly.express as px
import re
import io
import socket

st.set_page_config(page_title="Log Analyzer", layout="wide")

st.title("📊 Server Log Analyzer")
st.write("Upload your Nginx/Apache log file to get started. Credits: https://www.alessandro-dandrea.com/")

# ─── Known bot patterns and their expected reverse-DNS domains ───────────────
# Inspired by the SEJ article's "Validate Requests" section:
# user-agent keyword  →  legitimate reverse-DNS domain suffix
BOT_DEFINITIONS = {
    "Googlebot":       ["googlebot.com", "google.com"],
    "bingbot":         ["search.msn.com"],
    "Baiduspider":     ["baidu.com", "baidu.jp"],
    "YandexBot":       ["yandex.ru", "yandex.net", "yandex.com"],
    "DuckDuckBot":     ["duckduckgo.com"],
    "Applebot":        ["apple.com"],
    "AhrefsBot":       ["ahrefs.com"],
    "SemrushBot":      ["semrush.com"],
    "MJ12bot":         ["majestic.com", "mj12bot.com"],
    "PetalBot":        ["petalsearch.com", "aspiegel.com"],
    "Sogou":           ["sogou.com"],
    "Bytespider":      ["bytedance.com"],
    "GPTBot":          ["openai.com"],
    "Perplexitybot":   ["perplexity.ai"],
    "ClaudeBot":       ["anthropic.com"],
    "facebookexternalhit": ["facebook.com", "fbsv.net"],
    "Twitterbot":      ["twttr.com", "twitter.com"],
    "LinkedInBot":     ["linkedin.com"],
}

# Build a single regex that matches any known bot in the user-agent string
_BOT_UA_PATTERN = re.compile(
    "|".join(re.escape(k) for k in BOT_DEFINITIONS),
    re.IGNORECASE,
)


def identify_bot(user_agent: str) -> str | None:
    """Return the bot name if the UA matches a known bot pattern, else None."""
    for bot_name in BOT_DEFINITIONS:
        if bot_name.lower() in user_agent.lower():
            return bot_name
    return None


def reverse_dns(ip: str) -> str:
    """Perform a reverse DNS lookup for an IP address.

    Mirrors the article's approach using socket (stdlib) instead of
    dnspython so we don't add an extra dependency.
    """
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "N/A"


@st.cache_data
def validate_bot_ip(ip: str, bot_name: str) -> bool:
    """Validate that an IP genuinely belongs to the claimed bot.

    1. Reverse-DNS the IP  →  hostname
    2. Check hostname ends with one of the expected domains
    3. Forward-DNS the hostname  →  must resolve back to the original IP
    """
    hostname = reverse_dns(ip)
    if hostname == "N/A":
        return False

    expected_domains = BOT_DEFINITIONS.get(bot_name, [])
    if not any(hostname.rstrip(".").endswith(domain) for domain in expected_domains):
        return False

    # Forward verification: hostname must resolve back to the original IP
    try:
        resolved_ip = socket.gethostbyname(hostname)
        return resolved_ip == ip
    except (socket.herror, socket.gaierror, OSError):
        return False


# ─── File uploader ───────────────────────────────────────────────────────────
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

    # ─── Bot identification: tag every row with a bot name (or None) ─────
    df['detected_bot'] = df['user_agent'].apply(identify_bot)

    user_agents = sorted(df['user_agent'].unique())

    def format_user_agent(ua):
        return ua if len(ua) <= 80 else f"{ua[:77]}..."

    # ─── Sidebar ─────────────────────────────────────────────────────────
    with st.sidebar:
        st.header("Filters")

        analysis_mode = st.radio(
            "Analysis mode",
            ["🤖 Verified Bots Only", "🌐 All Traffic"],
            help=(
                "**Verified Bots Only** filters to known bot user-agents "
                "and validates their IPs via reverse DNS (as described in "
                "the SEJ article). **All Traffic** shows every request."
            ),
        )

        if analysis_mode == "🤖 Verified Bots Only":
            # Let user pick which bots to include
            detected_bots = sorted(
                df.loc[df['detected_bot'].notna(), 'detected_bot'].unique()
            )
            selected_bots = st.multiselect(
                "Bots to verify",
                options=detected_bots,
                default=detected_bots,
                help="Select which bot families to validate via reverse DNS.",
            )
            do_dns_validation = st.checkbox(
                "Validate IPs via reverse DNS",
                value=True,
                help=(
                    "When enabled, each bot IP is verified with a "
                    "reverse+forward DNS check to confirm it genuinely "
                    "belongs to the claimed search engine. "
                    "Disable for faster (but unverified) results."
                ),
            )
            
            # Get unique User Agents for the selected bot families
            bot_df = df[df['detected_bot'].isin(selected_bots)]
            bot_uas = sorted(bot_df['user_agent'].unique())
            selected_bot_ua = st.selectbox(
                "Filter by User Agent",
                options=["All"] + bot_uas,
                index=0,
                format_func=format_user_agent,
                help="Filter results to show only a specific User Agent.",
            )
        else:
            selected_agents = st.multiselect(
                "User agents",
                options=user_agents,
                default=[],
                placeholder="All user agents",
                format_func=format_user_agent,
                help="Select one or more user agents. Leave empty to include all entries.",
            )

    # ─── Apply filters ───────────────────────────────────────────────────
    if analysis_mode == "🤖 Verified Bots Only":
        # Step 1: filter to rows whose UA matches a selected bot
        df_bots = df[df['detected_bot'].isin(selected_bots)].copy()
        total_bot_rows = len(df_bots)

        if do_dns_validation and not df_bots.empty:
            # Step 2: deduplicate IPs to minimize DNS lookups (per the article)
            unique_ips = df_bots[['ip', 'detected_bot']].drop_duplicates(subset='ip')

            with st.spinner(
                f"🔍 Validating {len(unique_ips)} unique bot IPs via reverse DNS…"
            ):
                unique_ips['is_valid'] = unique_ips.apply(
                    lambda row: validate_bot_ip(row['ip'], row['detected_bot']),
                    axis=1,
                )

            valid_ips = set(unique_ips.loc[unique_ips['is_valid'], 'ip'])
            df_view = df_bots[df_bots['ip'].isin(valid_ips)].copy()

            # Show validation stats
            n_valid = unique_ips['is_valid'].sum()
            n_invalid = len(unique_ips) - n_valid
            col_v1, col_v2, col_v3 = st.columns(3)
            col_v1.metric("Unique Bot IPs", len(unique_ips))
            col_v2.metric("✅ Verified", int(n_valid))
            col_v3.metric("❌ Failed DNS", int(n_invalid))

            if n_invalid > 0:
                with st.expander("Show failed (spoofed) IPs"):
                    failed = unique_ips[~unique_ips['is_valid']][['ip', 'detected_bot']]
                    failed.columns = ['IP', 'Claimed Bot']
                    st.dataframe(failed, use_container_width=True)

            st.success(
                f"Showing **{len(df_view)}** verified bot requests "
                f"(filtered from {total_bot_rows} claimed bot hits across {len(df)} total log entries)."
            )
        else:
            df_view = df_bots
            if df_view.empty:
                st.warning("No bot user-agents detected in the log file.")
            else:
                st.success(
                    f"Showing {len(df_view)} bot requests "
                    f"(DNS validation disabled) from {len(df)} total log entries."
                )

        # Apply User Agent filter if a specific one is selected
        if selected_bot_ua != "All":
            df_view = df_view[df_view['user_agent'] == selected_bot_ua]
            st.info(f"Filtering results for User Agent: `{selected_bot_ua}` ({len(df_view)} requests match).")
    else:
        # "All Traffic" mode — same behaviour as the original script
        if selected_agents:
            df_view = df[df['user_agent'].isin(selected_agents)]
            st.success(
                f"Showing {len(df_view)} of {len(df)} log entries "
                f"for {len(selected_agents)} selected user agent(s)."
            )
        else:
            df_view = df
            st.success(f"Parsed {len(df)} lines successfully!")

    # ─── Charts ──────────────────────────────────────────────────────────
    if df_view.empty:
        st.warning("No log entries match the current filters.")
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

        st.write("### URLs Performance")
        if not df_view.empty:
            df_sorted = df_view.sort_values('timestamp')
            url_perf = df_sorted.groupby('url').last().reset_index()
            url_perf = url_perf[['url', 'timestamp', 'status']]
            url_perf.columns = ['Path', 'Last Time Crawled', 'Last Status Code']
            url_perf = url_perf.sort_values(by='Last Time Crawled', ascending=False)
            st.dataframe(url_perf, use_container_width=True)
        else:
            st.write("No performance data available.")

        user_agent_counts = df_view['user_agent'].value_counts().reset_index()
        user_agent_counts.columns = ['user_agent', 'count']

        st.write("### User Agent Hits")
        st.dataframe(user_agent_counts, width='stretch')

        # In bot mode, show a breakdown by verified bot family
        if analysis_mode == "🤖 Verified Bots Only" and 'detected_bot' in df_view.columns:
            bot_counts = df_view['detected_bot'].value_counts().reset_index()
            bot_counts.columns = ['bot', 'count']
            st.write("### Verified Bot Breakdown")
            fig_bots = px.bar(
                bot_counts,
                x='bot',
                y='count',
                labels={'bot': 'Bot', 'count': 'Requests'},
                color='bot',
            )
            st.plotly_chart(fig_bots, width='stretch')

        st.write("### Raw Data")
        st.dataframe(df_view)