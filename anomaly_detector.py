import pandas as pd
import re

# ─── Known bot patterns and their expected reverse-DNS domains ───────────────
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


def identify_bot(user_agent: str) -> str | None:
    """Return the bot name if the UA matches a known bot pattern, else None."""
    if not isinstance(user_agent, str):
        return None
    for bot_name in BOT_DEFINITIONS:
        if bot_name.lower() in user_agent.lower():
            return bot_name
    return None


def get_ua_family(user_agent: str) -> str:
    """Return the user agent family (bot or browser name) for the user agent string."""
    bot = identify_bot(user_agent)
    if bot:
        bot_display_names = {
            "Googlebot": "Googlebot",
            "bingbot": "Bingbot",
            "Baiduspider": "Baiduspider",
            "YandexBot": "YandexBot",
            "DuckDuckBot": "DuckDuckBot",
            "Applebot": "Applebot",
            "AhrefsBot": "AhrefsBot",
            "SemrushBot": "SemrushBot",
            "MJ12bot": "Majestic / MJ12bot",
            "PetalBot": "PetalBot",
            "Sogou": "Sogou",
            "Bytespider": "Bytespider",
            "GPTBot": "GPTBot",
            "Perplexitybot": "PerplexityBot",
            "ClaudeBot": "ClaudeBot",
            "facebookexternalhit": "Facebook External Hit",
            "Twitterbot": "Twitterbot",
            "LinkedInBot": "LinkedInBot",
        }
        return bot_display_names.get(bot, bot)

    ua_lower = user_agent.lower()
    if "edg/" in ua_lower or "edge" in ua_lower:
        return "Edge"
    elif "chrome" in ua_lower:
        return "Chrome"
    elif "firefox" in ua_lower:
        return "Firefox"
    elif "safari" in ua_lower:
        return "Safari"
    elif "opera" in ua_lower or "opr/" in ua_lower:
        return "Opera"
    elif "msie" in ua_lower or "trident/" in ua_lower:
        return "Internet Explorer"
    
    return "Other / Unknown"


def categorize_ua(user_agent: str) -> str:
    """Normalize user agent to one of the specified categories:
    Googlebot, Bingbot, GPTBot, PerplexityBot, ClaudeBot, human browser, other
    """
    if not isinstance(user_agent, str):
        return "other"
    
    bot = identify_bot(user_agent)
    if bot:
        bot_lower = bot.lower()
        if "googlebot" in bot_lower:
            return "Googlebot"
        elif "bingbot" in bot_lower:
            return "Bingbot"
        elif "gptbot" in bot_lower:
            return "GPTBot"
        elif "perplexitybot" in bot_lower:
            return "PerplexityBot"
        elif "claudebot" in bot_lower:
            return "ClaudeBot"
        else:
            return "other"
            
    # Check if human browser
    ua_lower = user_agent.lower()
    browsers = ["chrome", "safari", "firefox", "edge", "edg/", "opera", "msie", "trident"]
    if any(browser in ua_lower for browser in browsers):
        return "human browser"
        
    return "other"


def detect_anomalies(df: pd.DataFrame, min_requests: int = 5, variance_threshold: float = 0.25) -> pd.DataFrame:
    """Identify inconsistent HTTP response byte sizes on the same URL for different user agents."""
    if df.empty:
        return pd.DataFrame()
        
    working_df = df.copy()
    
    # Map columns to standard names
    col_mapping = {
        'url': 'url',
        'user_agent': 'user_agent',
        'size': 'bytes',
        'status': 'status_code'
    }
    for col, std_col in col_mapping.items():
        if col in working_df.columns and std_col not in working_df.columns:
            working_df[std_col] = working_df[col]
            
    # Ensure types are correct
    working_df['bytes'] = pd.to_numeric(working_df['bytes'], errors='coerce').fillna(0)
    working_df['status_code'] = pd.to_numeric(working_df['status_code'], errors='coerce')
    
    # Categorize User Agents
    working_df['ua_category'] = working_df['user_agent'].apply(categorize_ua)
    
    # Perform grouping calculations using pandas aggregations
    # Calculate group sizes and filter early
    group_sizes = working_df.groupby(['url', 'ua_category']).size()
    valid_groups = group_sizes[group_sizes >= min_requests].index
    
    if valid_groups.empty:
        return pd.DataFrame()
        
    # Filter working_df to only valid groups
    filtered_df = working_df.set_index(['url', 'ua_category']).loc[valid_groups].reset_index()
    
    # Basic statistics
    agg_df = filtered_df.groupby(['url', 'ua_category'])['bytes'].agg(
        request_count='count',
        avg_bytes='mean',
        median_bytes='median',
        std_bytes='std',
        min_bytes='min',
        max_bytes='max'
    ).reset_index()
    
    # Standard deviation can be NaN if request count is 1 (though min_requests >= 5 protects against this)
    agg_df['std_bytes'] = agg_df['std_bytes'].fillna(0.0)
    
    # Range and variance percentage
    range_bytes = agg_df['max_bytes'] - agg_df['min_bytes']
    agg_df['variance_pct'] = range_bytes / agg_df['median_bytes']
    agg_df['variance_pct'] = agg_df['variance_pct'].replace([float('inf'), float('-inf')], 0.0).fillna(0.0)
    
    agg_df['anomaly_flag'] = agg_df['variance_pct'] > variance_threshold
    
    # Compute status codes
    # For status codes, we find the most frequent and minority codes
    status_counts = filtered_df.groupby(['url', 'ua_category', 'status_code']).size().reset_index(name='count')
    # Sort to place the most frequent status first
    status_counts = status_counts.sort_values(['url', 'ua_category', 'count'], ascending=[True, True, False])
    
    # Most frequent is the first row per group
    most_frequent = status_counts.groupby(['url', 'ua_category']).first().reset_index()
    most_frequent = most_frequent.rename(columns={'status_code': 'most_frequent_status'})[['url', 'ua_category', 'most_frequent_status']]
    
    # Minority status codes
    all_statuses = status_counts.groupby(['url', 'ua_category'])['status_code'].apply(lambda x: list(x.astype(int))).reset_index()
    
    # Merge status code info back
    status_info = pd.merge(most_frequent, all_statuses, on=['url', 'ua_category'])
    
    def get_minority(row):
        freq = int(row['most_frequent_status'])
        all_s = row['status_code']
        min_s = [s for s in all_s if s != freq]
        return ", ".join(map(str, min_s)) if min_s else "None"
        
    status_info['minority_statuses'] = status_info.apply(get_minority, axis=1)
    status_info = status_info[['url', 'ua_category', 'most_frequent_status', 'minority_statuses']]
    
    # Merge status code info back to aggregations
    report_df = pd.merge(agg_df, status_info, on=['url', 'ua_category'])
    
    # Include response time if available
    if 'response_time_ms' in filtered_df.columns:
        resp_time_df = filtered_df.groupby(['url', 'ua_category'])['response_time_ms'].mean().reset_index(name='avg_response_time_ms')
        report_df = pd.merge(report_df, resp_time_df, on=['url', 'ua_category'])
        report_df['avg_response_time_ms'] = report_df['avg_response_time_ms'].round(2).fillna("N/A")
        
    # Round columns and rename to user-facing formats
    report_df['avg_bytes'] = report_df['avg_bytes'].round(2)
    report_df['median_bytes'] = report_df['median_bytes'].round(2)
    report_df['std_bytes'] = report_df['std_bytes'].round(2)
    report_df['variance_pct'] = (report_df['variance_pct'] * 100).round(2)
    
    # Rename columns to match requested outputs
    rename_dict = {
        'url': 'URL',
        'ua_category': 'User Agent Category',
        'request_count': 'Request Count',
        'avg_bytes': 'Avg Bytes',
        'median_bytes': 'Median Bytes',
        'std_bytes': 'Std Bytes',
        'min_bytes': 'Min Bytes',
        'max_bytes': 'Max Bytes',
        'variance_pct': 'Variance %',
        'anomaly_flag': 'Anomaly Flag',
        'most_frequent_status': 'Most Frequent Status Code',
        'minority_statuses': 'Minority Status Codes'
    }
    if 'avg_response_time_ms' in report_df.columns:
        rename_dict['avg_response_time_ms'] = 'Avg Response Time ms'
        
    report_df = report_df.rename(columns=rename_dict)
    
    # Reorder columns to match output requirements
    col_order = [
        'URL', 'User Agent Category', 'Request Count', 'Avg Bytes', 'Median Bytes',
        'Std Bytes', 'Min Bytes', 'Max Bytes', 'Variance %', 'Anomaly Flag',
        'Most Frequent Status Code', 'Minority Status Codes'
    ]
    if 'Avg Response Time ms' in report_df.columns:
        col_order.append('Avg Response Time ms')
        
    report_df = report_df[col_order]
    
    # Sort
    report_df = report_df.sort_values(by=['Anomaly Flag', 'Variance %'], ascending=[False, False])
    
    return report_df


def export_report(report_df: pd.DataFrame, file_format: str = 'csv') -> str:
    """Format the report DataFrame as CSV or JSON."""
    if file_format.lower() == 'json':
        return report_df.to_json(orient='records', indent=2)
    else:
        return report_df.to_csv(index=False)
