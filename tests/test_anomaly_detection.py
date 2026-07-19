import unittest
import pandas as pd
from anomaly_detector import categorize_ua, detect_anomalies, export_report


class TestAnomalyDetection(unittest.TestCase):
    def test_ua_categorization(self):
        # Verify bot categorization
        google_ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
        bing_ua = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
        gpt_ua = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"
        perplexity_ua = "Mozilla/5.0 (compatible; PerplexityBot/1.0; +http://www.perplexity.ai/perplexitybot)"
        claude_ua = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 (compatible; ClaudeBot/1.0; +https://anthropic.com)"
        
        # Verify browser categorization
        chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        safari_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5.1 Safari/605.1.15"
        
        # Verify other/unknown categorization
        python_ua = "Python-urllib/3.9"

        self.assertEqual(categorize_ua(google_ua), "Googlebot")
        self.assertEqual(categorize_ua(bing_ua), "Bingbot")
        self.assertEqual(categorize_ua(gpt_ua), "GPTBot")
        self.assertEqual(categorize_ua(perplexity_ua), "PerplexityBot")
        self.assertEqual(categorize_ua(claude_ua), "ClaudeBot")
        self.assertEqual(categorize_ua(chrome_ua), "human browser")
        self.assertEqual(categorize_ua(safari_ua), "human browser")
        self.assertEqual(categorize_ua(python_ua), "other")

    def test_stable_group(self):
        # Stable group: 5 requests, all with exactly 1000 bytes.
        # Variance should be 0.0, Anomaly Flag should be False.
        data = {
            'url': ['/index.html'] * 5,
            'user_agent': [
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            ] * 5,
            'size': [1000] * 5,
            'status': [200] * 5
        }
        df = pd.DataFrame(data)
        report = detect_anomalies(df, min_requests=5, variance_threshold=0.25)
        
        self.assertFalse(report.empty)
        self.assertEqual(len(report), 1)
        self.assertEqual(report.iloc[0]['Anomaly Flag'], False)
        self.assertEqual(report.iloc[0]['Variance %'], 0.0)
        self.assertEqual(report.iloc[0]['Request Count'], 5)
        self.assertEqual(report.iloc[0]['Most Frequent Status Code'], 200)
        self.assertEqual(report.iloc[0]['Minority Status Codes'], 'None')

    def test_single_outlier(self):
        # Outlier: 5 requests, four with 1000 bytes, one with 200 bytes.
        # Range = 800, Median = 1000, Variance % = 80%.
        # Variance threshold = 25%.
        # Anomaly Flag should be True.
        data = {
            'url': ['/index.html'] * 5,
            'user_agent': [
                "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"
            ] * 5,
            'size': [1000, 1000, 1000, 1000, 200],
            'status': [200, 200, 200, 200, 404]
        }
        df = pd.DataFrame(data)
        report = detect_anomalies(df, min_requests=5, variance_threshold=0.25)
        
        self.assertFalse(report.empty)
        self.assertEqual(len(report), 1)
        self.assertEqual(report.iloc[0]['Anomaly Flag'], True)
        self.assertEqual(report.iloc[0]['Variance %'], 80.0)
        self.assertEqual(report.iloc[0]['Most Frequent Status Code'], 200)
        self.assertEqual(report.iloc[0]['Minority Status Codes'], '404')

    def test_systemic_variance(self):
        # Systemic variance: sizes varying widely.
        # Min = 200, Max = 1800, Median = 1000. Variance = 160%.
        data = {
            'url': ['/index.html'] * 5,
            'user_agent': [
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
            ] * 5,
            'size': [200, 600, 1000, 1400, 1800],
            'status': [200, 200, 200, 200, 200]
        }
        df = pd.DataFrame(data)
        report = detect_anomalies(df, min_requests=5, variance_threshold=0.25)
        
        self.assertFalse(report.empty)
        self.assertEqual(report.iloc[0]['Anomaly Flag'], True)
        self.assertEqual(report.iloc[0]['Variance %'], 160.0)

    def test_insufficient_requests(self):
        # Only 4 requests, which is less than min_requests = 5.
        # Should be excluded, resulting in empty report.
        data = {
            'url': ['/index.html'] * 4,
            'user_agent': [
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            ] * 4,
            'size': [1000] * 4,
            'status': [200] * 4
        }
        df = pd.DataFrame(data)
        report = detect_anomalies(df, min_requests=5, variance_threshold=0.25)
        
        self.assertTrue(report.empty)

    def test_optional_response_time(self):
        # Test optional response_time_ms column
        data = {
            'url': ['/index.html'] * 5,
            'user_agent': [
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            ] * 5,
            'size': [1000] * 5,
            'status': [200] * 5,
            'response_time_ms': [100, 120, 90, 110, 100]
        }
        df = pd.DataFrame(data)
        report = detect_anomalies(df, min_requests=5, variance_threshold=0.25)
        
        self.assertFalse(report.empty)
        self.assertIn('Avg Response Time ms', report.columns)
        self.assertEqual(report.iloc[0]['Avg Response Time ms'], 104.0)

    def test_human_browser_exclusion(self):
        # Human browser group: 5 requests, should be dropped entirely from report.
        data = {
            'url': ['/index.html'] * 5,
            'user_agent': [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
            ] * 5,
            'size': [1000, 1000, 1000, 1000, 200],
            'status': [200, 200, 200, 200, 200]
        }
        df = pd.DataFrame(data)
        report = detect_anomalies(df, min_requests=5, variance_threshold=0.25)
        
        self.assertTrue(report.empty)


if __name__ == '__main__':
    unittest.main()
