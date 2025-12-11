import argparse
import requests
from bs4 import BeautifulSoup
import re
import os
from openai import OpenAI

def analyze_with_openai(company_name, data):
    """Analyzes the scraped data using OpenAI API."""
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("\nError: OPENAI_API_KEY environment variable not set.")
        print("       Please set it to use the --analyze feature.")
        return None

    client = OpenAI(api_key=api_key)
    model = "o4-mini"

    # Format the data for the prompt
    prompt_data = f"Analysis Target: {company_name}\n\n"
    if data.get('cdn'):
        prompt_data += "--- CDNs ---\n"
        prompt_data += f"{'CDN Name':<30} {'# of IPs'}\n"
        prompt_data += "-"*45 + "\n"
        for name, count in data['cdn']:
            prompt_data += f"{name:<30} {count}\n"
        prompt_data += "\n"

    if data.get('hosting'):
        prompt_data += "--- Hosting ---\n"
        prompt_data += f"{'Cloud Host':<30} {'# of IPs'}\n"
        prompt_data += "-"*45 + "\n"
        for name, count in data['hosting']:
            prompt_data += f"{name:<30} {count}\n"
        prompt_data += "\n"

    if data.get('saas'):
        prompt_data += "--- SaaS ---\n"
        prompt_data += f"{'SaaS Platform':<30} {'# of IPs'}\n"
        prompt_data += "-"*45 + "\n"
        for name, count in data['saas']:
            prompt_data += f"{name:<30} {count}\n"
        prompt_data += "\n"

    system_prompt = ("You are a bug bounty hunter specializing in infrastructure reconnaissance "
                    "Your task is to analyze the provided CDN, Hosting, "
                     "and SaaS information for a target company and provide a concise summary highlighting potential areas of interest, "
                     "attack vectors based *solely* on this infrastructure data.\n\nFocus on:\n" 
                     "- The significance of specific CDNs (e.g., WAF capabilities, common misconfigurations).\n"
                     "- Implications of the hosting providers (e.g., cloud security models, potential for exposed services on specific providers).\n"
                     "- SaaS platforms that might indicate integration points, authentication mechanisms, or data storage locations relevant to security testing.\n"
                     "- Consider the relative number of IPs associated with each service as a potential indicator of scale or importance.\n"
                     "- Do not invent information not present in the tables. Provide actionable insights based *only* on the provided data.\n"
                     "- Provide any verified methodology to bug bounty hunt on the analysis. When describing methodology, focus on the *type* of action (e.g., subdomain enumeration, WAF fingerprinting) and suggest using 'modern tools' or 'appropriate tooling' for the task, rather than naming specific software tools.\n"
                     "- For the cloud section, attempt to build a GrayHatWarfare link for the user to click on to look at this target. Use the format: https://buckets.grayhatwarfare.com/files?keywords=<company_name> (replace <company_name> with the actual target company name).\n\n"
                     "**Formatting Instructions:** Structure your response for easy readability on a standard terminal. Use clear headings for sections (e.g., '1. CDN OBSERVATIONS'). Use double newlines to separate major sections and single newlines for list items under headings. Ensure bullet points (-) are clearly indented."
                    )

    print("\n--- AI Analysis --- ")
    print("Analyzing infrastructure data with OpenAI...\n")

    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_data}
            ]
        )
        analysis = response.choices[0].message.content
        return analysis.strip()
    except Exception as e:
        print(f"\nError during OpenAI API call: {e}")
        return None


def scrape_netify(company_name):
    """Scrapes netify.ai for CDN, Hosting, and SaaS information and returns it."""
    url = f"https://www.netify.ai/resources/applications/{company_name.lower()}"
    html_filename = f"debug_{company_name.lower()}.html"
    scraped_data = {'cdn': [], 'hosting': [], 'saas': []}

    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        # Save HTML content for debugging
        try:
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(response.text)
            # print(f"Saved HTML content to {html_filename}") # Keep this commented
        except IOError as e:
            print(f"Error saving HTML to {html_filename}: {e}")

    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 404:
             print(f"\nError: Could not find page for '{company_name}'.")
             print(f"         Please check the company name spelling and format.")
             print(f"         URL attempted: {url}")
             # Optionally save the 404 page content
             try:
                with open(html_filename, 'w', encoding='utf-8') as f:
                    f.write(http_err.response.text)
                # print(f"Saved 404 page content to {html_filename}")
             except IOError as io_e:
                print(f"Error saving 404 HTML to {html_filename}: {io_e}")
        else:
             print(f"\nHTTP Error occurred: {http_err}")
             # Save error response content
             try:
                with open(html_filename, 'w', encoding='utf-8') as f:
                    f.write(http_err.response.text)
                # print(f"Saved error response HTML content to {html_filename}")
             except IOError as io_e:
                print(f"Error saving error response HTML to {html_filename}: {io_e}")
        return None # Indicate error by returning None
    except requests.exceptions.RequestException as req_err:
        print(f"\nError fetching URL {url}: {req_err}")
        return None # Indicate error by returning None

    soup = BeautifulSoup(response.content, 'html.parser')

    # --- Extract CDN Info --- 
    cdn_table = soup.find('table', id='cdn-list-networks-summary') 
    if cdn_table:
        try:
            cdn_data_raw = []
            for row in cdn_table.find('tbody').find_all('tr'):
                cols = row.find_all('td')
                if len(cols) == 2:
                    service_link = cols[0].find('a')
                    service_name = service_link.text.strip() if service_link else cols[0].text.strip()
                    ip_count_str = cols[1].text.strip()
                    try:
                        ip_count = int(ip_count_str)
                        cdn_data_raw.append((service_name, ip_count))
                    except ValueError:
                        # Silently skip rows with unparseable IP counts for this section
                        pass 
            # Sort data by IP count (descending) and store
            scraped_data['cdn'] = sorted(cdn_data_raw, key=lambda item: item[1], reverse=True)
        except AttributeError:
            print("Warning: Error parsing CDN table structure.")

    # --- Extract Hosting Info --- 
    hosting_header = soup.find('h3', string=re.compile(r'Hosting', re.IGNORECASE))
    if hosting_header:
        hosting_table = soup.find('table', id='cloud-host-networks-summary')
        if hosting_table:
            try:
                hosting_data_raw = []
                for row in hosting_table.find('tbody').find_all('tr'):
                    cols = row.find_all('td')
                    if len(cols) == 2:
                        host_link = cols[0].find('a')
                        host_name = host_link.text.strip() if host_link else cols[0].text.strip()
                        ip_count_str = cols[1].text.strip()
                        try:
                           ip_count = int(ip_count_str)
                           hosting_data_raw.append((host_name, ip_count))
                        except ValueError:
                           pass # Skip unparseable
                # Sort data by IP count (descending) and store
                scraped_data['hosting'] = sorted(hosting_data_raw, key=lambda item: item[1], reverse=True)
            except AttributeError:
                 print("Warning: Error parsing Hosting table structure.")

    # --- Extract SaaS Info --- 
    saas_table = soup.find('table', id='saas-list-networks-summary') 
    if not saas_table:
        # Attempt alternate selector if primary ID fails
        saas_table = soup.select_one('table[id^="saas-list-networks-summary"]')

    if saas_table:
        try:
            saas_data_raw = []
            for row in saas_table.find('tbody').find_all('tr'):
                cols = row.find_all('td')
                if len(cols) == 2:
                    saas_link = cols[0].find('a')
                    saas_name = saas_link.text.strip() if saas_link else cols[0].text.strip()
                    ip_count_str = cols[1].text.strip()
                    try:
                        ip_count = int(ip_count_str)
                        saas_data_raw.append((saas_name, ip_count))
                    except ValueError:
                         pass # Skip unparseable
            # Sort data by IP count (descending) and store
            scraped_data['saas'] = sorted(saas_data_raw, key=lambda item: item[1], reverse=True)
        except AttributeError:
             print("Warning: Error parsing SaaS table structure.")

    # Return the dictionary containing the lists of tuples
    # Return None if no sections were found at all (or only errors occurred)
    if not scraped_data['cdn'] and not scraped_data['hosting'] and not scraped_data['saas']:
         # Check if an HTTP/Request error already occurred (which returns None)
         # If soup exists, it means request was successful but parsing failed everywhere
         if 'soup' in locals(): 
              print(f"\nWarning: No CDN, Hosting, or SaaS data found for '{company_name}'. Check debug HTML.")
         return None # Return None if truly no data found or request failed
    
    return scraped_data

def print_table(title, headers, data):
    """Helper function to print a formatted table."""
    print(f"--- {title} ---")
    if data:
        print(f"{headers[0]:<30} {headers[1]}")
        print("-"*45)
        for name, count in data:
            print(f"{name:<30} {count}")
    else:
        print("No data found for this section.")
    print("\n")

def main():
    parser = argparse.ArgumentParser(description='Netify Recon Tool')
    parser.add_argument('-c', '--company', required=True, help='Company name to lookup (e.g., walmart)')
    parser.add_argument('--analyze', action='store_true', help='Analyze the results with OpenAI (requires OPENAI_API_KEY env var)')
    args = parser.parse_args()
    
    print("\n") # Initial padding

    scraped_data = scrape_netify(args.company)

    if scraped_data:
        # Print the tables
        print_table("CDNs", ["CDNs", "# of IPs"], scraped_data.get('cdn'))
        print_table("Hosting", ["Cloud Hosts", "# of IPs"], scraped_data.get('hosting'))
        print_table("SaaS", ["SaaS", "# of IPs"], scraped_data.get('saas'))

        # Perform analysis if requested
        if args.analyze:
            analysis_result = analyze_with_openai(args.company, scraped_data)
            if analysis_result:
                # Simple post-processing for potentially better spacing
                # Add an extra newline before numbered sections if not already preceded by two
                import re
                formatted_analysis = re.sub(r'\n(?=\n*[0-9]+\.\s)', '\n\n', analysis_result) 
                # Ensure spacing after the title if needed
                formatted_analysis = formatted_analysis.replace('--- AI Analysis ---', '--- AI Analysis ---\n') 
                print(formatted_analysis.strip()) # Print the processed result
                print("\n") # Add spacing after analysis

if __name__ == "__main__":
    main()
