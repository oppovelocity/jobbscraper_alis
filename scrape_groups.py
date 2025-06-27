import requests
from bs4 import BeautifulSoup
import google.generativeai as genai

def scrape_jobs(url: str, api_key: str) -> list[dict]:
    """Scrapes job postings from a given URL and returns a list of dicts with summaries."""
    try:
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error fetching the URL: {e}")
        return []

    soup = BeautifulSoup(response.content, 'lxml')
    # This is a generic example; selectors will need to be adapted for the target site
    job_elements = soup.find_all('div', class_='job-listing')
    jobs = []

    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')

    for job_element in job_elements:
        title_element = job_element.find('h2')
        link_element = job_element.find('a')
        description_element = job_element.find('p')

        if title_element and link_element:
            title = title_element.get_text(strip=True)
            job_url = link_element['href']
            description = description_element.get_text(strip=True) if description_element else "No description found."

            try:
                prompt = f"Summarize the following job description in a few key points:\n\n{description}"
                summary_response = model.generate_content(prompt)
                summary = summary_response.text
            except Exception as e:
                print(f"Error generating summary with Gemini AI: {e}")
                summary = "Could not generate summary."

            jobs.append({
                'title': title,
                'url': job_url,
                'summary': summary
            })
    return jobs
