import json

import requests
from lxml import html


def get_github_alerts(owner, repo, token, branch="main"):
    """
    Fetch code scanning alerts from the GitHub API for the specified repository and branch.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts?ref={branch}"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"token {token}"
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 404:
        raise Exception(f"Repository {owner}/{repo} not found or code scanning is not enabled.")
    elif response.status_code == 401:
        raise Exception("Unauthorized access. Check your GitHub token.")

    response.raise_for_status()  # Raise an exception for other HTTP errors
    return response.json()


def read_json_file(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)
    return data


def get_exploitability(cwe_id):
    """
    Fetch the 'Likelihood of exploitability' from the CWE Mitre website for the given CWE ID.
    """
    url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
    response = requests.get(url)

    if response.status_code == 200:
        tree = html.fromstring(response.content)

        # Use the provided full XPath to locate the element
        likelihood_element = tree.xpath('//*[@id="oc_'+cwe_id+'_Likelihood_Of_Exploit"]/div/div')
        if likelihood_element:
            # Extract the text content from the found element
            likelihood = likelihood_element[0].text_content().strip()
            return likelihood
        else:
            likelihood = "Not Found"
            # print(f"Element not found using XPath for CWE-{cwe_id}")
            return likelihood
    else:
        print(f"Failed to fetch data from {url}. Status code: {response.status_code}")
        return None


def main():
    # Replace these with your actual GitHub username, repository name, personal access token, and branch name
    owner = "dkrdini"
    repo = "vulnerable-code"
    token = "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"
    branch = "main"  # Specify the branch to check alerts

    try:
        # Fetch alerts for the specified branch
        alerts = get_github_alerts(owner, repo, token, branch)
    except Exception as e:
        print(e)
        return

    # Filter alerts with severity 'High' or above
    high_severity_alerts = [alert for alert in alerts if
                            alert['rule']['severity'].lower() in ['error', 'high', 'critical']]

    # Check the 'Likelihood of exploitability' for each alert
    bid_to_cwe = read_json_file("bandit_to_cwe.json")
    for alert in high_severity_alerts:
        cwe_id = None
        cwe = bid_to_cwe[alert['rule']['id']]  # Extract CWE ID (assuming the format is 'CWE-XXX')
        cwe_id = cwe.split('-')[1]
        exploitability = get_exploitability(cwe_id)
        if exploitability:
            if 'High' in exploitability:
                print(
                    f"Vulnerability: {alert['most_recent_instance']['message']['text']}, Severity: {alert['rule']['severity']}, Exploitability: {exploitability}, Url: {alert['html_url']}")


if __name__ == "__main__":
    main()
