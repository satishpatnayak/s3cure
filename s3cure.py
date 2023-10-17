import argparse
import requests
from xml.etree import ElementTree
from urllib.parse import urlparse
from termcolor import colored
from tabulate import tabulate
import subprocess
import textwrap
import json
import plotly.graph_objects as go
import datetime
import os

def check_bucket_public_access(bucket_name):
    url = f"https://{bucket_name}.s3.amazonaws.com/"

    try:
        response = requests.get(url)
        if response.status_code == 200:
            return True, url
        else:
            return False, url

    except Exception as e:
        print(f"Error checking public access for bucket {bucket_name}: {e}")
        return False, []

def list_bucket_objects(bucket_name):
    try:
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        response = requests.get(url)
        if response.status_code == 200:
            root = ElementTree.fromstring(response.content)
            object_keys = [o.findtext("{http://s3.amazonaws.com/doc/2006-03-01/}Key") for o in root.findall(".//{http://s3.amazonaws.com/doc/2006-03-01/}Contents")]
            return object_keys
        else:
            return []

    except Exception as e:
        print(f"Error listing objects in bucket {bucket_name}: {e}")
        return []

def check_http_access(bucket_name):
    http_url = f"http://{bucket_name}.s3.amazonaws.com"
    
    try:
        response = requests.get(http_url)
        if response.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        print(f"Error checking HTTP access for bucket {bucket_name}: {e}")
        return False

def run_trufflehog_scan(bucket_name):
    try:
        command = ["trufflehog", "s3", "--bucket", bucket_name, "--json"]
        result = subprocess.run(command, capture_output=True, text=True, encoding='utf-8')  
        if result.returncode == 0:
            wrapped_result = textwrap.fill(result.stdout, width=35)
            return wrapped_result
        else:
            return f"Error: {result.stderr}"
    except FileNotFoundError:
        return "Trufflehog not found. Make sure it's available."

def generate_html_report(results):
    html_report = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>S3 Bucket Vulnerability Report</title>
        <link rel="stylesheet" type="text/css" href="style.css">
        <script type="text/javascript" src="csv.js"></script>
        <script type="text/javascript" src="https://www.gstatic.com/charts/loader.js"></script>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.9.0/html2pdf.bundle.js"></script>
    </head>
    <body>
        <h1>S3 Bucket Vulnerability Report</h1>
        

        <table id="data-table">
        <h2>Scan Results</h2>
            <tr>
                <th>Bucket Name (URL)</th>
                <th>Public Access</th>
                <th>Object (Object URL)</th>
                <th>Access over HTTP</th>
                <th>Trufflehog Scan Results</th>
            </tr>
    """

    public_buckets = 0
    non_public_buckets = 0
    http_accessible_buckets = 0
    buckets_with_secrets = 0

    for result in results:
        bucket_name, is_public, object_keys, http_accessible, trufflehog_scan_result = result
        status_message = f'<span style="color: red;">Public</span>' if is_public else "Not public"
        http_message = f'<span style="color: red;">Yes</span>' if http_accessible else "No"

        bucket_name_parts = bucket_name.split("\n")
        bucket_name = bucket_name_parts[0]
        bucket_url = bucket_name_parts[1][:-1]
        bucket_url =bucket_url[1:]
        
        object_list = []
        if object_keys:
            for obj_key in object_keys:
                obj_url = f'{bucket_url}{obj_key}'
                object_list.append(f'<a href="{obj_url}">{obj_url}</a>')
        else:
            object_list.append("-")
        
        object_list_str = "<br>".join(object_list)

        if is_public:
            public_buckets += 1
        else:
            non_public_buckets += 1
        
        if http_accessible:
            http_accessible_buckets += 1
        
        if "No secrets found" not in trufflehog_scan_result and "No secrets scanning if Bucket is not public" not in trufflehog_scan_result:
            buckets_with_secrets += 1
        
        total_scanned_buckets = public_buckets + non_public_buckets
        https_accessible_buckets = total_scanned_buckets - http_accessible_buckets
        buckets_without_secrets = total_scanned_buckets - buckets_with_secrets

    
   
    
        html_report += f"""
            <tr>
                <td>{bucket_name}</br> (<a href="{bucket_url}">{bucket_url} </a>) </td>
                <td>{status_message}</td>
                <td>{object_list_str}</td>
                <td>{http_message}</td>
                <td>{trufflehog_scan_result}</td>
            </tr>
        """

    html_report += f"""
            <div class="category">
                <h2># Total Buckets Scanned</h2>
                <h3>{total_scanned_buckets}</h3>
            </div>

             <div class="category">
                <h2># Public Buckets</h2>
                <h3>{public_buckets}</h3>
            </div>
            <div class="category">
                <h2># Buckets with HTTP access</h2>
                <h3>{http_accessible_buckets}</h3>
            </div>
            <div class="category">
                <h2>#Buckets with secrets</h2>
                <h3>{buckets_with_secrets}</h3>
            </div>
            <div></div>

            <div class="export-button-container">
            <button class="export-button" id="generatePDF" onclick="generatePDF()">Generate PDF Report</button>
            <button class="export-button" onclick="exportTableToCSV()">Export to CSV</button>
            </div>
        """



    html_report += """

        </table>
        <h2>Recommendations and References:</h2>
        <table>
            <tr>
                <th>Vulnerability</th>
                <th>Recommendation</th>
                <th>References</th>
            </tr>
            <tr>
                <td>Public S3 Bucket</td>
                <td>Configure bucket policies and permissions to restrict public access.</td>
                <td><a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html">AWS Documentation</a></td>
            </tr>
            <tr>
                <td>HTTP Accessible Bucket</td>
                <td>Use HTTPS for secure access to S3 buckets.</td>
                <td><a href="https://repost.aws/knowledge-center/s3-bucket-policy-for-config-rule">AWS Knowledge Center</a></td>
            </tr>
        </table>
        <p style='text-align: center;'>--------------------------- End of Report ---------------------------</p>
        <p style='text-align: center;'>Github Repo - <a href="https://github.com/satishpatnayak/s3cure">https://github.com/satishpatnayak/s3cure </a></p>
        <p style='text-align: center;'>x (Twitter) - <a href="https://twitter.com/satish_patnayak">@satish_patnayak</a></p>
    </body>
    </html>
    """

    current_datetime = datetime.datetime.now()
    formatted_date_time = str(current_datetime.strftime("%Y-%m-%d %H-%M-%S"))
    result_file="s3cure_scan_report_"+formatted_date_time+".html"
    print("\n Results are saved into "+os.getcwd()+"\\"+result_file)
    with open(result_file, "w") as html_file:
        html_file.write(html_report)


def main():
    print("-------------------------------------------------------------------------------------")
    print("   _____ ____   _____ _    _ _____  ______   ");
    print("  / ____|___ \ / ____| |  | |  __ \|  ____|");  
    print(" | (___   __) | |    | |  | | |__) | |__  ");
    print("  \___ \ |__ <| |    | |  | |  _  /|  __|  ");
    print(" __ __) |___) | |____| |__| | | \ \| |____ ");
    print(" |_____/|____/ \_____|\____/|_|  \_\______|");
   
    print("\n Created by https://twitter.com/satish_patnayak\n");
    print("-------------------------------------------------------------------------------------\n")
    print("[Info] - Started analyzing the S3 bucket(s). Please wait!")

    

    parser = argparse.ArgumentParser(description="Check S3 bucket vulnerabilities.")
    parser.add_argument("-b", "--bucket", help="Check a single bucket by name E.g. buggybucket.py -b <Bucket name>")
    parser.add_argument("-f", "--file", help="Check buckets from a text file E.g. buggybucket.py -b <File name>")
    parser.add_argument("-u", "--url", help="Check bucket by URL E.g. buggybucket.py -b <Bucket URL>")

    args = parser.parse_args()

    results = []


    if args.bucket:
        bucket_name = args.bucket
        is_public, bucket_url = check_bucket_public_access(bucket_name)
        object_keys = list_bucket_objects(bucket_name)
        http_accessible = check_http_access(bucket_name)
        if is_public:
            trufflehog_scan_result = run_trufflehog_scan(bucket_name)
            if (not trufflehog_scan_result):
                trufflehog_scan_result="No secrets found"
        else:
            trufflehog_scan_result="No secrets scanning if Bucket is not public"
        bucket_name = f"{bucket_name}\n({bucket_url})"
        results.append((bucket_name, is_public, object_keys, http_accessible, trufflehog_scan_result))

    elif args.file:
        with open(args.file, "r") as file:
            for line in file:
                bucket_name = line.strip()
                is_public, bucket_url  = check_bucket_public_access(bucket_name)
                object_keys = list_bucket_objects(bucket_name)
                http_accessible = check_http_access(bucket_name)
                if is_public:
                    trufflehog_scan_result = run_trufflehog_scan(bucket_name)
                    if (not trufflehog_scan_result):
                        trufflehog_scan_result="No secrets found"
                else:
                    trufflehog_scan_result="No secrets scanning if Bucket is not public"

                bucket_name = f"{bucket_name}\n({bucket_url})"
                results.append((bucket_name, is_public, object_keys, http_accessible, trufflehog_scan_result))

    elif args.url:
        parsed_url = urlparse(args.url)
        bucket_name = parsed_url.netloc.split(".")[0]
        is_public, bucket_url  = check_bucket_public_access(bucket_name)
        object_keys = list_bucket_objects(bucket_name)
        http_accessible = check_http_access(bucket_name)
        if is_public:
            trufflehog_scan_result = run_trufflehog_scan(bucket_name)
            if (not trufflehog_scan_result):
                trufflehog_scan_result="No secrets found"

        else:
            trufflehog_scan_result="No secrets scanning if Bucket is not public"
        bucket_name = f"{bucket_name}\n({args.url})"
        results.append((bucket_name, is_public, object_keys, http_accessible, trufflehog_scan_result))

    else:
        parser.print_help()

    table_data = []
    for result in results:
        bucket_name, is_public, object_keys, http_accessible,trufflehog_scan_result  = result
        #bucket_name = f"{bucket_name}\n{bucket_url}"
        status_message = colored("Public", "red") if is_public else "Not public"
        http_message = colored("Yes", "red") if http_accessible else "No"
        #object_list = "\n".join(object_keys) if object_keys else "-"
        if object_keys:
            object_list = []
            for obj_key in object_keys:
                obj_url = f"{bucket_url}{obj_key}"
                object_list.append(f'{obj_key}\n({obj_url})\n')
            object_list_str = "\n".join(object_list)
        else:
            object_list_str = " - "
        table_data.append([bucket_name , status_message, object_list_str, http_message, trufflehog_scan_result])

    headers = ["Bucket Name (URL)", "Public Access", "Object (Object URL)", "Access over HTTP", "Trufflehog Scan Results"]
    print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
    html_report=tabulate(table_data, headers=headers, tablefmt="html")
    with open("output.html", "w") as html_file:
        html_file.write(html_report)

    vulnerabilities = [
        {
            "Vulnerability": "Public S3 Bucket",
            "Recommendation": "Configure bucket policies and permissions to restrict public access.",
            "References": "https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html"
        },
        {
            "Vulnerability": "HTTP Accessible Bucket",
            "Recommendation": "Use HTTPS for secure access to S3 buckets.",
            "References": "https://repost.aws/knowledge-center/s3-bucket-policy-for-config-rule"
        }
    ]

    print("\nRecommendations and References:")
    vulnerabilities_table_data = []
    for index, vuln_data in enumerate(vulnerabilities, start=1):
        vulnerabilities_table_data.append([vuln_data["Vulnerability"], vuln_data["Recommendation"], vuln_data["References"]])
    
    vulnerabilities_headers = ["Vulnerability", "Recommendation", "References"]
    print(tabulate(vulnerabilities_table_data, headers=vulnerabilities_headers, tablefmt="fancy_grid"))

    # Generate HTML report
    generate_html_report(results)
    

    print("\n ---------------------------***** End of Report *****---------------------------".center(30))


if __name__ == "__main__":
    main()