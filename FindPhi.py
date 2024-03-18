import logging
import os
import json
import argparse
import ctypes
from tqdm import tqdm
from nightfall import Nightfall, Detector, Confidence, DetectionRule
import json
from datetime import datetime





# Set up command-line argument parsing
parser = argparse.ArgumentParser(description='Scan files for sensitive information using Nightfall API.\n\nExample usage: python getPHI.py --max_file_size 15 --max_matches_per_file 10 --file_scan_timeout 10',
                                 formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('--max_file_size', type=int, required=True, help='Maximum file size in MB to scan.')
parser.add_argument('--max_matches_per_file', type=int, required=True, help='Maximum number of matches per file before skipping.')
parser.add_argument('--file_scan_timeout', type=int, required=True, help='Timeout in seconds for scanning each file.')
args = parser.parse_args()

MAX_FILE_SIZE = args.max_file_size * 1024 * 1024  # Convert MB to bytes
MAX_MATCHES_PER_FILE = args.max_matches_per_file
FILE_SCAN_TIMEOUT = args.file_scan_timeout

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def print_full_path(file_name):
    """Prints the full path of a given file."""

    # Get the current working directory
    cwd = os.getcwd()

    # Construct the full path using the correct separator
    full_path = os.path.join(cwd, file_name)

    # Print the full path in a clear format
    print(f"Scanning: {full_path}")


def save_findings_to_json(findings, file_path, save_file_path):
    # Use the save_file_path parameter to determine the filename
    filename = os.path.join(save_file_path, "findings.json")

    new_data = []
    for finding in findings[0]:
        finding_data = {
            'file_path': file_path,
            'finding': finding.finding,
            'redacted_finding': finding.redacted_finding,
            'before_context': finding.before_context,
            'after_context': finding.after_context,
            'detector_name': finding.detector_name,
            'detector_uuid': finding.detector_uuid,
            'confidence': finding.confidence.name,  # Convert Enum to string
            'byte_range_start': finding.byte_range.start,
            'byte_range_end': finding.byte_range.end,
            'codepoint_range_start': finding.codepoint_range.start,
            'codepoint_range_end': finding.codepoint_range.end,
            'row_range_start': finding.row_range.start if finding.row_range else None,
            'row_range_end': finding.row_range.end if finding.row_range else None,
            'column_range_start': finding.column_range.start if finding.column_range else None,
            'column_range_end': finding.column_range.end if finding.column_range else None,
            'commit_hash': finding.commit_hash,
            'commit_author': finding.commit_author,
            'matched_detection_rule_uuids': finding.matched_detection_rule_uuids,
            'matched_detection_rules': finding.matched_detection_rules
           
        }
        new_data.append(finding_data)

    # Read existing data if file exists
    if os.path.exists(filename):
        with open(filename, 'r') as json_file:
            try:
                data = json.load(json_file)
            except json.JSONDecodeError:  # Handle empty or invalid JSON file
                data = []
        data.extend(new_data)
    else:
        data = new_data

    # Write (or overwrite) the JSON file with updated data
    with open(filename, 'w') as json_file:
        json.dump(data, json_file, indent=4)

    print(f"Findings saved to {filename}")



def get_drives():
    """Get a list of available drives on Windows."""
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if bitmask & 1:
            drives.append(letter + ':\\')
        bitmask >>= 1
    return drives

def is_text_file(file_path):
    """Attempt to determine if a file is a text file."""
    try:
        if os.path.getsize(file_path) > MAX_FILE_SIZE:
            logging.info(f"Skipping large file: {file_path}")
            return False
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            if '\0' in file.read(1024):
                return False
        return True
    except Exception as e:
        logging.error(f"Error checking if file is text: {file_path}, {e}")
        return False
class Finding:
    def __init__(self, finding, redacted_finding, before_context, after_context,
                 detector_name, detector_uuid, confidence, byte_range, codepoint_range,
                 row_range, column_range, commit_hash, commit_author,
                 matched_detection_rule_uuids, matched_detection_rules):
        self.finding = finding
        self.redacted_finding = redacted_finding
        self.before_context = before_context
        self.after_context = after_context
        self.detector_name = detector_name
        self.detector_uuid = detector_uuid
        self.confidence = confidence
        self.byte_range = byte_range
        self.codepoint_range = codepoint_range
        self.row_range = row_range
        self.column_range = column_range
        self.commit_hash = commit_hash
        self.commit_author = commit_author
        self.matched_detection_rule_uuids = matched_detection_rule_uuids
        self.matched_detection_rules = matched_detection_rules

def parse_findings(findings):
    for finding in findings:
        # Access individual attributes:
        print(f"Finding: {finding.finding}")
        print(f"Detector Name: {finding.detector_name}")
        print(f"Confidence: {finding.confidence}")
        print(f"Byte Range: {finding.byte_range}")

        # ... Access and process other attributes similarly ...

        print("-" * 20)  # Separator between findings

def parse_findings(findings_list):
    parsed_data = []

    for finding in findings_list:
        parsed_finding = {
            'finding': finding.finding,
            'redacted_finding': finding.redacted_finding,
            'detector_name': finding.detector_name,
            'detector_uuid': finding.detector_uuid,
            'confidence': finding.confidence,
            # Add other attributes as needed...
        }
        parsed_data.append(parsed_finding)

    return parsed_data

def scan_file(file_path, nightfall, detection_rule):
    if not is_text_file(file_path):
        return None        
    logging.info(f"Scanning: {file_path}")
    print_full_path(file_path)
   
   
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            text_content = file.read()
            findings, _  = nightfall.scan_text([text_content], detection_rules=[detection_rule])
            # Check if findings contain any results
            if findings:
                       for finding in findings[0]:
                           print("File", file_path)
                           print("Finding:", finding.finding)
                           print("Redacted Finding:", finding.redacted_finding)
                           print("Detector Name:", finding.detector_name)
                           print("Detector UUID:", finding.detector_uuid)
                           print("Confidence:", finding.confidence)
                           print("Byte Range Start:", finding.byte_range.start)
                           print("Byte Range End:", finding.byte_range.end)
                           print("Codepoint Range Start:", finding.codepoint_range.start)
                           print("Codepoint Range End:", finding.codepoint_range.end)
                           print("Before Context:", finding.before_context)
                           print("After Context:", finding.after_context)
                           print("Row Range:", finding.row_range)
                           print("Column Range:", finding.column_range)
                           print("Commit Hash:", finding.commit_hash)
                           print("Commit Author:", finding.commit_author)
                           print("Matched Detection Rule UUIDs:", finding.matched_detection_rule_uuids)
                           print("Matched Detection Rules:", finding.matched_detection_rules)
                           print()
                           save_file_path = "c:\\temp"
                           save_findings_to_json(findings, save_file_path, file_path )
               
               

                #print("Findings structure:", findings)
            else:
                print("nothing")
    except Exception as e:
        logging.error(f"Error scanning file: {file_path}, {e}")
        return None




def scan_drive(drive, nightfall, detection_rule):
    """Recursively scan each drive for files that contain sensitive information."""
    results = {}
    for root, dirs, files in os.walk(drive):
        for file in tqdm(files, desc=f"Scanning drive {drive}", unit='file'):
            file_path = os.path.join(root, file)
            findings_list = scan_file(file_path, nightfall, detection_rule)
            if findings_list:
                for findings in findings_list:  # Iterate through each list of findings
                    for finding in findings:  # Iterate through each finding in the list
                        # Adjust according to your findings structure
                        phi_type = finding["detector"]["name"]
                        if phi_type not in results:
                            results[phi_type] = []
                        results[phi_type].append(file_path)
    return results

if __name__ == "__main__":
    output_dir = r"C:\temp"
    os.makedirs(output_dir, exist_ok=True)

    # Initialize Nightfall API client
    nightfall_api_key = os.environ.get("NIGHTFALL_API_KEY")
    if not nightfall_api_key:
        logging.error("NIGHTFALL_API_KEY environment variable is not set.")
        exit(1)
    nightfall = Nightfall(nightfall_api_key)

    # Define detectors and create a detection rule
    mbinum = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="US_MEDICARE_BENEFICIARY_IDENTIFIER")
    cryptokey = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="CRYPTOGRAPHIC_KEY")
    apikey = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="API_KEY")
    dbcon = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="DATABASE_CONNECTION_STRING")
    passwordincode = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="PASSWORD_IN_CODE")
    ip = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="IP_ADDRESS")
    claimnum = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="US_HEALTH_INSURANCE_CLAIM_NUMBER")
    hcin = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="US_HEALTHCARE_NPI")
    icd9des = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="ICD9_DIAGNOSIS_DESCRIPTION")
    icd9code = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="ICD9_CODE")
    drugname = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="FDA_NATIONAL_DRUG_NAME")
    ein = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="US_EMPLOYER_IDENTIFICATION_NUMBER")
    creditcard = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="CREDIT_CARD_NUMBER")
    email = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="EMAIL_ADDRESS")
    dob = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="DATE_OF_BIRTH")
    person = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="PERSON_NAME")
    phone = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="PHONE_NUMBER")
    street = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="STREET_ADDRESS")
    passport = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="US_PASSPORT")
    phi = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="PROTECTED_HEALTH_INFORMATION")
    pii = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="HIPAA_DEFINED_PII")
    swift = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="SWIFT_CODE")
    micr = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="US_BANK_ROUTING_MICR")
    iban = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="IBAN_CODE")
    imei = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="IMEI_HARDWARE_ID")
    mac = Detector(min_confidence=Confidence.POSSIBLE, nightfall_detector="MAC_ADDRESS")

    detection_rule = DetectionRule([phi, swift, micr, iban, imei, mac, pii, claimnum, hcin, icd9des, icd9code, drugname, ein, creditcard, email, dob, person, phone, street, passport, ip, passwordincode, dbcon, apikey, cryptokey, mbinum])


    all_results = {}
    drives = get_drives()
    for drive in drives:
        logging.info(f"Starting scan on drive: {drive}")
        results = scan_drive(drive, nightfall, detection_rule)
        for phi_type, file_paths in results.items():
            all_results[phi_type] = all_results.get(phi_type, []) + file_paths

    output_path = os.path.join(output_dir, "scan_results.json")
    with open(output_path, 'w') as f:
        json.dump(all_results, f, indent=4)

    logging.info(f"Scan results saved to {output_path}")