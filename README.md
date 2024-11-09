import os
import mysql.connector
import random
from datetime import datetime
from prettytable import PrettyTable

# MySQL database connection
db_config = {
    "host": "localhost",
    "user": "root",
    "password": "sudharshana",
    "database": "malware_analysis"
}

# Malware information dictionary (for impact and prevention)
malware_info = {
    "Trojan": {
        "impact": "Trojans disguise themselves as legitimate software, allowing attackers to gain unauthorized access, steal data, or harm the system.",
        "prevention": [
            "Only download software from trusted sources.",
            "Use security software to detect and remove Trojans.",
            "Be cautious with email attachments and links."
        ]
    },
    "Ransomware": {
        "impact": "Ransomware encrypts files or locks the system, demanding a ransom to restore access. It can result in data loss or financial loss.",
        "prevention": [
            "Regularly back up data to avoid being locked out.",
            "Use strong passwords and enable multi-factor authentication.",
            "Be cautious with suspicious emails and links, and use security tools to detect threats."
        ]
    },
    "Benign": {
        "impact": "This file is not considered malicious.",
        "prevention": ["No specific actions are required."]
    }
}

# Connect to MySQL
def connect_to_db():
    try:
        connection = mysql.connector.connect(**db_config)
        print("Connected to MySQL database.")
        return connection
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return None

# Create the analysis_results table if it doesn't exist
def create_table(connection):
    cursor = connection.cursor()
    create_table_query = """
    CREATE TABLE IF NOT EXISTS analysis_results (
        id INT AUTO_INCREMENT PRIMARY KEY,
        file_name VARCHAR(255) NOT NULL,
        static_analysis TEXT,
        dynamic_analysis TEXT,
        malware_classification VARCHAR(50),
        analysis_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """
    cursor.execute(create_table_query)
    connection.commit()
    print("Table 'analysis_results' is ready.")
    cursor.close()

# Store analysis result in MySQL database
def store_analysis_result(connection, file_name, static_result, dynamic_result, classification):
    cursor = connection.cursor()
    query = """
    INSERT INTO analysis_results (file_name, static_analysis, dynamic_analysis, malware_classification)
    VALUES (%s, %s, %s, %s)
    """
    cursor.execute(query, (file_name, static_result, dynamic_result, classification))
    connection.commit()
    cursor.close()
    print(f"Inserted {file_name} into analysis_results with classification '{classification}'")

# Perform static analysis (basic placeholder for text files)
def static_analysis(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            if "malicious" in content:
                return "Malicious pattern found"
            return "No known malicious signatures found."
    except Exception as e:
        print(f"Error during static analysis of {file_path}: {e}")
        return "Static analysis failed"

# Perform dynamic analysis (placeholder function)
def dynamic_analysis(file_path):
    behaviors = ["creates file", "modifies registry", "initiates network connection"]
    return random.choice(behaviors)

# Classify malware based on analysis
def classify_malware(static_result, dynamic_result):
    if "network connection" in dynamic_result:
        return "Trojan"
    elif "registry" in dynamic_result:
        return "Ransomware"
    else:
        return "Benign"

# Display impact and prevention based on malware type
def display_malware_info(malware_type):
    if malware_type in malware_info:
        info = malware_info[malware_type]
        print(f"\nMalware Type: {malware_type}")
        print(f"Impact: {info['impact']}")
        print("Prevention Tips:")
        for tip in info['prevention']:
            print(f" - {tip}")
    else:
        print(f"No information available for malware type: {malware_type}")

# Main function to process files
def process_file(file_path):
    connection = connect_to_db()
    if connection is None:
        print("Failed to connect to the database.")
        return

    try:
        # Ensure the table is created before storing results
        create_table(connection)
        
        if os.path.isfile(file_path):
            print(f"\nProcessing {file_path}")
            
            # Static and dynamic analysis
            static_result = static_analysis(file_path)
            print(f"Static analysis result: {static_result}")  # Debug
            
            dynamic_result = dynamic_analysis(file_path)
            print(f"Dynamic analysis result: {dynamic_result}")  # Debug
            
            # Malware classification
            classification = classify_malware(static_result, dynamic_result)
            print(f"Malware classification: {classification}")  # Debug
            
            # Store result in database
            store_analysis_result(connection, file_path, static_result, dynamic_result, classification)
            
            # Display malware information
            display_malware_info(classification)
    
    finally:
        connection.close()
        print("File processing completed.")

# Function to display analysis results from the database
def table():
    connection = connect_to_db()
    create_table(connection)  # Ensure the table exists before fetching data
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM analysis_results")
    rcd = cursor.fetchall()
    
    # Check if data was retrieved successfully
    if len(rcd) == 0:
        print("No records found in the analysis_results table.")  # Debug
    else:
        print("Fetched records from analysis_results table.")  # Debug
    
    n = PrettyTable(['id', 'file_name', 'static_analysis', 'dynamic_analysis', 'malware_classification', 'analysis_date'])
    for a in range(len(rcd)):
        n.add_row([rcd[a][0], rcd[a][1], rcd[a][2], rcd[a][3], rcd[a][4], rcd[a][5]])
    print(n)
    cursor.close()

if _name_ == "_main_":
    while True:
        # Prompt user for file input
        user_file_path = input("Enter the file path for analysis (e.g., C:/path/to/your/file.exe), or type 'exit' to quit: ")

        if user_file_path.lower() == 'exit':
            print("Exiting the program.")
            break  # Exit the loop if the user types 'exit'

        # Check if file path exists before processing
        if os.path.exists(user_file_path):
            process_file(user_file_path)
            table()
        else:
            print("The file path you entered does not exist. Please check the path and try again.")


