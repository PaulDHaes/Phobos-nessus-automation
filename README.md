
---

# Phobus Nessus automation

Phobus Nessus automation is a Python script designed to process Nessus scan reports and automate the execution of Nmap/other basic commands based on the findings in the report. It provides a convenient way to identify vulnerabilities and perform further evidence collection.

## Features

- Parses Nessus scan reports (.nessus file)
- Identifies unique findings based on severity levels
- Can exclude given severity level execution
- Automates the execution of Nmap/other commands for identified/collecting evidence
- Supports user interaction for command execution
- Option to execute all commands for the same plugin and port
- Easy to follow command execution

## Requirements

- Python 3.x
- Nmap installed and accessible via the command line
- For easy use best run this on a Kali linux machine

## Usage

1. Clone the repository or download the script file (`phobus-nessus.py`).
2. Ensure you have the required dependencies installed (Python 3.x and Nmap).
3. Run the script with the command `python phobus-nessus.py -f <file>`.
4. Provide the path to the Nessus scan report file when prompted.
5. Follow the on-screen instructions to process the report and execute Nmap commands.

## Example usage

```shell
python3 phobus-nessus.py -f nessus_file.nessus
```

## Contributions

Contributions to improve Mega-Nessus are welcome! Feel free to fork the repository, make your changes, aks for improvments and submit a pull request.

## Acknowledgments

- This project was inspired by the need for automating vulnerability evidence collection workflows.

---
