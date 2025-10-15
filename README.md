# Purpose 
My program is a Python-based command-line tool that scans files or directories for hardcoded secrets such as API keys, passwords, tokens, or private keys. It helps developers identify and remove sensitive data from their source code before committing to repositories. 
 
# Detection Logic 
My program  uses regular expressions  to identify patterns that commonly indicate hardcoded secrets within code files. Each regex pattern targets specific types of semiliterate, such as API keys, tokens, and private keys. My program scans every line in each file within the given directory or file path, comparing text against these patterns. If a match is found, the script records the filename, line number, a nd type of secret detected, helping developers quickly locate and remove exposed credentials 


# Usage 
To use my program, the user has to provide a file or directory path as input when running the Python script from the command line. This script scans all files in the specified path, checking each line for matches against the predefined regex patterns. If selects are found, the tool displays a detailed report listing the file name, line number, and defective pattern. Users can also choose to save the results to a report file by adding the -o option followed by a filename. If no secrets are detected, the program reports "No secrets found. This makes it easy for developers to check their code for sensitive information before committing or sharing it publicly. 
