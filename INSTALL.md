# Steps to Use the Script:

1. Save the script as setup.sh in the project directory.


2. Make the script executable:
`
chmod +x setup.sh
`

3. Run the script:
   
`
./setup.sh
`

5. Once the setup is complete, activate the virtual environment:

`
source oneforall-env/bin/activate
`


Key Features of the Script:

Installs all required tools (assetfinder, subfinder, sqlmap, etc.).

Sets CHAOS_CLIENT_KEY and SHODAN_API_KEY as environment variables.

Creates and activates a Python virtual environment.

Installs Python dependencies from requirements.txt.
