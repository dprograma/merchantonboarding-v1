# This is a readme file for setting up the Aggregated Merchant Acquiring and Payment Gateway System (AMAPGS) Application

# 1. Install python on your device (MacOs, Windows, Linux)

# 2. Clone the amapgs-v1 repository, create virtual environment and install django

run `git clone https://kenegwuda@bitbucket.org/siliconharbourng/amapgs-v1.git`

run `cd amapgs-v1`

run `python3 -m venv venv`

run `source venv/bin/activate`

run `pip install django` # if django is not already installed

# 3. setup postgres database and set the login credentials

# 4. install desktop docker (MacOs, Windows, Linux)

# 5. start the server

run `docker-compose up` # may require `sudo` for admin permission

####################################################################
# Code Analysis, sorting and static type checking
####################################################################

# 6. Run black

Run `black userservice tests`

# 7. Run isort

Run `isort userservice tests`

# 8. Run PyLint

Run `pylint userservice tests`

# 9. Run Mypy

Run `mypy userservice tests`

# 10. Run static validation comprising black, isort, pylint, mypy and pytest

Run `chmod +x static_validation.sh`     # may require `sudo` for admin permission

Run `DJANGO_SETTINGS_MODULE=merchantonboardingservice.settings_dev ./static_validation.sh`



