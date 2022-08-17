import re


def validate_email(email):
    return re.fullmatch(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', email)


# function for validating password
def validate_password(passwd):
    reg = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{6,18}$"

    return bool(re.fullmatch(reg, passwd))


def validate_number(num):
    return re.fullmatch('[6-9][0-9]{9}', str(num))


def validate_name(name):
    return name.isalpha()


def validate_gender(gender):
    return gender in ["male", "m", "female", "f"]
