import re

def validate_email(email):
    """Validate email format."""
    email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(email_regex, email) is not None


def validate_password_strength(password):
    """
    Validate password strength.
    Password must contain:
    - At least 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    """
    if len(password) < 8:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    if not any(char in "!@#$%^&*()-_+=<>?/{}[]~" for char in password):
        return False
    return True


def validate_user_registration_form(data):
    """
    Validate the user registration form.
    Expects a dictionary with keys: 'name', 'email', 'password'.
    """
    errors = {}

    if not data.get('name'):
        errors['name'] = "Name is required."
    if not data.get('email') or not validate_email(data['email']):
        errors['email'] = "A valid email is required."
    if not data.get('password') or not validate_password_strength(data['password']):
        errors['password'] = "Password does not meet strength requirements."

    return errors


def validate_patient_form(data):
    """
    Validate the patient registration form.
    Expects a dictionary with keys: 'name', 'age', 'gender', 'condition'.
    """
    errors = {}

    if not data.get('name'):
        errors['name'] = "Patient name is required."
    if not data.get('age') or not data['age'].isdigit() or int(data['age']) <= 0:
        errors['age'] = "A valid age is required."
    if not data.get('gender') or data['gender'] not in ['Male', 'Female', 'Other']:
        errors['gender'] = "Gender must be 'Male', 'Female', or 'Other'."
    if not data.get('condition'):
        errors['condition'] = "Medical condition is required."

    return errors
