from flask_mail import Message
from utils.mail_utils import mail
from flask import url_for

def send_reset_email(recipient_email):
    """
    Sends a password reset email to the given recipient.

    Args:
        recipient_email (str): The email address of the recipient.
    """
    reset_link = url_for('reset_password', _external=True)
    subject = "Password Reset Request"
    body = f"""
    Dear User,

    We received a request to reset your password. You can reset your password by clicking the link below:

    {reset_link}

    If you did not request a password reset, please ignore this email or contact support if you have concerns.

    Best regards,
    EHR System Team
    """

    msg = Message(subject=subject, sender="noreply@ehrsystem.com", recipients=[recipient_email])
    msg.body = body
    mail.send(msg)
