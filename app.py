from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
import sqlite3
import logging
from werkzeug.security import generate_password_hash, check_password_hash
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# App configurations
app.config['SECRET_KEY'] = '6e7c5b10d48a8f2b10f117b8dbd6b79d09a2c9f30c3a816eb7cd30e023f0dffb'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ena.egbe.hawk.ai@gmail.com'
app.config['MAIL_PASSWORD'] = 'vfbs mdhh wegf gvto'
app.config['MAIL_DEFAULT_SENDER'] = 'ena.egbe.hawk.ai@gmail.com'

# Initialize extensions
csrf = CSRFProtect(app)
mail = Mail(app)

# Token Serializer
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# Database connection helper
def get_db_connection():
    conn = sqlite3.connect('database/ehr.db')
    conn.row_factory = sqlite3.Row
    return conn

def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset-salt')

def verify_reset_token(token, expiration=3600):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=expiration)
    except Exception:
        return None
    return email

# Context Processor for Roles
@app.context_processor
def inject_roles():
    return {
        'current_roles': session.get('roles', []),
        'current_route': request.endpoint  # Pass the current route
    }


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Verify the reset token
    email = verify_reset_token(token)
    if not email:
        # If the token is invalid or expired, flash a message and redirect to forgot-password page
        flash('The reset link is invalid or has expired.', 'danger')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        # Get the new password and confirmation password from the form
        new_password = request.form['password']
        confirm_password = request.form['confirm_password']

        # Check if passwords match
        if new_password != confirm_password:
            flash('Passwords do not match. Please try again.', 'danger')
            return render_template('reset-password.html', token=token)

        # Hash the new password and update the database
        hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
        conn = get_db_connection()
        conn.execute('UPDATE users SET password = ? WHERE email = ?', (hashed_password, email))
        conn.commit()
        conn.close()

        # Flash success message and redirect to login page
        flash('Your password has been updated! You can now log in.', 'success')
        return redirect(url_for('login'))

    # Render the reset-password form
    return render_template('reset-password.html', token=token)

# Home Page
@app.route('/')
def index():
    return render_template('index.html')

# About Page
@app.route('/about')
def about():
    return render_template('about.html')

# Contact Page
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        flash('Message sent successfully!', 'success')
        # Logic to handle message (e.g., send email)
    return render_template('contact.html')

# Authentication Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['roles'] = user['roles'].split(',') if user['roles'] else []
            flash('Login successful!', 'success')

            # Redirect based on roles
            if 'admin' in session['roles']:
                return redirect(url_for('admin_dashboard'))
            elif 'doctor' in session['roles']:
                return redirect(url_for('doctor_dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')

        conn = get_db_connection()
        existing_user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if existing_user:
            flash('Email already registered. Please use another.', 'danger')
            conn.close()
            return redirect(url_for('register'))

        conn.execute('INSERT INTO users (name, email, password, roles) VALUES (?, ?, ?, ?)',
                     (name, email, password, 'doctor'))
        conn.commit()
        conn.close()
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user:
            try:
                send_reset_email(email)
                flash('Password reset link has been sent to your email.', 'success')
            except Exception as e:
                flash(f'Error sending email: {str(e)}', 'danger')
        else:
            flash('Email not found. Please try again.', 'danger')

    return render_template('forgot-password.html')

@app.route('/switch-role/<string:role>')
def switch_role(role):
    if 'roles' in session and role in session['roles']:
        if role == 'admin':
            return redirect(url_for('admin_dashboard'))
        elif role == 'doctor':
            return redirect(url_for('doctor_dashboard'))
    flash('Access Denied: Role not available.', 'danger')
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('index'))

# Admin Routes
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'roles' in session and 'admin' in session['roles']:
        conn = get_db_connection()
        total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        active_doctors = conn.execute('SELECT COUNT(*) as count FROM users WHERE roles LIKE ?', ('%doctor%',)).fetchone()['count']
        conn.close()
        return render_template('admin/admin-dashboard.html', total_users=total_users, active_doctors=active_doctors)
    flash('Access Denied: Admins Only', 'danger')
    return redirect(url_for('login'))

@app.route('/admin/manage-users')
def manage_users():
    if 'roles' in session and 'admin' in session['roles']:
        conn = get_db_connection()
        users = conn.execute('SELECT * FROM users').fetchall()
        conn.close()
        return render_template('admin/manage-users.html', users=users)
    flash('Access Denied: Admins Only', 'danger')
    return redirect(url_for('login'))

@app.route('/admin/edit-user/<int:id>', methods=['GET', 'POST'])
def edit_user(id):
    if 'roles' in session and 'admin' in session['roles']:
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (id,)).fetchone()

        if request.method == 'POST':
            name = request.form['name']
            email = request.form['email']
            roles = request.form.getlist('roles')  # Get all selected roles as a list
            roles_combined = ','.join(roles)  # Combine roles into a comma-separated string

            conn.execute('UPDATE users SET name = ?, email = ?, roles = ? WHERE id = ?',
                         (name, email, roles_combined, id))
            conn.commit()
            conn.close()

            # Update session roles if the currently logged-in user is edited
            if session['user_id'] == id:
                session['roles'] = roles

            flash('User updated successfully!', 'success')
            return redirect(url_for('manage_users'))

        conn.close()
        roles = user['roles'].split(',') if user['roles'] else []
        return render_template('admin/edit-user.html', user=user, roles=roles)

    flash('Access Denied: Admins Only', 'danger')
    return redirect(url_for('login'))
@app.route('/admin/system-overview')
def system_overview():
    if 'roles' in session and 'admin' in session['roles']:
        conn = get_db_connection()
        total_users = conn.execute('SELECT COUNT(*) as count FROM users').fetchone()['count']
        total_patients = conn.execute('SELECT COUNT(*) as count FROM patients').fetchone()['count']
        total_admins = conn.execute('SELECT COUNT(*) as count FROM users WHERE roles LIKE ?', ('%admin%',)).fetchone()['count']
        total_doctors = conn.execute('SELECT COUNT(*) as count FROM users WHERE roles LIKE ?', ('%doctor%',)).fetchone()['count']
        both_rights = conn.execute('SELECT COUNT(*) as count FROM users WHERE roles LIKE ? AND roles LIKE ?', ('%admin%', '%doctor%')).fetchone()['count']
        conn.close()

        # Placeholder for system performance
        system_performance = "System running optimally."

        return render_template(
            'admin/system-overview.html',
            total_users=total_users,
            total_patients=total_patients,
            total_admins=total_admins,
            total_doctors=total_doctors,
            both_rights=both_rights,
            system_performance=system_performance
        )
    flash('Access Denied: Admins Only', 'danger')
    return redirect(url_for('login'))

@app.route('/admin/system-settings', methods=['GET', 'POST'])
def system_settings():
    # Check if the session contains 'roles' and the user has 'admin' role
    if 'roles' in session and 'admin' in session['roles']:
        if request.method == 'POST':
            # Logic for handling system settings updates
            flash('System settings updated successfully!', 'success')
        return render_template('admin/system-settings.html')

    # Redirect non-admin users to login with an access denied message
    flash('Access Denied: Admins Only', 'danger')
    return redirect(url_for('login'))

@app.route('/admin/delete-user/<int:id>', methods=['POST'])
def delete_user(id):
    if 'role' in session and session['role'] == 'admin':
        conn = get_db_connection()
        conn.execute('DELETE FROM users WHERE id = ?', (id,))
        conn.commit()
        conn.close()

        flash('User deleted successfully!', 'success')
        return redirect(url_for('manage_users'))

    flash('Access Denied: Admins Only', 'danger')
    return redirect(url_for('login'))

# Doctor Routes
@app.route('/dashboard')
def doctor_dashboard():
    if 'roles' in session and 'doctor' in session['roles']:
        conn = get_db_connection()
        patients = conn.execute('SELECT * FROM patients WHERE doctor_id = ?', (session['user_id'],)).fetchall()
        conn.close()
        return render_template('dashboard/doctor-dashboard.html', patients=patients)
    flash('Access Denied: Doctors Only', 'danger')
    return redirect(url_for('login'))

@app.route('/dashboard/add-patient', methods=['GET', 'POST'])
def add_patient():
    if 'role' in session and session['role'] == 'doctor':
        if request.method == 'POST':
            name = request.form['name']
            age = request.form['age']
            condition = request.form['condition']

            conn = get_db_connection()
            conn.execute('INSERT INTO patients (name, age, condition, doctor_id) VALUES (?, ?, ?, ?)',
                         (name, age, condition, session['user_id']))
            conn.commit()
            conn.close()
            flash('Patient added successfully!', 'success')
            return redirect(url_for('doctor_dashboard'))

        return render_template('dashboard/add-patient.html')
    flash('Access Denied: Doctors Only', 'danger')
    return redirect(url_for('login'))

@app.route('/dashboard/edit-patient/<int:id>', methods=['GET', 'POST'])
def edit_patient(id):
    if 'role' in session and session['role'] == 'doctor':
        conn = get_db_connection()
        patient = conn.execute('SELECT * FROM patients WHERE id = ?', (id,)).fetchone()

        if request.method == 'POST':
            name = request.form['name']
            age = request.form['age']
            condition = request.form['condition']

            conn.execute('UPDATE patients SET name = ?, age = ?, condition = ? WHERE id = ?',
                         (name, age, condition, id))
            conn.commit()
            conn.close()
            flash('Patient updated successfully!', 'success')
            return redirect(url_for('doctor_dashboard'))

        conn.close()
        return render_template('dashboard/edit-patient.html', patient=patient)
    flash('Access Denied: Doctors Only', 'danger')
    return redirect(url_for('login'))

@app.route('/messages', methods=['GET', 'POST'])
def messages():
    conn = get_db_connection()
    if request.method == 'POST':
        # Sending a new message
        sender_id = session.get('user_id')  # Ensure user is logged in
        receiver_id = request.form['receiver_id']
        message = request.form['message']

        if sender_id:
            conn.execute(
                'INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
                (sender_id, receiver_id, message)
            )
            conn.commit()
            flash('Message sent successfully!', 'success')
        else:
            flash('You need to log in to send messages.', 'danger')

    # Fetching messages for the logged-in user
    user_id = session.get('user_id')
    if user_id:
        inbox_messages = conn.execute(
            '''
            SELECT m.message, m.sent_at, u.name AS sender_name
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.receiver_id = ?
            ORDER BY m.sent_at DESC
            ''', (user_id,)
        ).fetchall()

        users = conn.execute('SELECT id, name, email FROM users WHERE id != ?', (user_id,)).fetchall()
        conn.close()

        return render_template('dashboard/messages.html', messages=inbox_messages, users=users)
    else:
        conn.close()
        flash('You need to log in to view messages.', 'danger')
        return redirect(url_for('login'))

@app.route('/send-message', methods=['POST'])
def send_message():
    # Get form data
    sender_id = session.get('user_id')  # Ensure user is logged in
    receiver_id = request.form.get('receiver_id')
    message = request.form.get('message')

    # Check if the user is logged in
    if not sender_id:
        flash('You need to log in to send a message.', 'danger')
        return redirect(url_for('login'))

    # Insert the message into the database
    conn = get_db_connection()
    conn.execute(
        'INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)',
        (sender_id, receiver_id, message)
    )
    conn.commit()
    conn.close()

    flash('Message sent successfully!', 'success')
    return redirect(url_for('messages'))


# Reset Email Function
def send_reset_email(to_email):
    token = generate_reset_token(to_email)
    reset_link = f"http://127.0.0.1:5000/reset-password/{token}"
    msg = Message(
        subject='Password Reset Request',
        sender=app.config['MAIL_DEFAULT_SENDER'],  # Explicit sender configuration
        recipients=[to_email]
    )
    msg.body = f"""Hello,

You requested a password reset. Click the link below to reset your password:
{reset_link}

If you did not request this, please ignore this email or contact support.

Best regards,
The EHR Team
"""
    mail.send(msg)


@app.before_first_request
def log_config():
    print("MAIL_USERNAME:", app.config['MAIL_USERNAME'])
    print("MAIL_DEFAULT_SENDER:", app.config['MAIL_DEFAULT_SENDER'])


@app.route('/manage-patients', methods=['GET'])
def manage_patients():
    if 'roles' not in session or 'doctor' not in session['roles']:
        flash('Access denied: Only doctors can manage patients.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    patients = conn.execute('SELECT * FROM patients WHERE doctor_id = ?', (session['user_id'],)).fetchall()
    conn.close()

    return render_template('dashboard/manage-patients.html', patients=patients)


@app.route('/create-patient', methods=['GET', 'POST'])
def create_patient():
    if 'roles' not in session or 'doctor' not in session['roles']:
        flash('Access denied: Only doctors can add patients.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        gender = request.form['gender']
        condition = request.form['condition']

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO patients (name, age, gender, condition, doctor_id) VALUES (?, ?, ?, ?, ?)',
            (name, age, gender, condition, session['user_id'])
        )
        conn.commit()
        conn.close()

        flash('Patient added successfully!', 'success')
        return redirect(url_for('manage_patients'))

    return render_template('dashboard/create-patient.html')


@app.route('/update-patient/<int:id>', methods=['GET', 'POST'])
def update_patient(id):
    if 'roles' not in session or 'doctor' not in session['roles']:
        flash('Access denied: Only doctors can edit patients.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    patient = conn.execute('SELECT * FROM patients WHERE id = ?', (id,)).fetchone()

    if not patient:
        flash('Patient not found.', 'danger')
        return redirect(url_for('manage_patients'))

    if request.method == 'POST':
        name = request.form['name']
        age = request.form['age']
        gender = request.form['gender']
        condition = request.form['condition']

        conn.execute(
            'UPDATE patients SET name = ?, age = ?, gender = ?, condition = ? WHERE id = ?',
            (name, age, gender, condition, id)
        )
        conn.commit()
        conn.close()

        flash('Patient updated successfully!', 'success')
        return redirect(url_for('manage_patients'))

    conn.close()
    return render_template('dashboard/update-patient.html', patient=patient)


@app.route('/delete-patient/<int:id>', methods=['POST'])
def delete_patient(id):
    if 'roles' not in session or 'doctor' not in session['roles']:
        flash('Access denied: Only doctors can delete patients.', 'danger')
        return redirect(url_for('login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM patients WHERE id = ?', (id,))
    conn.commit()
    conn.close()

    flash('Patient deleted successfully!', 'success')
    return redirect(url_for('manage_patients'))


@app.route('/appointments', methods=['GET'])
def appointments():
    """Display all appointments."""
    conn = get_db_connection()
    appointments = conn.execute('''
        SELECT a.id, a.appointment_date, a.appointment_time, a.reason, a.status, 
               p.name AS patient_name 
        FROM appointments a 
        JOIN patients p ON a.patient_id = p.id
    ''').fetchall()
    conn.close()
    return render_template('dashboard/appointments.html', appointments=appointments)


@app.route('/create-appointment', methods=['GET', 'POST'])
def create_appointment():
    """Create a new appointment."""
    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        appointment_date = request.form.get('appointment_date')
        appointment_time = request.form.get('appointment_time')
        reason = request.form.get('reason')
        status = request.form.get('status')

        # Retrieve the doctor_id from the session
        doctor_id = session.get('user_id')

        if not doctor_id:
            flash('You must be logged in as a doctor to create an appointment.', 'danger')
            return redirect(url_for('login'))

        conn = get_db_connection()
        try:
            conn.execute('''
                INSERT INTO appointments (patient_id, doctor_id, appointment_date, appointment_time, reason, status) 
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (patient_id, doctor_id, appointment_date, appointment_time, reason, status))
            conn.commit()
            flash('Appointment created successfully!', 'success')
        except sqlite3.IntegrityError as e:
            flash(f'Error creating appointment: {str(e)}', 'danger')
        finally:
            conn.close()

        return redirect(url_for('appointments'))

    # Fetch patients for the dropdown
    conn = get_db_connection()
    patients = conn.execute('SELECT id, name FROM patients').fetchall()
    conn.close()
    return render_template('dashboard/create-appointment.html', patients=patients)


@app.route('/edit-appointment/<int:appointment_id>', methods=['GET', 'POST'])
def edit_appointment(appointment_id):
    conn = get_db_connection()
    if request.method == 'POST':
        appointment_date = request.form.get('appointment_date')
        appointment_time = request.form.get('appointment_time')
        reason = request.form.get('reason')
        status = request.form.get('status')

        try:
            conn.execute('''
                UPDATE appointments 
                SET appointment_date = ?, appointment_time = ?, reason = ?, status = ?
                WHERE id = ?
            ''', (appointment_date, appointment_time, reason, status, appointment_id))
            conn.commit()
            flash('Appointment updated successfully!', 'success')
        except sqlite3.Error as e:
            flash(f'Error updating appointment: {str(e)}', 'danger')
        finally:
            conn.close()
        return redirect(url_for('appointments'))

    # Fetch appointment details for editing
    appointment = conn.execute('SELECT * FROM appointments WHERE id = ?', (appointment_id,)).fetchone()
    conn.close()
    if not appointment:
        flash('Appointment not found.', 'danger')
        return redirect(url_for('appointments'))

    return render_template('dashboard/edit-appointment.html', appointment=appointment)


@app.route('/delete-appointment/<int:id>', methods=['POST'])
def delete_appointment(id):
    """Delete an appointment."""
    conn = get_db_connection()
    conn.execute('DELETE FROM appointments WHERE id = ?', (id,))
    conn.commit()
    conn.close()

    flash('Appointment canceled successfully!', 'success')
    return redirect(url_for('appointments'))

@app.route('/analytics', methods=['GET'])
def analytics():
    # Connect to the database
    conn = get_db_connection()

    # Query patient data grouped by gender
    gender_query = conn.execute('''
        SELECT 
            gender, 
            COUNT(*) as count 
        FROM 
            patients 
        GROUP BY 
            gender
    ''').fetchall()

    # Prepare gender data for chart.js
    gender_data = {
        'male': 0,
        'female': 0,
        'other': 0
    }
    for row in gender_query:
        if row['gender'].lower() == 'male':
            gender_data['male'] = row['count']
        elif row['gender'].lower() == 'female':
            gender_data['female'] = row['count']
        else:
            gender_data['other'] = row['count']

    # Query appointment data grouped by status
    status_query = conn.execute('''
        SELECT 
            status, 
            COUNT(*) as count 
        FROM 
            appointments 
        GROUP BY 
            status
    ''').fetchall()

    # Prepare status data for chart.js
    status_data = {
        'scheduled': 0,
        'completed': 0,
        'cancelled': 0
    }
    for row in status_query:
        if row['status'].lower() == 'scheduled':
            status_data['scheduled'] = row['count']
        elif row['status'].lower() == 'completed':
            status_data['completed'] = row['count']
        elif row['status'].lower() == 'cancelled':
            status_data['cancelled'] = row['count']

    # Close the connection
    conn.close()

    # Render the analytics page
    return render_template(
        'dashboard/analytics.html',  # Adjusted path to point to 'dashboard/templates/analytics.html'
        gender_data=[gender_data['male'], gender_data['female'], gender_data['other']],
        status_data=[status_data['scheduled'], status_data['completed'], status_data['cancelled']]
    )

@app.route('/test-email')
def test_email():
    try:
        msg = Message(
            subject='Test Email',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=['your-test-email@example.com'],
            body='This is a test email.'
        )
        mail.send(msg)
        return "Test email sent successfully!"
    except Exception as e:
        return f"Failed to send email: {e}"

print("MAIL_USERNAME:", app.config['MAIL_USERNAME'])
print("MAIL_PASSWORD:", app.config['MAIL_PASSWORD'])
print("MAIL_DEFAULT_SENDER:", app.config['MAIL_DEFAULT_SENDER'])


mail_handler = logging.StreamHandler()
mail_handler.setLevel(logging.DEBUG)
app.logger.addHandler(mail_handler)


# Run the app
if __name__ == '__main__':
    app.run(debug=True)
