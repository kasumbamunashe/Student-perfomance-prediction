from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash
from sqlalchemy.exc import IntegrityError
import random
import string
import os
import uuid
from datetime import datetime
import pandas as pd
import numpy as np
import joblib
from io import BytesIO
from xhtml2pdf import pisa
from flask_mail import Message, Mail
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'

# PostgreSQL Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
                                        'postgresql://postgres:Munashe056@localhost/student'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'



# Flask-Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kasumbamunashe@gmail.com'
app.config['MAIL_PASSWORD'] = 'xgya hlcv zjzr fjxv'  # Use an app-specific password here
app.config['MAIL_DEFAULT_SENDER'] = 'kasumbamunashe@gmail.com'

mail = Mail(app)


# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(1200), nullable=False)  # 'admin' or 'teacher'
    reset_token = db.Column(db.String(255),nullable=True)

class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    surname = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    gender = db.Column(db.String(120), nullable=False)  # 'Male' or 'Female'
    nextOfKin = db.Column(db.String(120), nullable=False)
    nextOfKinPhoneNumber = db.Column(db.String(120), nullable=False)
    nextOfKinEmail = db.Column(db.String(100), nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.String(120), nullable=False)  # 'admin' or 'teacher'
    grade = db.Column(db.String(120), nullable=False)
    assessments = db.relationship('Assessment', backref='student', lazy=True, cascade="all, delete-orphan")
    reset_token = db.Column(db.String(255), nullable=True)  # Make this nullable
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))


class Assessment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='SET NULL'), nullable=True)
    test_score = db.Column(db.Float, nullable=True)
    assignment_score = db.Column(db.Float, nullable=True)
    study_hours = db.Column(db.Float, nullable=True)
    exercise_score = db.Column(db.Float, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id', ondelete='SET NULL'), nullable=True)
    predicted_status = db.Column(db.String(50))
    overall_status = db.Column(db.String(50))
    student = db.relationship('Student', backref='predictions', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

class Suggestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prediction_id = db.Column(db.Integer, db.ForeignKey('prediction.id', ondelete='SET NULL'), nullable=True)
    weak_area = db.Column(db.String(50))
    suggestion = db.Column(db.Text)
    prediction = db.relationship('Prediction', backref='suggestions', lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

model = joblib.load('studentPerfomance5.pkl')
suggestions = {
    'average_study_hours': "Encourage consistent study habits and allocate specific time slots each day for studying.",
    'average_test_mark': "Review test materials regularly, take practice tests, and focus on areas where marks were low.",
    'average_assignment_mark': "Ensure timely completion of assignments, seek feedback from teachers, and improve writing and research skills.",
    'average_exercise_mark': "Participate in regular exercise, join study groups, and engage in discussions to better understand the material."
}

df = pd.read_csv('student_performance_with_grades.csv')
df.drop(columns=['Unnamed: 5'], inplace=True)
threshold_percentile = 0.25
thresholds = df[['average_study_hours', 'average_test_mark', 'average_assignment_mark', 'average_exercise_mark']].quantile(threshold_percentile)

weights = {
    'average_study_hours': 1.5,
    'average_test_mark': 1.5,
    'average_assignment_mark': 1.2,
    'average_exercise_mark': 1.0
}

# Function to identify weak areas with weighting
def identify_weak_areas(row, thresholds, weights):
    weak_areas = []
    for feature in thresholds.index:
        if row[feature] < thresholds[feature]:
            weak_areas.append((feature, weights[feature]))
    return sorted(weak_areas, key=lambda x: x[1], reverse=True)  # Sort by weight

# Function to determine status based on weak areas
def determine_status(weak_areas):
    num_weak_areas = len(weak_areas)
    if num_weak_areas == 0:
        return "High Achiever"
    elif num_weak_areas <= 2:
        return "Proficient"
    elif num_weak_areas <= 3:
        return "Needs Improvement"
    else:
        return "Struggling"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def generate_password(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for i in range(length))
    return password


def send_email(to, subject, template):
    msg = Message(
        subject,
        recipients=[to],
        html=template,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')  # 'admin' or 'teacher'

        # Check if username already exists
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash(f'The username "{username}" is already taken. Please choose another one.', 'danger')
            return redirect(url_for('register'))

        # Proceed with user creation if username does not exist
        password = generate_password()  # Auto-generate password
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password, role=role)

        try:
            db.session.add(user)
            db.session.commit()

            # Send the email with the username and password
            subject = "Your Account Information"
            template = f"<p>Dear {username},</p><p>Your account has been created with the following details:</p><ul><li>Username: {username}</li><li>Password: {password}</li></ul><p>Please keep this information secure.</p>"
            send_email(email, subject, template)

            flash(f'Your account has been created! Your password has been sent to your email.', 'success')
            return redirect(url_for('login'))

        except IntegrityError:
            db.session.rollback()
            flash(f'An error occurred while creating the account. Please try again.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()  # Query by username
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form.get('username')
        user = User.query.filter_by(username=username).first()
        if user:
            token = str(uuid.uuid4())  # Generate a unique token
            # Store the token in the database with an expiration time
            user.reset_token = token
            db.session.commit()
            reset_link = url_for('reset_password', token=token, _external=True)
            subject = "Password Reset Request"
            template = f"<p>Dear {username},</p><p>You requested a password reset. Click the link below to reset your password:</p><p><a href='{reset_link}'>Reset Password</a></p><p>If you didn't request this, please ignore this email.</p>"
            send_email(user.email, subject, template)

            flash('A password reset link has been sent to your email.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Username not found.', 'danger')
    return render_template('forgot_password.html')

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')

        # Check if the current password is correct
        if not bcrypt.check_password_hash(current_user.password, current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('manage_users'))

        # Check if the new passwords match
        if new_password != confirm_new_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('manage_users'))

        # Update the password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        current_user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('dashboard'))

    return render_template('change_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash('Invalid or expired token.', 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('reset_password.html', token=token)

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user.password = hashed_password
        user.reset_token = None  # Clear the token after reset
        db.session.commit()
        flash('Your password has been updated!', 'success')
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token)


@app.route('/dashboard')
@login_required
def dashboard():
    # Check if the current user is an admin
    if current_user.role == 'admin':
        users = User.query.all()
        students = Student.query.all()
        return render_template('admin_dashboard.html', user=current_user, users=users, students=students)

    # Check if the current user is a teacher
    elif current_user.role == 'teacher':
        students = Student.query.all()

        # Get the latest assessment for each student
        assessments = db.session.query(
            Assessment
        ).distinct(Assessment.student_id).order_by(
            Assessment.student_id,
            Assessment.created_at.desc()
        ).all()

        # Get the most recent prediction for each student
        recent_predictions = db.session.query(
            Prediction
        ).distinct(Prediction.student_id).order_by(
            Prediction.student_id,
            Prediction.created_at.desc()
        ).all()

        # Render the teacher's dashboard and pass the assessments and predictions to the template
        return render_template(
            'teacher_dashboard.html',
            user=current_user,
            students=students,
            assessments=assessments,
            predictions=recent_predictions
        )

    # Check if the current user is a student
    elif current_user.role == 'student':
        # Query student by user_id
        student = Student.query.filter_by(user_id=current_user.id).first()
        if student is None:
            flash('Student not found.', 'danger')
            return redirect(url_for('login'))

        # Get the student's assessments and predictions with their suggestions
        assessments = Assessment.query.filter_by(student_id=student.id).all()
        predictions = db.session.query(Prediction).filter_by(student_id=student.id).all()

        # Render the student's dashboard
        return render_template(
            'student_dashboard.html',
            user=current_user,
            student=student,
            assessments=assessments,
            predictions=predictions
        )


    # Handle unauthorized access
    else:
        flash('You do not have permission to access this dashboard.', 'danger')
        return redirect(url_for('login'))



@app.route('/add_user', methods=['POST'])
@login_required
def add_user():
    username = request.form.get('username')
    email = request.form.get('email')
    password = generate_password()
    role = request.form.get('role')

    # Check if username or email already exists
    existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
    if existing_user:
        return jsonify({'success': False, 'message': "Username or email already exists. Please choose a different one."}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    new_user = User(username=username, email=email, password=hashed_password, role=role)

    db.session.add(new_user)

    try:
        db.session.commit()

        # Send email after the user is successfully added
        subject = f"{role.capitalize()} Account Created"
        template = f"""
            <p>Dear {username},</p>
            <p>Your {role.lower()} account has been created with the following details:</p>
            <ul>
                <li>Username: {username}</li>
                <li>Password: {password}</li>
            </ul>
            <p>Please keep this information secure.</p>
        """
        send_email(email, subject, template)

        return jsonify({'success': True, 'message': "User added successfully."})
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': "An error occurred while adding the user. Please try again."}), 500


@app.route('/edit_user/<int:user_id>', methods=['POST'])
@login_required
def edit_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    user.username = request.form.get('username')
    user.email = request.form.get('email')
    user.role = request.form.get('role')  # Update the role
    db.session.commit()
    flash('User updated successfully', 'success')
    return redirect(url_for('manage_users'))


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role != 'admin':
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('manage_users'))

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/update_profile', methods=['GET', 'POST'])
@login_required
def update_profile():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']

        current_user.username = username
        current_user.email = email
        db.session.commit()

        flash('Profile updated successfully', 'success')
        return redirect(url_for('update_profile'))

    # Handle GET request to display the form
    return render_template('update_profile.html', user=current_user)


@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    # Get role filter from query parameters
    role_filter = request.args.get('role', 'all')

    # Fetch users based on role filter
    if role_filter == 'all':
        users = User.query.all()
    else:
        users = User.query.filter_by(role=role_filter).all()

    # Fetch all students
    students = Student.query.all()

    # Render the template with users and students
    return render_template('admin_dashboard.html', users=users, students=students, user=current_user, role_filter=role_filter)


@app.route('/update_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        user.role = request.form.get('role')

        db.session.commit()
        flash('User details updated successfully', 'success')
        return redirect(url_for('manage_users'))

    return render_template('update_user.html', user=user, current_user=current_user)


@app.route('/manage_students', methods=['GET', 'POST'])
@login_required
def manage_students():
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        student_id = request.form.get('id')
        if student_id:
            student = Student.query.get(student_id)
            if student:
                try:
                    db.session.delete(student)
                    db.session.commit()
                    flash('Student deleted successfully', 'success')
                except Exception as e:
                    db.session.rollback()
                    flash(f'An error occurred while deleting the student: {e}', 'danger')
        else:
            email = request.form.get('email')
            existing_student = Student.query.filter_by(email=email).first()
            existing_user = User.query.filter_by(email=email).first()
            if existing_student:
                flash('A student with this email already exists. Please use a different email.', 'danger')
            elif existing_user:
                flash('A user with this email already exists. Please use a different email.', 'danger')
            else:
                name = request.form.get('name')
                surname = request.form.get('surname')
                gender = request.form.get('gender')
                next_of_kin = request.form.get('nextOfKin')
                next_of_kin_phone = request.form.get('nextOfKinPhoneNumber')
                next_of_kin_email = request.form.get('nextOfKinEmail')
                password = generate_password()  # Generate password
                role = 'student'
                hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
                grade = request.form.get('grade')

                if not all([name, surname, email, grade, gender, next_of_kin, next_of_kin_phone, next_of_kin_email]):
                    flash('All fields are required!', 'warning')
                    return redirect(url_for('manage_students'))

                user1 = User(username=email, email=email, password=hashed_password, role=role)
                try:
                    db.session.add(user1)
                    db.session.commit()  # Commit to get user1.id

                    student = Student(
                        name=name, surname=surname, username=email, email=email, gender=gender,
                        nextOfKin=next_of_kin, nextOfKinPhoneNumber=next_of_kin_phone,
                        nextOfKinEmail=next_of_kin_email, password=hashed_password, role=role, grade=grade,
                        reset_token=None,  # Explicitly set to None if not used
                        user_id=user1.id  # Set the user_id from the newly created User
                    )

                    db.session.add(student)
                    db.session.commit()

                    subject = "Student Account Created"
                    template = f"<p>Dear {name} {surname},</p><p>Your student account has been created with the following details:</p><ul><li>Username: {email}</li><li>Password: {password}</li></ul><p>Please keep this information secure.</p>"
                    send_email(email, subject, template)
                    flash('Student added successfully', 'success')
                except IntegrityError as e:
                    db.session.rollback()
                    flash(f'An error occurred while adding the student: {e}', 'danger')
                except Exception as e:
                    db.session.rollback()
                    flash(f'An unexpected error occurred: {e}', 'danger')

    students = Student.query.all()
    return render_template('admin_dashboard.html', students=students, user=current_user)



@app.route('/update_student', methods=['POST'])
def update_student():
    student_id = request.form.get('student_id')
    name = request.form.get('name')
    surname = request.form.get('surname')
    email = request.form.get('email')
    grade = request.form.get('grade')
    gender = request.form.get('gender')
    next_of_kin = request.form.get('nextOfKin')
    next_of_kin_phone_number = request.form.get('nextOfKinPhoneNumber')
    next_of_kin_email = request.form.get('nextOfKinEmail')

    # Find the student by ID
    student = Student.query.get_or_404(student_id)

    # Find the associated user by email
    user = User.query.filter_by(email=student.email).first_or_404()

    try:
        # Update Student fields
        student.name = name
        student.surname = surname
        student.email = email
        student.gender = gender
        student.nextOfKin = next_of_kin
        student.nextOfKinPhoneNumber = next_of_kin_phone_number
        student.nextOfKinEmail = next_of_kin_email
        student.grade = grade

        # Update User fields if email has changed
        if user.email != email:
            user.email = email

        # Update username in User table if provided
        # (Assuming you also want to update the username, if it's a field in your form)
        # if 'username' in request.form:
        #     user.username = request.form.get('username', user.username)

        db.session.commit()
        flash('Student details updated successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Failed to update student details: {}'.format(str(e)), 'danger')

    return redirect(url_for('dashboard'))


@app.route('/delete_student/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    if current_user.role != 'admin':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    student = Student.query.get_or_404(student_id)  # Returns 404 if student not found
    try:
        # Delete all suggestions associated with each prediction of this student
        predictions = Prediction.query.filter_by(student_id=student.id).all()
        for prediction in predictions:
            Suggestion.query.filter_by(prediction_id=prediction.id).delete()

        # Delete all predictions associated with this student
        Prediction.query.filter_by(student_id=student.id).delete()

        # Delete all assessments associated with this student (if needed)
        Assessment.query.filter_by(student_id=student.id).delete()

        # Now delete the student
        db.session.delete(student)
        db.session.commit()

        flash('Student and all associated assessments, predictions, and suggestions deleted successfully', 'success')
    except IntegrityError as e:
        db.session.rollback()
        flash(f'An integrity error occurred while deleting the student: {e}', 'danger')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred while deleting the student: {e}', 'danger')

    return redirect(url_for('dashboard'))


@app.route('/student_management')
@login_required
def student_management():
    students = Student.query.all()  # Fetch all students from the database
    return render_template('admin_dashboard.html', students=students)


@app.route('/api/students', methods=['GET'])
def api_students():
    students = Student.query.all()
    student_list = [{'id': student.id, 'name': student.name, 'surname': student.surname,
                     'email': student.email, 'gender': student.gender, 'grade': student.grade}
                    for student in students]
    return jsonify(student_list)


@app.route('/add_assessment', methods=['POST'])
@login_required
def add_assessment():
    # Get form data
    student_id = request.form.get('student_id')
    test_score = request.form.get('test_score')
    assignment_score = request.form.get('assignment_score')
    study_hours = request.form.get('study_hours')
    exercise_score = request.form.get('exercise_score')

    # Validate that student_id is provided
    if not student_id:
        return jsonify({'success': False, 'message': 'Student ID is required.'})

    # Validate that the student exists
    student = Student.query.get(student_id)
    if not student:
        return jsonify({'success': False, 'message': 'Student not found.'})

    # Initialize default values for optional fields
    test_score = int(test_score) if test_score else None
    assignment_score = int(assignment_score) if assignment_score else None
    study_hours = int(study_hours) if study_hours else None
    exercise_score = int(exercise_score) if exercise_score else None

    # Validate numeric inputs if they are provided
    if test_score is not None and test_score < 0:
        return jsonify({'success': False, 'message': 'Test score must be non-negative.'})
    if assignment_score is not None and assignment_score < 0:
        return jsonify({'success': False, 'message': 'Assignment score must be non-negative.'})
    if study_hours is not None and study_hours < 0:
        return jsonify({'success': False, 'message': 'Study hours must be non-negative.'})
    if exercise_score is not None and exercise_score < 0:
        return jsonify({'success': False, 'message': 'Exercise score must be non-negative.'})

    # Add logic to save the new assessment to the database
    try:
        new_assessment = Assessment(
            student_id=student_id,
            test_score=test_score,
            assignment_score=assignment_score,
            study_hours=study_hours,
            exercise_score=exercise_score
        )
        db.session.add(new_assessment)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

    return redirect(url_for('dashboard'))

    # GET request
    search_query = request.args.get('search', '')
    if search_query:
        students = Student.query.filter(Student.name.ilike(f'%{search_query}%')).all()
    else:
        students = Student.query.all()

    return render_template('add_assessment.html', students=students)


@app.route('/teacher_dashboard')
@login_required
def teacher_dashboard():
    if current_user.role != 'teacher':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('login'))

    assessments = Assessment.query.all()
    return render_template('teacher_dashboard.html', assessments=assessments, user=current_user)


@app.route('/search_students', methods=['GET'])
def search_students():
    query = request.args.get('name', '')

    if query:
        # Query for students matching the search term
        students = Student.query.filter(
            (Student.name.ilike(f'%{query}%')) |
            (Student.surname.ilike(f'%{query}%'))
        ).all()
    else:
        # Return all students if no search term is provided
        students = Student.query.all()

    # Prepare the result to return
    result = [
        {
            'id': student.id,
            'name': student.name,
            'surname': student.surname
        }
        for student in students
    ]

    return jsonify(result)


@app.route('/delete-assessment/<int:assessment_id>', methods=['POST'])
@login_required
def delete_assessment(assessment_id):
    assessment = Assessment.query.get(assessment_id)
    if not assessment:
        return jsonify({'success': False, 'message': 'Assessment not found.'})

    try:
        db.session.delete(assessment)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/update-assessment/<int:assessment_id>', methods=['GET', 'POST'])
@login_required
def update_assessment(assessment_id):
    if current_user.role != 'teacher':
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('dashboard'))

    assessment = Assessment.query.get_or_404(assessment_id)

    if request.method == 'POST':
        try:
            assessment.test_score = float(request.form.get('test_score'))
            assessment.assignment_score = float(request.form.get('assignment_score'))
            assessment.study_hours = float(request.form.get('study_hours'))
            assessment.exercise_score = float(request.form.get('exercise_score'))

            # Validate that scores are within acceptable ranges
            if not (0 <= assessment.test_score <= 100 and 0 <= assessment.assignment_score <= 100 and 0 <= assessment.exercise_score <= 100):
                flash('Scores must be between 0 and 100.', 'danger')
                return redirect(url_for('update_assessment', assessment_id=assessment_id))

            db.session.commit()
            flash('Assessment updated successfully!', 'success')
            return redirect(url_for('add_assessment'))
        except ValueError:
            flash('Please enter valid numeric values for all scores.', 'danger')
            return redirect(url_for('update_assessment', assessment_id=assessment_id))

    return redirect(url_for('dashboard'))


def evaluate_student_performance(new_student_marks):
    new_student_df = pd.DataFrame([new_student_marks])

    predicted_status = model.predict(new_student_df)
    predicted_status_label = 'Pass' if predicted_status[0] == 1 else 'Fail'

    new_student_df['weak_areas'] = new_student_df.apply(lambda row: identify_weak_areas(row, thresholds, weights),
                                                        axis=1)
    new_student_df['status'] = new_student_df['weak_areas'].apply(determine_status)
    new_student_df['suggestions'] = new_student_df['weak_areas'].apply(
        lambda areas: [suggestions[area[0]] for area in areas])

    weak_areas = new_student_df['weak_areas'].values[0]
    suggestions_list = new_student_df['suggestions'].values[0]
    status = new_student_df['status'].values[0]

    return {
        'predicted_status': predicted_status_label,
        'status': status,
        'weak_areas': weak_areas,
        'suggestions': suggestions_list
    }


@app.route('/predict/<int:student_id>', methods=['GET'])
def predict(student_id):
    student = Student.query.get_or_404(student_id)

    # Get the last three assessments
    assessments = Assessment.query.filter_by(student_id=student_id).order_by(Assessment.created_at.desc()).limit(
        3).all()
    if len(assessments) < 3:
        return "Not enough assessment data for prediction."

    # Calculate the average marks
    avg_study_hours = sum(a.study_hours for a in assessments) / len(assessments)
    avg_test_mark = sum(a.test_score for a in assessments) / len(assessments)
    avg_assignment_mark = sum(a.assignment_score for a in assessments) / len(assessments)
    avg_exercise_mark = sum(a.exercise_score for a in assessments) / len(assessments)

    # Prepare the data for prediction
    new_student_marks = {
        'average_study_hours': avg_study_hours,
        'average_test_mark': avg_test_mark,
        'average_assignment_mark': avg_assignment_mark,
        'average_exercise_mark': avg_exercise_mark
    }

    result = evaluate_student_performance(new_student_marks)

    # Save the prediction results
    prediction = Prediction(
        student_id=student_id,
        predicted_status=result['predicted_status'],
        overall_status=result['status']
    )
    db.session.add(prediction)
    db.session.commit()

    # Save suggestions
    for area, suggestion in zip(result['weak_areas'], result['suggestions']):
        suggestion_entry = Suggestion(
            prediction_id=prediction.id,
            weak_area=area[0],
            suggestion=suggestion
        )
        db.session.add(suggestion_entry)

    db.session.commit()

    # Send email to next of kin
    sendPred_email(student.nextOfKinEmail,student.name, result)

    return f"Prediction done for {student.name}. Status: {result['status']}"


from flask import jsonify

@app.route('/view_predictions/<int:student_id>', methods=['GET'])
def view_prediction(student_id):
    student = Student.query.get_or_404(student_id)
    predictions = Prediction.query.filter_by(student_id=student_id).order_by(Prediction.created_at.desc()).all()

    if not predictions:
        return jsonify({"error": f"No predictions found for student {student.name}."}), 404

    latest_prediction = predictions[0]
    latest_suggestions = Suggestion.query.filter_by(prediction_id=latest_prediction.id).order_by(Suggestion.created_at.desc()).all()

    result = {
        'id': latest_prediction.id,
        'predicted_status': latest_prediction.predicted_status,
        'overall_status': latest_prediction.overall_status,
        'suggestions': [suggestion.suggestion for suggestion in latest_suggestions],
        'student_name': f"{student.name} {student.surname}"
    }

    return jsonify(result)



@app.route('/filter_predictions/<status>', methods=['GET'])
def filter_predictions(status):
    valid_statuses = ['High Achiever', 'Proficient', 'Needs Improvement', 'Struggling']
    if status not in valid_statuses:
        return "Invalid status filter."

    predictions = Prediction.query.filter_by(overall_status=status).all()

    if not predictions:
        return f"No predictions found with status {status}."

    results = []
    for prediction in predictions:
        student = Student.query.get(prediction.student_id)
        suggestions = Suggestion.query.filter_by(prediction_id=prediction.id).all()
        result = {
            'student_name': f"{student.name} {student.surname}",
            'predicted_status': prediction.predicted_status,
            'overall_status': prediction.overall_status,
            'suggestions': [suggestion.suggestion for suggestion in suggestions]
        }
        results.append(result)

    return render_template('filter_predictions.html', status=status, results=results)


def sendPred_email(recipient, student_name, result):
    msg = Message(
        "Student Performance Prediction",
        sender="your_email@gmail.com",
        recipients=[recipient]
    )

    msg.body = f"""
    Dear {student_name},

    Please find below the details of your recent performance prediction:

    ------------------------------------------------
    Predicted Status:         {result['predicted_status']}
    Overall Status:           {result['status']}
    ------------------------------------------------

    Weak Areas Identified:
    {result['weak_areas']}

    Suggestions for Improvement:
    {result['suggestions']}

    ------------------------------------------------

    We encourage you to take these suggestions seriously to improve your academic performance.

    Best regards,
    Your School's Performance Team
    """

    mail.send(msg)


@app.route('/predict_all', methods=['GET'])
def predict_all():
    students = Student.query.all()
    if not students:
        return "No students found."

    for student in students:
        # Get the last three assessments for each student
        assessments = Assessment.query.filter_by(student_id=student.id).order_by(Assessment.created_at.desc()).limit(
            3).all()
        if len(assessments) < 3:
            continue  # Skip this student if not enough data

        # Calculate the average marks
        avg_study_hours = sum(a.study_hours for a in assessments) / len(assessments)
        avg_test_mark = sum(a.test_score for a in assessments) / len(assessments)
        avg_assignment_mark = sum(a.assignment_score for a in assessments) / len(assessments)
        avg_exercise_mark = sum(a.exercise_score for a in assessments) / len(assessments)

        # Prepare the data for prediction
        new_student_marks = {
            'average_study_hours': avg_study_hours,
            'average_test_mark': avg_test_mark,
            'average_assignment_mark': avg_assignment_mark,
            'average_exercise_mark': avg_exercise_mark
        }

        result = evaluate_student_performance(new_student_marks)

        # Save the prediction results
        prediction = Prediction(
            student_id=student.id,
            predicted_status=result['predicted_status'],
            overall_status=result['status']
        )
        db.session.add(prediction)
        db.session.flush()  # Ensure the prediction is saved and the ID is available

        # Save suggestions
        for area, suggestion in zip(result['weak_areas'], result['suggestions']):
            suggestion_entry = Suggestion(
                prediction_id=prediction.id,
                weak_area=area[0],
                suggestion=suggestion
            )
            db.session.add(suggestion_entry)

        db.session.commit()  # Commit changes for each student

        # Send email to next of kin with the student's name included
        sendPred_email(student.nextOfKinEmail, student.name, result)

    return "Predictions done for all students."


@app.route('/predictions')
def view_predictions():
    # Query the latest prediction for each student
    latest_predictions = (
        db.session.query(Prediction)
            .join(Suggestion, Prediction.id == Suggestion.prediction_id, isouter=True)
            .add_entity(Suggestion)
            .filter(Prediction.created_at == db.session.query(db.func.max(Prediction.created_at))
                    .filter(Prediction.student_id == Prediction.student_id))
            .all()
    )

    # Create a dictionary to hold the latest suggestion for each prediction
    latest_suggestions = {}
    for prediction, suggestion in latest_predictions:
        if suggestion:
            latest_suggestions[prediction.id] = suggestion

    return render_template('predictions.html', predictions=latest_predictions, latest_suggestions=latest_suggestions)



def generate_pdf_report(student_id):
    # Retrieve student data from the database
    student = Student.query.get(student_id)
    if not student:
        return None, "Student not found"

    # Retrieve predictions and suggestions
    predictions = Prediction.query.filter_by(student_id=student_id).all()
    suggestions = Suggestion.query.join(Prediction).filter(Prediction.student_id == student_id).all()

    # Render the HTML content for the report
    html = render_template('student_report.html', student=student, predictions=predictions, suggestions=suggestions)

    # Convert HTML to PDF
    pdf = BytesIO()
    pisa_status = pisa.CreatePDF(html, dest=pdf)

    if pisa_status.err:
        return None, "PDF generation failed"

    pdf.seek(0)
    return pdf, None

def send_report(student_email, next_of_kin_email, pdf_file):
    msg = Message('Student Performance Report', sender='your_email@example.com', recipients=[student_email, next_of_kin_email])
    msg.body = 'Please find attached the performance report for your student.'
    pdf_file.seek(0)  # Reset file pointer to the beginning
    msg.attach('report.pdf', 'application/pdf', pdf_file.read())

    with mail.connect() as conn:
        conn.send(msg)

@app.route('/generate_report/<int:student_id>', methods=['GET'])
def generate_and_send_report(student_id):
    pdf, error = generate_pdf_report(student_id)
    if error:
        return jsonify({'error': error}), 500

    student = Student.query.get(student_id)
    if not student:
        return jsonify({'error': 'Student not found'}), 404

    send_report(student.email, student.nextOfKinEmail, pdf)

    # Return PDF as a downloadable file
    pdf.seek(0)
    return send_file(pdf, as_attachment=True, download_name='report.pdf', mimetype='application/pdf')


@app.route('/generate_all_reports', methods=['POST'])
def generate_all_reports():
    students = Student.query.all()
    for student in students:
        pdf, error = generate_pdf_report(student.id)
        if error:
            flash(f"Error generating report for {student.name}: {error}", 'error')
            continue

        # Send email with the report
        try:
            msg = Message(
                subject="Your Performance Report",
                recipients=[student.email, student.nextOfKinEmail],
                body="Please find your performance report attached.",
                html=render_template('email_body.html', student=student)  # Create an email body template if needed
            )
            msg.attach("report.pdf", "application/pdf", pdf.read())
            mail.send(msg)
        except Exception as e:
            flash(f"Error sending report for {student.name}: {str(e)}", 'error')
            continue

    flash("All reports have been generated and sent successfully.", 'success')
    return redirect(url_for('dashboard'))  # Redirect to a page after processing


@app.route('/update_studentP', methods=['GET', 'POST'])
@login_required
def update_studentP():
    # Fetch the student profile based on the current user ID
    student = Student.query.filter_by(id=current_user.id).first()

    if request.method == 'POST':
        # Update the student profile with the form data
        student.name = request.form['name']
        student.surname = request.form['surname']
        student.email = request.form['email']
        student.gender = request.form['gender']
        student.grade = request.form['grade']
        student.nextOfKin = request.form['nextOfKin']
        student.nextOfKinPhoneNumber = request.form['nextOfKinPhoneNumber']
        student.nextOfKinEmail = request.form['nextOfKinEmail']

        try:
            # Save the changes to the database
            db.session.commit()
            flash('Profile updated successfully!', 'success')
        except:
            # Handle errors in saving to the database
            db.session.rollback()
            flash('Error updating profile. Please try again.', 'danger')

        # Redirect back to the profile page
        return redirect(url_for('update_studentP'))

    # Render the profile page with the student data
    return render_template('student_dashboard.html', student=student)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables are created
    app.run(debug=True)
