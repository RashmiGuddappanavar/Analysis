import os
import pickle
import pandas as pd
from flask import Flask, request, render_template, flash, redirect, session, abort, jsonify
from datetime import datetime
from analytics import write_to_csv_departments, write_to_csv_teachers
from models import StemmedCountVectorizer
from analytics import get_counts, get_tables, get_titles
from teacherdashboard import get_feedback_counts
from bcrypt import hashpw, gensalt, checkpw

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Load users from the database
        try:
            df = pd.read_csv('dataset/users.csv')
            user = df.loc[df['username'] == username]
            if not user.empty and checkpw(password.encode('utf-8'), user.iloc[0]['password'].encode('utf-8')):
                session['logged_in'] = True
                role = user.iloc[0]['role']
                if role == 'admin':
                    return redirect('/admin')
                elif role == 'hod':
                    return redirect('/hoddashboard')
                elif role == 'teacher':
                    teacher_number = int(username.replace('teacher', ''))
                    return redirect(f'/teacherdashboard/{teacher_number}')
                elif role == 'student':
                    return render_template('student_dashboard.html')
            else:
                flash("Invalid username or password", 'error')
                return render_template('loginerror.html')
        except Exception as e:
            flash(f"Error loading users: {str(e)}", 'error')
            return render_template('loginerror.html')

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        role = request.form['role']  # e.g., admin, hod, teacher, or student

        if password != confirm_password:
            flash("Passwords do not match!", 'error')
            return redirect('/signup')

        # Hash the password for security
        hashed_password = hashpw(password.encode('utf-8'), gensalt()).decode('utf-8')

        # Save user to the CSV file (database or file storage)
        user_data = {'username': username, 'password': hashed_password, 'role': role}

        try:
            if os.path.exists('dataset/users.csv'):
                df = pd.read_csv('dataset/users.csv')
            else:
                df = pd.DataFrame(columns=['username', 'password', 'role'])

            if username in df['username'].values:
                flash("Username already exists. Please choose another one.", 'error')
                return redirect('/signup')

            new_user = pd.DataFrame([user_data])
            df = pd.concat([df, new_user], ignore_index=True)
            df.to_csv('dataset/users.csv', index=False)
            flash("Signup successful! Please log in.", 'success')
        except Exception as e:
            flash(f"Error saving user: {str(e)}", 'error')
            return redirect('/signup')

        return redirect('/login')  # Redirect to login page after successful signup

    return render_template('signup.html')

@app.route("/logout")
def logout():
    session['logged_in'] = False
    return redirect('/')

def teacherdashboard(teachernumber):
    ttf, teachers_total_positive_feedbacks, teachers_total_negative_feedbacks, teachers_total_neutral_feedbacks, teachers_li = get_feedback_counts()

    # Extract feedback counts for each teacher
    teacher_feedback = teachers_li[teachernumber-1]

    # Calculate percentage scores
    percentages = [int(round(feedback / ttf * 100)) for feedback in teacher_feedback]

    return render_template('teacherdashboard.html', ttf=ttf, 
                           ttp=percentages[0], ttn=percentages[1], ttneu=percentages[2])

@app.route("/predict", methods=['POST'])
def predict():
    form_data = {field: request.form[field] for field in ['Teaching', 'Placements', 'CollaborationWithCompanies', 
                                                           'Infrastructure', 'Hostel', 'Library', 'Sports', 'Events', 
                                                           'teacher1', 'teacher2', 'teacher3', 'teacher4', 'teacher5', 'teacher6']}

    model = pickle.load(open('SVM classifier.pkl', 'rb'))

    # Predict scores for various departments and teachers
    department_scores = {key: model.predict(pd.array([value]))[0] for key, value in form_data.items() if key not in ['teacher1', 'teacher2', 'teacher3', 'teacher4', 'teacher5', 'teacher6']}
    teacher_scores = {f"teacher{i}": model.predict(pd.array([form_data[f"teacher{i}"]]))[0] for i in range(1, 7)}

    time = datetime.now().strftime("%m/%d/%Y (%H:%M:%S)")

    # Write department and teacher scores to respective CSVs
    write_to_csv_departments(time, department_scores)
    write_to_csv_teachers(teacher_scores)

    return render_template('thankyoupage.html')

@app.route('/admin')
def root():
    if not session.get('logged_in'):
        return redirect('/login')

    total_feedbacks, total_positive_feedbacks, total_negative_feedbacks, total_neutral_feedbacks, li = get_counts()
    teachers_feedback = get_feedback_counts()[1]

    return render_template('admin.html', tf=total_feedbacks, tpf=total_positive_feedbacks, tnegf=total_negative_feedbacks, 
                           tneuf=total_neutral_feedbacks, tp=li[0], tn=li[1], tneu=li[2], teachers_feedback=teachers_feedback)

@app.route("/hoddashboard")
def hoddashboard():
    if not session.get('logged_in'):
        return redirect('/login')

    teachers_feedback = get_feedback_counts()[1]
    return render_template('hoddashboard.html', teachers_feedback=teachers_feedback)

@app.route("/teacherdashboard/<int:teachernumber>")
def teacherdashboard_page(teachernumber):
    if not session.get('logged_in'):
        return redirect('/login')

    ttf, teachers_total_positive_feedbacks, teachers_total_negative_feedbacks, teachers_total_neutral_feedbacks, teachers_li = get_feedback_counts()

    # Extract feedback counts for each teacher
    teacher_feedback = teachers_li[teachernumber-1]
    percentages = [int(round(feedback / ttf * 100)) for feedback in teacher_feedback]

    return render_template('teacherdashboard.html', ttf=ttf, ttp=percentages[0], ttn=percentages[1], ttneu=percentages[2])

@app.route("/displayteacherfeedbacks")
def displayteacherfeedbacks():
    if not session.get('logged_in'):
        return redirect('/login')

    df1 = pd.read_csv('dataset/teacherdb.csv')
    return render_template('teacherfeedbacks.html', tables=[df1.to_html(classes='data', header="true")])

@app.route("/display")
def display():
    if not session.get('logged_in'):
        return redirect('/login')

    df = pd.read_csv('dataset/database.csv')
    return render_template('feedbacks.html', tables=[df.to_html(classes='data', header="true")])

app.secret_key = os.urandom(12)
app.run(port=5000, host='0.0.0.0', debug=True)
