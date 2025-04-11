from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from datetime import datetime
import joblib
import numpy as np
import os
from bson.objectid import ObjectId


app = Flask(__name__)
app.secret_key = os.urandom(24)

# MongoDB Configuration
client = MongoClient('mongodb://localhost:27017/')
db = client['heart_disease_db']
users = db['users']
predictions = db['predictions']

# Load ML model
model = joblib.load('models\svm_model.pkl')
scaler = joblib.load('models\scaler.pkl')

# --------------------------
# COMMON ROUTES
# --------------------------
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('home'))

# --------------------------
# USER AUTHENTICATION
# --------------------------
@app.route('/user/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        if users.find_one({'email': email}):
            flash('Email already exists!', 'danger')
            return redirect(url_for('user_register'))
        
        users.insert_one({
            'email': email,
            'password': password,
            'role': 'user',
            'created_at': datetime.now(),
            'name': request.form.get('name', ''),
            'status': 'active'
        })
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('user_login'))
    
    return render_template('auth/user_register.html')

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users.find_one({'email': email, 'role': 'user'})
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['user_email'] = user['email']
            session['user_role'] = 'user'
            if 'name' in user:
                session['user_name'] = user['name']
            flash('Login successful!', 'success')
            return redirect(url_for('patient_dashboard'))
        
        flash('Invalid credentials or not a user account!', 'danger')
    
    return render_template('auth/user_login.html')

# --------------------------
# ADMIN AUTHENTICATION
# --------------------------
@app.route('/admin/register', methods=['GET', 'POST'])
def admin_register():
    if users.count_documents({'role': 'admin'}) > 4:
        flash('Admin registration is restricted!', 'danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        
        users.insert_one({
            'email': email,
            'password': password,
            'role': 'admin',
            'created_at': datetime.now(),
            'status': 'active'
        })
        flash('First admin registered successfully!', 'success')
        return redirect(url_for('admin_login'))
    
    return render_template('auth/admin_register.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = users.find_one({'email': email, 'role': 'admin'})
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = str(user['_id'])
            session['user_email'] = user['email']
            session['user_role'] = 'admin'
            flash('Admin login successful!', 'success')
            return redirect(url_for('admin_dashboard'))
        
        flash('Invalid credentials or not an admin account!', 'danger')
    
    return render_template('auth/admin_login.html')

# --------------------------
# USER PORTAL ROUTES
# --------------------------
@app.route('/patient/dashboard')
def patient_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'user':
        return redirect(url_for('user_login'))
    
    user_predictions = list(predictions.find(
        {'user_id': session['user_id']}
    ).sort('timestamp', -1).limit(5))
    
    return render_template('user/dashboard.html',
                         predictions=user_predictions,
                         user_name=session.get('user_name', 'Patient'))

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
    
    if request.method == 'POST':
        try:
            features = [
                float(request.form['age']),
                float(request.form['sex']),
                float(request.form['cp']),
                float(request.form['trestbps']),
                float(request.form['chol']),
                float(request.form['fbs']),
                float(request.form['restecg']),
                float(request.form['thalach']),
                float(request.form['exang']),
                float(request.form['oldpeak']),
                float(request.form['slope']),
                float(request.form['ca']),
                float(request.form['thal'])
            ]
            
            scaled_features = scaler.transform([features])
            prediction = model.predict(scaled_features)[0]
            probability = model.predict_proba(scaled_features)[0][1] * 100
            
            pred_id = predictions.insert_one({
                'user_id': session['user_id'],
                'user_email': session['user_email'],
                'features': features,
                'prediction': int(prediction),
                'probability': float(probability),
                'timestamp': datetime.now()
            }).inserted_id
            
            return redirect(url_for('prediction_report', prediction_id=pred_id))
        
        except Exception as e:
            flash('Error processing your request. Please check your inputs.', 'danger')
    
    return render_template('user/predict.html')

@app.route('/report/<prediction_id>')
def prediction_report(prediction_id):
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
    
    prediction = predictions.find_one({'_id': ObjectId(prediction_id), 'user_id': session['user_id']})
    if not prediction:
        flash('Report not found', 'danger')
        return redirect(url_for('patient_dashboard'))
    
    return render_template('user/report.html', prediction=prediction)

@app.route('/history')
def prediction_history():
    if 'user_id' not in session:
        return redirect(url_for('user_login'))
    
    user_predictions = list(predictions.find(
        {'user_id': session['user_id']}
    ).sort('timestamp', -1))
    
    return render_template('user/history.html', predictions=user_predictions)

# --------------------------
# ADMIN PORTAL ROUTES
# --------------------------
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('admin_login'))
    
    total_users = users.count_documents({})
    total_predictions = predictions.count_documents({})
    high_risk = predictions.count_documents({'prediction': 1})
    
    recent_predictions = list(predictions.find().sort('timestamp', -1).limit(5))
    
    return render_template('admin/dashboard.html',
                         total_users=total_users,
                         total_predictions=total_predictions,
                         high_risk=high_risk,
                         recent_predictions=recent_predictions)

@app.route('/admin/users')
def admin_users():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('admin_login'))
    
    all_users = list(users.find())
    return render_template('admin/users.html', users=all_users)

@app.route('/admin/edit_user/<user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('admin_login'))
    
    user = users.find_one({'_id': ObjectId(user_id)})
    
    if request.method == 'POST':
        update_data = {
            'name': request.form.get('name'),
            'email': request.form.get('email'),
            'status': request.form.get('status', 'active')
        }
        users.update_one({'_id': ObjectId(user_id)}, {'$set': update_data})
        flash('User updated successfully!', 'success')
        return redirect(url_for('admin_users'))
    
    return render_template('admin/edit_user.html', user=user)

@app.route('/admin/model_performance')
def model_performance():
    if 'user_id' not in session or session.get('user_role') != 'admin':
        return redirect(url_for('admin_login'))
    
    
    # Example data - replace with actual model comparisons
    performance_data = {
        'svm': {'accuracy': 0.8146341463414634, 'precision': 0.76, 'recall': 0.9223300970873787},
        'decision_tree': {'accuracy': 0.8439024390243902, 'precision': 0.784, 'recall': 0.9514563106796117}
    }
    return render_template('admin/model_performance.html', data=performance_data)

if __name__ == '__main__':
    app.run(debug=True)