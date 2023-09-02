from flask import Flask, render_template, session, redirect, url_for, g, request, flash
from database import get_db, close_db
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
import uuid
import smtplib
import ssl
from email.message import EmailMessage
from functools import wraps
from forms import RegistrationForm, AddAdmin, LoginForm, TaskManager, ForgotForm, ResetPassword, ForgotPasswordReset, SendMail, ResetUsername, ResetEmail, UpdatePFP, EditTaskManager, ManagerLoginForm, ManagerAddEmployee, ManagerAddTask
from datetime import datetime
from itsdangerous import URLSafeSerializer, SignatureExpired

app = Flask(__name__)
app.config["SECRET_KEY"] = "SECRET-KEY"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)
app.teardown_appcontext(close_db)
#email verification
server_sender = '122367736@umail.ucc.ie'
server_password = 'lhfsdslbcaftjzmq'
server = smtplib.SMTP('smtp.gmail.com', 587)
em = EmailMessage()

s = URLSafeSerializer('secreturlserialiser')
#upload pictures
upload_folder = 'static/pfp'
app.config['UPLOAD_FOLDER'] = upload_folder


'''
Hi Derek! I hope you are doing well. Here are the details for this website:
Manager Login - Username: derek, Password: db
You can make your own employee account but here is also mine
Username: evan, Password: lin

You can only add new managers by being a manager yourself 
You can assign tasks to employees as manager, change pfp, email, username, password.
You can add employees to your team and remove them

Users:
Users can receive assign task by manager
Send email, make their own task, edit task, delete task, complete task etc

'''

@app.before_request
def logged_in_user():
    g.user = session.get('user_id', None)  
    g.username = session.get('username', None)
    g.pfp = session.get('pfp', None)
    g.admin = session.get('admin', None)

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.url))
        return view(*args, **kwargs)
    return wrapped_view

@app.route('/')
def redirect_page():
    return redirect(url_for('login'))

@app.route('/login', methods=["GET","POST"])
def login():
    form = LoginForm()
    message = ''
    db = get_db()
    if form.validate_on_submit():
        username = form.username.data
        username = username.lower()
        password = form.password.data
        db = get_db()
        user_validate = db.execute("""SELECT * FROM users
                                WHERE username =?;""",(username,)).fetchone()
        if user_validate is None:
            form.username.errors.append("You have typed the wrong Username")
        elif not check_password_hash(user_validate["password"], password):
            form.password.errors.append("Incorrect Password")
        else:
            user_id = user_validate['user_id']
            username = user_validate['username']
            pfp = user_validate['pfp']
            session.clear()
            session["user_id"] = user_id
            session['username'] = username
            session['pfp'] = pfp
            next_page = request.args.get("next")
            if not next_page:
                next_page=url_for("home")
            return redirect(next_page)
    return render_template('login.html', form=form)

@app.route("/register", methods=["GET","POST"])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data 
        username = username.lower()
        password = form.password.data
        password2 = form.password2.data
        email = form.email.data
        email = email.lower()
        db = get_db()
        duplicate_username = db.execute("""SELECT * FROM users
                            WHERE username = ?""",(username,)).fetchone()
        if duplicate_username is not None:
            form.username.errors.append("Username already taken.")
        else:
            token = s.dumps(email, salt='email-confirm')
            em = EmailMessage()
            em['From'] = server_sender
            em['To'] = email
            em['Subject'] = 'Account Verification'
            link = url_for('verify_email', token=token, username=username, password = generate_password_hash(password), email=email, _external=True)
            body = 'Your link is {}'.format(link)
            em.set_content(body)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(server_sender, server_password)
                smtp.sendmail(server_sender, email, em.as_string())
                flash('Please go to your email to confirm your account registration')
            return redirect(url_for('login'))
    return render_template("register.html", form=form)

@app.route('/verify_email/<token>/<username>/<password>/<email>')
def verify_email(token,username,password,email):
    db = get_db()
    token = s.loads(token, salt='email-confirm', max_age=3600)
    db.execute("""INSERT INTO users (username, password, email, pfp, manager_id) VALUES (?, ?, ?, NULL, NULL);""",
                       (username, password, email))
    db.commit()
    flash('You can now sign in!!')
    return redirect(url_for('login'))

@app.route('/forgot_password', methods=["GET","POST"])
def forgot_password():
    message = ''
    form = ForgotForm()
    if form.validate_on_submit():
        email = form.email.data
        db = get_db()
        user = db.execute("""SELECT * FROM users
                            WHERE email = ?;""",(email,)).fetchone()
        if user is None:
            form.email.errors.append("Email is wrong")
            return render_template('forgot.html', form=form, message=message)
        else:
            token = s.dumps(email, salt='password-reset')
            em['From'] = server_sender
            em['To'] = email
            em['Subject'] = 'Password Reset'
            link = url_for('forgot_password_reset', token=token, email=email, _external=True)
            body = 'Reset password {}'.format(link)
            em.set_content(body)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(server_sender, server_password)
                smtp.sendmail(server_sender, email, em.as_string())
                flash('Please go to your email to reset your password')
        return redirect(url_for('login'))
    return render_template('forgot.html', form=form, message=message)

@app.route('/forgot_password_reset/<token>/<email>', methods=["GET","POST"])
def forgot_password_reset(token,email):
    form = ForgotPasswordReset()
    if form.validate_on_submit():
        password = form.password.data
        db = get_db()
        token = s.loads(token, salt='password-reset', max_age=3600)
        new_password = generate_password_hash(password)
        db.execute("""UPDATE users SET password =? WHERE email =?;""",(new_password, email))
        db.commit()
        flash('Password Reset Successful')
        return redirect(url_for('login'))
    return render_template('forgotreset.html', form=form)

@app.route("/manager_login", methods =["GET","POST"])
def manager_login():
    form = ManagerLoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        db = get_db()
        user_validate = db.execute("""SELECT * FROM manager
                                WHERE manager_name =?;""",(username,)).fetchone()
        if user_validate is None:
            form.username.errors.append("You have typed the wrong Username")
        elif user_validate["password"] != password:
            form.password.errors.append("Incorrect Password")
        else:
            user_id = user_validate['manager_id']
            admin = user_validate['admin']
            pfp = user_validate['pfp']
            session.clear()
            session["user_id"] = user_id
            session['username'] = username
            session['pfp'] = pfp
            session['admin'] = admin
            next_page = request.args.get("next")
            if not next_page:
                next_page=url_for("admin_home")
            return redirect(next_page)
    return render_template('manager_login.html',form=form)


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect( url_for("login") )

@app.route("/home")
@login_required
def home():
    db = get_db()
    profile = db.execute("""SELECT * FROM users WHERE user_id =?;""",(g.user,)).fetchone()
    return render_template("home_profile.html", profile=profile)

@app.route("/admin_home")
@login_required
def admin_home():
    db = get_db()
    adminprofile = db.execute("""SELECT * FROM manager WHERE manager_id =?;""",(g.user,)).fetchone()
    return render_template("admin_home_profile.html", adminprofile=adminprofile)

@app.route("/task_dashboard", methods=["GET","POST"])
@login_required
def task_dashboard():
    db = get_db()
    form = TaskManager()
    message = ''
    now = datetime.now().date()
    total_tasks = db.execute("""SELECT t.task_id, t.task_title, t.task_due_date, t.priority 
                            from users as u JOIN task_manager as t
                            ON u.user_id = t.task_user_id
                            WHERE t.task_user_id = ? AND t.status = ?
                            ORDER BY t.priority DESC;""",(g.user, 1)).fetchall()
    completed_tasks =  db.execute("""SELECT t.task_id, t.task_title, t.task_due_date, t.priority 
                            from users as u JOIN task_manager as t
                            ON u.user_id = t.task_user_id
                            WHERE t.task_user_id = ? AND status = ?
                            ORDER BY t.priority DESC;""",(g.user, 0)).fetchall()
    overdue_tasks = db.execute("""SELECT t.task_id, t.task_title, t.task_due_date, t.priority 
                            from users as u JOIN task_manager as t
                            ON u.user_id = t.task_user_id
                            WHERE t.task_due_date < ?
                            ORDER BY t.priority DESC;""",(now,)).fetchall()
    if form.validate_on_submit():
        task = form.task.data
        due_date = form.due_date.data
        priority = form.priority.data
        if due_date <= datetime.now().date():
            form.due_date.errors.append('Cannot insert past tasks')
        else:
            manager = db.execute("""SELECT * FROM users WHERE user_id=?;""",(g.user,)).fetchone()
            manager_id = manager['manager_id']
            db.execute("""INSERT INTO task_manager (task_user_id, task_title, task_due_date, priority, status, manager_id)
                            VALUES (?, ?, ?, ?, ?, ?);""",(g.user, task, due_date, priority, 1, manager_id))
            db.commit()
            return redirect(url_for('task_dashboard'))
    return render_template('task_dashboard.html',form=form, message=message, total_tasks=total_tasks, completed_tasks=completed_tasks, overdue_tasks=overdue_tasks)

@app.route('/complete_task/<int:task_id>')
@login_required
def complete_task(task_id):
    db = get_db()
    complete_task = db.execute("""UPDATE task_manager
                                SET status = ?
                                WHERE task_id = ?;""", (0, task_id))
    db.commit()
    return redirect(url_for('task_dashboard'))

@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    db = get_db()
    db.execute("""DELETE FROM task_manager
                    WHERE task_id = ?;""", (task_id,))
    db.commit()
    return redirect(url_for('task_dashboard'))

@app.route('/edit_task/<int:task_id>', methods=["GET","POST"])
@login_required
def edit_task(task_id):
    form = EditTaskManager()
    db = get_db()
    original_task = db.execute("""SELECT * FROM task_manager WHERE task_id = ?;""",(task_id,)).fetchone()
    form.task.data = original_task['task_title']
    form.due_date.data = datetime.strptime(original_task['task_due_date'], '%Y-%m-%d').date()
    form.priority.data = original_task['priority']
    if form.validate_on_submit():
        task1 = form.task1.data
        due_date1 = form.due_date1.data
        priority1 = form.priority1.data
        if due_date1 < datetime.now().date():
            form.due_date1.errors.append('Cannot insert past tasks')
        else:
            db.execute("""UPDATE task_manager
                        SET task_title = ?, task_due_date = ?, priority = ?
                        WHERE task_id = ? AND task_user_id =?;""",(task1, due_date1, priority1, task_id,g.user))
            db.commit()
            return redirect(url_for('task_dashboard'))
    return render_template('edit_task.html', form=form, task=form.task.data, due_date=form.due_date.data, priority=form.priority.data)


@app.route("/assign_task", methods=["GET","POST"])
@login_required
def assign_task():
    db = get_db()
    form = ManagerAddTask()
    message = ''
    now = datetime.now().date()
    assigned_tasks = db.execute("""SELECT * 
                            from users as u JOIN task_manager as t
                            ON u.user_id = t.task_user_id
                            WHERE t.manager_id =? AND status =?
                            ORDER BY t.priority DESC;""",(g.user, 1)).fetchall()
    overdue_tasks = db.execute("""SELECT t.task_id, t.task_title, t.task_due_date, t.priority 
                            from users as u JOIN task_manager as t
                            ON u.user_id = t.task_user_id
                            WHERE t.task_due_date < ?
                            ORDER BY t.priority DESC;""",(now,)).fetchall()
    if form.validate_on_submit():
        name = form.name.data
        task = form.task.data
        due_date = form.due_date.data
        priority = form.priority.data
        user_validate = db.execute("""SELECT * FROM users
                                WHERE username =?;""",(name,)).fetchone()
        if user_validate is None:
            form.name.errors.append("You have typed the wrong Username")
        elif user_validate['manager_id'] != g.user:
            form.name.errors.append('You are not in charge of this employee')
        elif due_date <= datetime.now().date():
            form.due_date.errors.append('Cannot insert past tasks')
        else:
            db.execute("""INSERT INTO task_manager (task_user_id, task_title, task_due_date, priority, status, manager_id)
                            VALUES (?, ?, ?, ?, ?, ?)""",(int(user_validate['user_id']), task, due_date, priority, 1, g.user))
            db.commit()
            return redirect(url_for('assign_task'))
    return render_template('admin_assign_task.html',form=form, message=message, assigned_tasks=assigned_tasks, overdue_tasks=overdue_tasks)

@app.route('/manager_delete_task/<int:task_id>')
@login_required
def manager_delete_task(task_id):
    db = get_db()
    db.execute("""DELETE FROM task_manager
                    WHERE task_id = ?;""", (task_id,))
    db.commit()
    return redirect(url_for('assign_task'))

@app.route("/admin_tab", methods=["GET","POST"])
@login_required
def admin_tab():
    db = get_db()
    form = ManagerAddEmployee()
    message=''
    g.user = int(g.user)
    total_users = db.execute("""SELECT * FROM users WHERE manager_id = ?""",(g.user,)).fetchall()
    not_my_users = db.execute("""SELECT * FROM users WHERE manager_id IS NULL""").fetchall()
    if form.validate_on_submit():
        name = form.name.data
        user_validate = db.execute("""SELECT * FROM users
                                WHERE username =?;""",(name,)).fetchone()
        if user_validate is None:
            form.name.errors.append("This Employee does not exist")
        else:
            db.execute("""UPDATE users
                        SET manager_id =?
                        WHERE user_id =?""",(g.user,user_validate['user_id']))
            db.commit()
            message = 'Successfully Added'
            return render_template('admin_tab.html',form=form, message=message, total_users=total_users, not_my_users=not_my_users)
    return render_template('admin_tab.html',form=form, message=message, total_users=total_users, not_my_users=not_my_users)

@app.route('/add_employee/<int:user_id>')
@login_required
def add_employee(user_id):
    db = get_db()
    db.execute("""UPDATE users
                SET manager_id = ?
                WHERE user_id = ?;""", (g.user, user_id))
    db.commit()
    return redirect(url_for('admin_tab'))

@app.route('/remove_employee/<int:user_id>')
@login_required
def remove_employee(user_id):
    db = get_db()
    db.execute("""UPDATE users
                SET manager_id = NULL
                WHERE user_id = ?;""", (user_id,))
    db.commit()
    return redirect(url_for('admin_tab'))

@app.route('/send_mail', methods=['GET','POST'])
@login_required
def send_mail():
    form = SendMail()
    if form.validate_on_submit():
        email = form.email.data
        email = email.lower()
        title = form.title.data
        body = form.body.data
        db = get_db()
        user_email = db.execute("""SELECT * FROM users WHERE user_id =?;""",(g.user,)).fetchone()
        user_email = user_email['email']
        sender_email = db.execute("""SELECT * FROM users WHERE email =?;""",(email,)).fetchone()
        if sender_email is None:
            flash("Couldn't find this user's email")
        else:
    
            em = EmailMessage()
            em['From'] = server_sender
            em['To'] = email
            title = str(title)
            em['Subject'] = title
            em.set_content(body)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(server_sender, server_password)
                smtp.sendmail(server_sender, email, em.as_string())
                flash('Email sent!')
        return redirect(url_for('send_mail'))
    return render_template('send_email.html', form=form)

@app.route('/admin_send_mail', methods=['GET','POST'])
@login_required
def admin_send_mail():
    form = SendMail()
    if form.validate_on_submit():
        email = form.email.data
        email = email.lower()
        title = form.title.data
        body = form.body.data
        db = get_db()
        sender_email = db.execute("""SELECT * FROM manager WHERE email =?;""",(email,)).fetchone()
        if sender_email is None:
            flash("Couldn't find this user's email")
        else:
    
            em = EmailMessage()
            em['From'] = server_sender
            em['To'] = email
            title = str(title)
            em['Subject'] = title
            em.set_content(body)
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL('smtp.gmail.com', 465, context=context) as smtp:
                smtp.login(server_sender, server_password)
                smtp.sendmail(server_sender, email, em.as_string())
                flash('Email sent!')
        return redirect(url_for('admin_send_mail'))
    return render_template('send_admin_mail.html', form=form)


@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/admin_settings')
@login_required
def admin_settings():
    return render_template('admin_settings.html')

@app.route('/reset_password', methods = ["GET","POST"])
@login_required
def reset_password():
    form = ResetPassword()
    message = ''
    if form.validate_on_submit():
        password = form.password.data
        new_password = form.new_password.data
        new_password2 = form.new_password2.data
        db = get_db()
        user_validate = db.execute("""SELECT * FROM users
                                WHERE user_id =?;""",(g.user,)).fetchone()
        if not check_password_hash(user_validate["password"], password):
            form.password.errors.append("Wrong Password")
        else:
            db.execute("""UPDATE users
                        SET password = ?
                        WHERE user_id = ?;""",(generate_password_hash(new_password), user_validate['user_id']))
            db.commit()
            flash('Password has been changed.')
            return redirect(url_for('settings'))
    return render_template('reset_password.html', form=form, message=message)



@app.route('/reset_email', methods = ["GET","POST"])
@login_required
def reset_email():
    form = ResetEmail()
    message = ''
    db = get_db()
    if form.validate_on_submit():
        email = form.email.data
        email = email.lower()
        new_email = form.new_email.data
        new_email = new_email.lower()
        clashing_emails =  db.execute("""SELECT * FROM users
                                WHERE email =?;""",(new_email,)).fetchone()
        user_validate = db.execute("""SELECT * FROM users
                                WHERE user_id =?;""",(g.user,)).fetchone()
        if email != user_validate['email']:
            form.email.errors.append("Wrong Email")
        if clashing_emails:
            form.new_email.errors.append("This Email has already been taken")
        else:
            db.execute("""UPDATE users
                        SET email = ?
                        WHERE user_id = ?;""",(new_email, g.user))
            db.commit()
            flash('Email has been updated')
            return redirect(url_for('settings'))
    return render_template('reset_email.html', form=form, message=message)


@app.route('/reset_username', methods = ["GET","POST"])
@login_required
def reset_username():
    form = ResetUsername()
    message = ''
    db = get_db()
    if form.validate_on_submit():
        username = form.username.data
        username = username.lower()
        new_username = form.new_username.data
        new_username = new_username.lower()
        clashing_usernames =  db.execute("""SELECT * FROM users
                                WHERE username =?;""",(new_username,)).fetchone()
        user_validate = db.execute("""SELECT * FROM users
                                WHERE user_id =?;""",(g.user,)).fetchone()
        if username != user_validate['username']:
            form.username.errors.append("Wrong Username")
        elif clashing_usernames is not None:
            form.new_username.errors.append("This Username has already been taken")
        else:
            db.execute("""UPDATE users
                        SET username = ?
                        WHERE user_id = ?;""",(new_username, g.user))
            db.commit()
            session['username'] = new_username
            flash('Username Changed Successfully')
            return redirect(url_for('settings'))
    return render_template('reset_username.html', form=form, message=message)

@app.route('/admin_reset_password', methods = ["GET","POST"])
@login_required
def admin_reset_password():
    form = ResetPassword()
    message = ''
    if form.validate_on_submit():
        password = form.password.data
        new_password = form.new_password.data
        new_password2 = form.new_password2.data
        db = get_db()
        user_validate = db.execute("""SELECT * FROM manager
                                WHERE manager_id =?;""",(g.user,)).fetchone()
        if not user_validate["password"]:
            form.password.errors.append("Wrong Password")
        else:
            db.execute("""UPDATE manager
                        SET password = ?
                        WHERE manager_id = ?;""",(new_password, user_validate['manager_id']))
            db.commit()
            flash('Admin password has been changed.')
            return redirect(url_for('admin_settings'))
    return render_template('admin_reset_password.html', form=form, message=message)

@app.route('/admin_reset_email', methods = ["GET","POST"])
@login_required
def admin_reset_email():
    form = ResetEmail()
    message = ''
    db = get_db()
    if form.validate_on_submit():
        email = form.email.data
        email = email.lower()
        new_email = form.new_email.data
        new_email = new_email.lower()
        clashing_emails =  db.execute("""SELECT * FROM manager
                                WHERE email =?;""",(new_email,)).fetchone()
        user_validate = db.execute("""SELECT * FROM manager
                                WHERE manager_id =?;""",(g.user,)).fetchone()
        if email != user_validate['email']:
            form.email.errors.append("Wrong Email")
        if clashing_emails:
            form.new_email.errors.append("This Email has already been taken")
        else:
            db.execute("""UPDATE manager
                        SET email = ?
                        WHERE manager_id = ?;""",(new_email, g.user))
            db.commit()
            flash('Email has been updated')
            return redirect(url_for('admin_settings'))
    return render_template('admin_reset_email.html', form=form, message=message)

@app.route('/admin_reset_username', methods = ["GET","POST"])
@login_required
def admin_reset_username():
    form = ResetUsername()
    message = ''
    db = get_db()
    if form.validate_on_submit():
        username = form.username.data
        username = username.lower()
        new_username = form.new_username.data
        new_username = new_username.lower()
        clashing_usernames =  db.execute("""SELECT * FROM manager
                                WHERE manager_name =?;""",(new_username,)).fetchone()
        user_validate = db.execute("""SELECT * FROM manager
                                WHERE manager_id =?;""",(g.user,)).fetchone()
        if username != user_validate['manager_name']:
            form.username.errors.append("Wrong Username")
        elif clashing_usernames is not None:
            form.new_username.errors.append("This Username has already been taken")
        else:
            db.execute("""UPDATE manager
                        SET manager_name = ?
                        WHERE manager_id = ?;""",(new_username, g.user))
            db.commit()
            session['username'] = new_username
            flash('Username Changed Successfully')
            return redirect(url_for('admin_settings'))
    return render_template('admin_reset_username.html', form=form, message=message)

@app.route('/update_pfp', methods = ["GET","POST"])
@login_required
def update_pfp():
    form = UpdatePFP()
    db = get_db()
    if form.validate_on_submit():
        file = form.data['pfp']
        filename = secure_filename(file.filename)
        unique_pfp = str(uuid.uuid1()) + '_' + filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_pfp))     #gotten this code from Codemy Flask blog tutorial #49 at 11:05
        existing_file = db.execute("""SELECT *
                                    FROM users
                                    WHERE user_id = ?;""",(g.user,)).fetchone()
        try:
            if existing_file['pfp'] is not None:
                path = 'static/pfp/'+ existing_file['pfp']
                os.remove(path)
                db.execute("""UPDATE users
                            SET pfp = ?
                            WHERE user_id = ?;""",(unique_pfp,g.user))
                session['pfp'] = unique_pfp 
                db.commit()
            else:
                db.execute("""UPDATE users
                            SET pfp = ?
                            WHERE user_id = ?;""",(unique_pfp,g.user))
                new_pfp = db.execute("""SELECT *
                                        FROM users
                                        WHERE user_id = ?;""",(g.user,)).fetchone()
                db.commit()
                session['pfp'] = new_pfp['pfp']
        except:
            flash('Error, could not upload pfp')
        return redirect(url_for('home'))
    return render_template('upload_pfp.html', form=form)

@app.route('/admin_update_pfp', methods = ["GET","POST"])
@login_required
def admin_update_pfp():
    form = UpdatePFP()
    db = get_db()
    if form.validate_on_submit():
        file = form.data['pfp']
        filename = secure_filename(file.filename)
        unique_pfp = str(uuid.uuid1()) + '_' + filename
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], unique_pfp))              #gotten this code from Codemy Flask blog tutorial #49 at 11:05
        existing_file = db.execute("""SELECT *
                                    FROM manager
                                    WHERE manager_id = ?;""",(g.user,)).fetchone()
        try:
            if existing_file['pfp'] is not None:
                path = 'static/pfp/'+ existing_file['pfp']
                os.remove(path)
                db.execute("""UPDATE manager
                            SET pfp = ?
                            WHERE manager_id = ?;""",(unique_pfp,g.user))
                session['pfp'] = unique_pfp 
                db.commit()
            else:
                db.execute("""UPDATE manager
                            SET pfp = ?
                            WHERE manager_id = ?;""",(unique_pfp,g.user))
                new_pfp = db.execute("""SELECT *
                                        FROM manager
                                        WHERE manager_id = ?;""",(g.user,)).fetchone()
                db.commit()
                session['pfp'] =  new_pfp['pfp']
        except:
            flash('Error, could not upload pfp')
        return redirect(url_for('admin_home'))
    return render_template('admin_upload_pfp.html', form=form)

@app.route('/add_admin', methods=["GET","POST"])
@login_required
def register_admin():
    form = AddAdmin()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data
        db = get_db()
        duplicate_username = db.execute("""SELECT * FROM manager
                            WHERE manager_name = ?;""",(username,)).fetchone()
        if duplicate_username is not None:
            form.username.errors.append("Username already taken.")
        else:
            db.execute("""INSERT INTO manager (manager_name, password, email, pfp, admin) VALUES (?, ?, ?, NULL, ?);""",
                       (username, password, email, 'admin'))
            db.commit()
            flash('Admin Added')
        return redirect(url_for('admin_settings'))
    return render_template("register_admin.html", form=form)




