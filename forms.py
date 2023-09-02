from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, DateField, SelectField, EmailField
from wtforms.validators import InputRequired, EqualTo

class RegistrationForm(FlaskForm):
    username = StringField('Username: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter an username"})
    password = PasswordField('Password: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter a password"})
    password2 = PasswordField('Confirm Password: ', validators=[InputRequired(), EqualTo('password')])
    email = EmailField('Email: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your email"})
    submit = SubmitField("Register")

class EmailVerification(FlaskForm):
    verify = StringField('Verification code: ', validators=[InputRequired()], render_kw={"placeholder": "Please verify your email"})
    submit = SubmitField("Verify")


class LoginForm(FlaskForm):
    username = StringField('Username ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your username"})
    password = PasswordField('Password ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your password"})
    submit = SubmitField("Login")

class ForgotForm(FlaskForm):
    email = EmailField('Email Address', validators=[InputRequired()], render_kw={"placeholder": "Please enter"})
    submit = SubmitField("Send Email")

class ForgotPasswordReset(FlaskForm):
    password = PasswordField('Password ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your new password"})
    password2 = PasswordField('Confirm Password ', validators=[InputRequired()], render_kw={"placeholder": "Please confirm your new password"})
    submit = SubmitField("Submit")

class ManagerLoginForm(FlaskForm):
    username = StringField('Username: ', validators=[InputRequired()], render_kw={"placeholder": "Please your username"})
    password = PasswordField('Password: ', validators=[InputRequired(), EqualTo('password')], render_kw={"placeholder": "Please your password"})
    submit = SubmitField("Login")

class TaskManager(FlaskForm):
    task = StringField('Task', validators=[InputRequired()], render_kw={"placeholder": "Title"})
    due_date = DateField('Due Date', validators=[InputRequired()], render_kw={"placeholder": "Due Date"})
    priority = SelectField('Priority',choices= ['1','2','3','4','5','6','7','8','9','10'], validators=[InputRequired()])
    save = SubmitField('Add')

class ManagerAddEmployee(FlaskForm):
    name = StringField('Name', validators=[InputRequired()], render_kw={"placeholder": "Title"})
    submit = SubmitField('Add')

class ManagerAddTask(FlaskForm):
    name = StringField('Employee Name', validators=[InputRequired()], render_kw={"placeholder": "Name"})
    task = StringField('Task', validators=[InputRequired()], render_kw={"placeholder": "Title"})
    due_date = DateField('Due Date', validators=[InputRequired()], render_kw={"placeholder": "Due Date"})
    priority = SelectField('Priority',choices= ['1','2','3','4','5','6','7','8','9','10'], validators=[InputRequired()])
    save = SubmitField('Add')

class ResetPassword(FlaskForm):
    password = StringField('Password: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your original password"})
    new_password = PasswordField('New Password: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your new password"})
    new_password2 = PasswordField('Confirm New Password: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your confirm new password"})
    save = SubmitField('Save')

class ResetUsername(FlaskForm):
    username = StringField('Current Username: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your original username"})
    new_username = StringField('New Username: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your new username"})
    save = SubmitField('Save')

class ResetEmail(FlaskForm):
    email = EmailField('Current Email: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your original email"})
    new_email = EmailField('New Email: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your new email"})
    confirm_new_email = EmailField('Confirm Email: ', validators=[InputRequired()], render_kw={"placeholder": "Please confirm your email"})
    save = SubmitField('Save')

class UpdatePFP(FlaskForm):
    pfp = FileField('Add Profile Picture', validators=[FileAllowed(['jpg','png'])])
    save = SubmitField('Add New PFP')

class EditTaskManager(FlaskForm):
    task = StringField('New Task', render_kw={"placeholder": "Title"})
    due_date = DateField('Due Date', render_kw={"placeholder": "Due Date"})
    priority = SelectField('Priority',choices= ['1','2','3','4','5','6','7','8','9','10'], validators=[InputRequired()])

    task1 = StringField('New Task', validators=[InputRequired()], render_kw={"placeholder": "Title"})
    due_date1 = DateField('New Due Date', validators=[InputRequired()], render_kw={"placeholder": "Due Date"})
    priority1 = SelectField('New Priority',choices= ['1','2','3','4','5','6','7','8','9','10'], validators=[InputRequired()])
    save = SubmitField('Save')

class SendMail(FlaskForm):
    email = EmailField('Email: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter recipients email"})
    title = StringField('Title: ', validators=[InputRequired()], render_kw={"placeholder": "Title"})
    body = StringField('Message: ', validators=[InputRequired()])
    send = SubmitField('Send Email')

class AddAdmin(FlaskForm):
    username = StringField('Username: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter an username"})
    password = PasswordField('Password: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter a password"})
    password2 = PasswordField('Confirm Password: ', validators=[InputRequired(), EqualTo('password')])
    email = EmailField('Email: ', validators=[InputRequired()], render_kw={"placeholder": "Please enter your email"})
    submit = SubmitField("Register New Admin")




