#!/usr/bin/env python
from main import *
from basehandler import *
import re
TEACHER_AUTH_CODE = "teacher1"


def signupError(self, error):
  vals={'error':error}
  vals.update(self.request.POST.items())
  self.render_template('public/signup.html', vals)





################################################################################
# Class:  Signup
#   - Creates new user
#   - Creates / rejects Instructor users based on
#     the predefined TEACHER_AUTH_CODE
################################################################################
class SignupHandler(BaseHandler):
#  def send_approved_mail(self, sender_address, to_address, name):
#    mail.send_mail(sender = sender_address,
#                   to = to_address,
#                   subject = "Your account has been approved",
#                   body = """Dear %s:
#                   Your email account has been approved now you can sign in and
#                   user your new MathQuizzes account to the fullest. """ % name)

  def get(self):
     self.render_template('public/signup.html')

  def post(self):
    user_name = self.request.get('username')
    email = self.request.get('email')
    name = self.request.get('name')
    password = self.request.get('password')
    last_name = self.request.get('lastname')
    teacherRequest = self.request.get('isteacher')
    teacherbool = False

    if teacherRequest:
       teachercode = self.request.get('teachercode')
       if teachercode != TEACHER_AUTH_CODE:
         signupError(self,'Authorization Error!')
         return
       teacherbool = True

    if len(password) < 6:
      signupError(self, 'Password length must be at least 6 characters.')
      return

    if len(password) >= 12:
      signupError(self, 'Password length cannot be more than 12 characters.')
      return

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
      signupError(self, 'Email is not a valid email format')
      return


    unique_properties = ['email_address']
    user_data = self.user_model.create_user(
      user_name,
      unique_properties,
      email_address=email,
      name=name,
      password_raw=password,
      last_name=last_name,
      verified=False,
      isTeacher=teacherbool,
    )

    if not user_data[0]: #user_data is a tuple
      signupError(self, 'Email associated with another account.')
      return

    user = user_data[1]
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='v', user_id=user_id,
      signup_token=token, _full=True)

#    self.send_approved_mail('{}@appspot.gserviceaccount.com'.format(
#        app_identity.get_application_id()), email, name)

    msg = 'Account Created!'
    #    self.display_message(msg.format(url=verification_url))
    self.redirect(self.uri_for('home'))
