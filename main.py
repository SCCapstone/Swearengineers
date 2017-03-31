
#!/usr/bin/env python
#=======
#Signatures:
#Matthew
#John
#Jory
#James
#Nathaniel Polly

# [START imports]

from google.appengine.ext.webapp import template
from google.appengine.ext import ndb
from google.appengine.api import app_identity
from google.appengine.api import mail
from google.appengine.api import users
from collections import defaultdict

from sympy import *
from sympy.parsing.sympy_parser import parse_expr

import logging
import os.path
import webapp2
import urllib
import time
import datetime
import json
import re


from webapp2_extras import auth
from webapp2_extras import sessions


from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError


DEFAULT_USER = "test@email.sc.edu"

class Author(ndb.Model):
    """Sub model for representing an author."""
    identity = ndb.StringProperty(indexed=False)
    email = ndb.StringProperty(indexed=True)

class Problem(ndb.Model):
    quiz = ndb.StringProperty(indexed=True)
    author = ndb.StructuredProperty(Author)
    content = ndb.StringProperty(indexed=False)
    answer = ndb.StringProperty(indexed=False)
    tags = ndb.StringProperty(indexed=False)
    difficulty = ndb.StringProperty(indexed=False)
    date = ndb.DateTimeProperty(auto_now_add=True)

def get_entity(prob_key):
    problem = prob_key.get()
    return problem

def deleteEntity(problem):
    problem.key.delete()

def updateEntity(key):
    problem = key.get()
    problem.content = 'omgitworked'
    problem.put()

class Quiz(ndb.Model):
    author = ndb.StructuredProperty(Author)
    name = ndb.StringProperty(indexed=True)
    content = ndb.StringProperty(indexed=False)
    date = ndb.DateTimeProperty(auto_now_add=True)
    jgrades = ndb.JsonProperty(default=[])

class Course(ndb.Model):
    teacher = ndb.StructuredProperty(Author)
    courseName = ndb.StringProperty(indexed=True)
    student = ndb.StructuredProperty(Author, repeated=True)
    quizzes = ndb.StructuredProperty(Quiz, repeated=True)
    dateCreated = ndb.DateTimeProperty(auto_now_add=True)

class coursesActive(ndb.Model):
	course = ndb.StructuredProperty(Course)
	student = ndb.StructuredProperty(Author)
	dateAdded = ndb.DateTimeProperty(auto_now_add=True)

class Grades(ndb.Model):
    author = ndb.StructuredProperty(Author)
    value = ndb.FloatProperty(indexed=False)
    stringgrade = ndb.StringProperty(indexed=False)
    quiz = ndb.StringProperty(indexed=False)
    date = ndb.DateTimeProperty(auto_now_add=True)
    pag = ndb.JsonProperty()

def user_key(user=DEFAULT_USER):
    """Constructs a Datastore key for a User entity.

    We use guestbook_name as the key.
    """
    return ndb.Key('User', user)

def user_required(handler):
  """
    Decorator that checks if there's a user associated with the current session.
    Will also fail if there's no session present.
  """
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)

  return check_login

class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
     """Shortcut to access the auth instance as a property."""
     return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    """Shortcut to access a subset of the user attributes that are stored
    in the session.


    The list of attributes to store in the session is specified in
      config['webapp2_extras.auth']['user_attributes'].
    :returns
      A dictionary with most user information
    """
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    """Shortcut to access the current logged in user.

    Unlike user_info, it fetches information from the persistence layer and
    returns an instance of the underlying model.

    :returns
      The instance of the user model associated to the logged in user.
    """
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    """Returns the implementation of the user model.

    It is consistent with config['webapp2_extras.auth']['user_model'], if set.
    """
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      """Shortcut to access the current session."""
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params=None):
    if not params:
      params = {}
    user = self.user_info
    params['user'] = user
    path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
    self.response.out.write(template.render(path, params))

  def display_message(self, message):
    """Utility function to display a template with a simple message."""
    params = {
      'message': message
    }
    self.render_template('message.html', params)

  # this is needed for webapp2 sessions to work
  def dispatch(self):
      # Get a session store for this request.
      self.session_store = sessions.get_store(request=self.request)

      try:
          # Dispatch the request.
          webapp2.RequestHandler.dispatch(self)
      finally:
          # Save all sessions.
          self.session_store.save_sessions(self.response)

# no longer using this
#class MainHandler(BaseHandler):
#  def get(self):
#     self.render_template('main.html')

class SignupHandler(BaseHandler):

  def send_approved_mail(self, sender_address, to_address, name):
    mail.send_mail(sender = sender_address,
                   to = to_address,
                   subject = "Your account has been approved",
                   body = """Dear %s:
                   Your email account has been approved now you can sign in and
                   user your new MathQuizzes account to the fullest. """ % name)

    #Customize ot USER
  def get(self):
     self.render_template('signup.html')

  def post(self):
    user_name = self.request.get('username')
    email = self.request.get('email')
    name = self.request.get('name')
    password = self.request.get('password')
    last_name = self.request.get('lastName')

    if len(password) < 6:
      self.display_message('Password Length must be at least 6 \
        characters')
      return

    if len(password) >= 12:
      self.display_message('Password Length cannot be more than \
        12 characters')
      return

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        self.display_message('Email is not a valid email format')
        return


    unique_properties = ['email_address']
    user_data = self.user_model.create_user(user_name,
      unique_properties,
      email_address=email, name=name, password_raw=password,
      last_name=last_name, verified=False)

    if not user_data[0]: #user_data is a tuple
      self.display_message('Unable to create user for email %s because of \
        duplicate keys %s' % (user_name, user_data[1]))
      return

    user = user_data[1]
    user_id = user.get_id()

    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='v', user_id=user_id,
      signup_token=token, _full=True)

    self.send_approved_mail('{}@appspot.gserviceaccount.com'.format(
        app_identity.get_application_id()), email, name)

    msg = 'Account Created!'
#    self.display_message(msg.format(url=verification_url))

    self.redirect(self.uri_for('home'))

class ForgotPasswordHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')

    user = self.user_model.get_by_auth_id(username)
    if not user:
      logging.info('Could not find any user entry for username %s', username)
      self._serve_page(not_found=True)
      return

    user_id = user.get_id()
    token = self.user_model.create_signup_token(user_id)

    verification_url = self.uri_for('verification', type='p', user_id=user_id,
      signup_token=token, _full=True)

    msg = 'Send an email to user in order to reset their password. \
          They will be able to do so by visiting'

    self.display_message(msg.format(url=verification_url))

  def _serve_page(self, not_found=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'not_found': not_found
    }
    self.render_template('forgot.html', params)


class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    # it should be something more concise like
    # self.auth.get_user_by_token(user_id, signup_token)
    # unfortunately the auth interface does not (yet) allow to manipulate
    # signup tokens concisely
    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token,
      'signup')

    if not user:
      logging.info('Could not find any user with id "%s" signup token "%s"',
        user_id, signup_token)
      self.abort(404)

    # store user data in the session
    self.auth.set_session(self.auth.store.user_to_dict(user), remember=True)

    if verification_type == 'v':
      # remove signup token, we don't want users to come back with an old link
      self.user_model.delete_signup_token(user.get_id(), signup_token)

      if not user.verified:
        user.verified = True
        user.put()

      self.display_message('User email address has been verified.')
      return
    elif verification_type == 'p':
      # supply user to the page
      params = {
        'user': user,
        'token': signup_token
      }
      self.render_template('resetpassword.html', params)
    else:
      logging.info('verification type not supported')
      self.abort(404)

class SetPasswordHandler(BaseHandler):

  @user_required
  def post(self):
    password = self.request.get('password')
    old_token = self.request.get('t')

    if not password or password != self.request.get('confirm_password'):
      self.display_message('passwords do not match')
      return

    user = self.user
    user.set_password(password)
    user.put()

    # remove signup token, we don't want users to come back with an old link
    self.user_model.delete_signup_token(user.get_id(), old_token)

    self.display_message('Password updated')

class LoginHandler(BaseHandler):
  def get(self):
    self._serve_page()

  def post(self):
    username = self.request.get('username')
    password = self.request.get('password')
    try:
      u = self.auth.get_user_by_password(username, password, remember=True,
        save_session=True)
      self.redirect(self.uri_for('home'))
    except (InvalidAuthIdError, InvalidPasswordError) as e:
      logging.info('Login failed for user %s because of %s', username, type(e))
      self._serve_page(True)

  def _serve_page(self, failed=False):
    username = self.request.get('username')
    params = {
      'username': username,
      'failed': failed
    }
    self.render_template('login.html', params)

class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('login'))

class AuthenticatedHandler(BaseHandler):
   @user_required
   def get(self):
     self.render_template('home.html')

class MainHandler(BaseHandler, webapp2.RequestHandler):
   @user_required
   def get(self):
     user = self.user
     grades = getMyGradeList(self)
     template_values = {'grades': grades }
     self.render_template('home.html', template_values)


class helpHandler(BaseHandler):
   @user_required
   def get(self):
     user = self.user
     template_values = {'email': user.email_address}
     self.render_template('inHelp.html', template_values)


###########################################################
# Creation
###########################################################
class inProblemHandler(BaseHandler, webapp2.RequestHandler):
   @user_required
   def get(self):
        quizzes = getMyQuizList(self)
        user = self.user
        course_query = Course.query(ancestor=user_key(user.email_address)).order(-Course.dateCreated)
        courses = course_query.fetch()
        self.render_template('inProblem.html', {'quizzes': quizzes, 'courses': courses} )

   def post(self):
     user = self.user
     problem_key = self.request.get('problem_key')

     # a test for editing a problem
     if not problem_key:
        problem = Problem(parent=user_key(user.email_address))
        problem.author = Author(
                 identity=user.name,
                 email=user.email_address)
     else:
        prob_key = ndb.Key(urlsafe=self.request.get('problem_key'))
        problem = prob_key.get()

     # a test for adding a new quiz
     problem.quiz = self.request.get('quiz_name')
     if not problem.quiz:
       self.display_message('Make sure to select a quiz from the dropdown first!')
       return
     qq = Quiz.query().order(-Quiz.date)
     qq = qq.filter(Quiz.name == problem.quiz)
     test = qq.get()
     if test is None:
     	#self.display_message(self.request.get('course_key_'))
     	course_key = ndb.Key(urlsafe=self.request.get('course_key_'))
     	course = course_key.get()
        quiz = Quiz(parent=user_key(user.email_address))
        quiz.author = Author(
                  identity=user.name,
                  email=user.email_address)
        quiz.name = problem.quiz
        quiz.put()
        course.quizzes.append(quiz)
        course.put()

     problem.content = self.request.get('problem')
     problem.tags = self.request.get('tags')
     problem.answer = self.request.get('answer')
     problem.difficulty = self.request.get('difficulty')
     if not problem.content or not problem.tags or not problem.answer or not problem.quiz:
       self.display_message('Please fill out all parts of the form')
       return
     problem.put()
     time.sleep(.1)
     self.render_template('inProblem.html',{'selectdefault': problem.quiz, 'success': '1' })


class inCreateCourseHandler(BaseHandler, webapp2.RequestHandler):
   @user_required
   def get(self):
     self.render_template('inCreateCourse.html')

   def post(self):
     user = self.user
     course = Course(parent=user_key(user.email_address))
     course.teacher = Author(
                 identity=user.name,
                 email=user.email_address)
     course.courseName = self.request.get('courseName')
     course.put()
     self.redirect(self.uri_for('inCreateCourse'))


###########################################################
# My Things
###########################################################

class inMyProblemsHandler(BaseHandler):
   @user_required
   def get(self):
     user = self.user
     problem_query = Problem.query(ancestor=user_key(user.email_address)).order(-Problem.date)
#          ancestor=user_key(user.email_address)).order(-Problem.date)
     problems = problem_query.fetch()
     quizzes = getMyQuizList(self)
     template_values = {'problems': problems, 'quizzes': quizzes }
     self.render_template('inMyProblems.html', template_values)

   def post(self):
     quiz = self.request.get('quiz')
     quizzes = getQuizList()
     problem_query = Problem.query().filter(Problem.quiz == quiz)
     problems = problem_query.fetch()
     template_values = { 'problems': problems, 'selectdefault': quiz,
             'quizzes': quizzes}
     self.render_template('inMyProblems.html', template_values)

class inMyQuizzesHandler(BaseHandler):
   @user_required
   def get(self):
        user = self.user
        quizzes = getMyQuizList(self)
        template_values = {'quizzes': quizzes }
        self.render_template('inMyQuizzes.html', template_values)

class inMyCoursesHandler(BaseHandler):
   @user_required
   def get(self):
        user = self.user
        course_query = Course.query()
        courses = course_query.fetch()
        #mycourse_query = Course.query(Course.student.email == user.email_address)
        mycourses = []

        for x in courses:
        	#self.display_message("                           fdsafa              test")
        	for student in x.student:
        		#self.display_message("                    fasd      test2")
        		if(student.email == user.email_address):
        			#self.display_message("                    dfasf                     adding")
        			mycourses.append(x)
        
        courses_owned_query = Course.query(ancestor=user_key(user.email_address)).order(-Course.dateCreated)
        courses_owned = courses_owned_query.fetch()

        #for y in courses_owned:
        #	numQuizzes = len(y.quizzes)
        #	self.display_message(y.courseName)
        #	self.display_message(numQuizzes)
       # if not courses_owned:


        template_values = {'mycourses': mycourses,
        					'courses': courses,
        					'courses_owned': courses_owned }
        self.render_template('inMyCourses.html', template_values)

class inMyGradesHandler(BaseHandler):
   @user_required
   def get(self):
     user = self.user
     grade_query = Grades.query(ancestor=user_key(user.email_address)).order(-Grade.date)
     grades = grade_query.fetch()
     template_values = {'grades': grades}
     self.render_template('inMyGrades.html', template_values)

###########################################################
# Actions (Taking Quiz/Grading)
###########################################################
class inQuizzesHandler(BaseHandler, webapp2.RequestHandler):
   @user_required
   def get(self):
      if self.request.get('grade') is not '':
         grade = ndb.Key(urlsafe=self.request.get('grade'))
         grade = grade.get()
         sd=grade.quiz
         self.render_template('inQuizzes.html', {'grade': grade, 'selectdefault': sd })
      elif self.request.get('quiz_name') is not None:
         quiz_name = self.request.get('quiz_name')
         quizzes = getQuizList()
         problem_query = Problem.query().filter(Problem.quiz == quiz_name)
         problems = problem_query.fetch()
         template_values = {
                 'problems': problems,
                 'quizzes': quizzes,
                 'selectdefault': quiz_name}
         self.render_template('inQuizzes.html', template_values)
      elif self.request.get('quiz_name') is None:
         quizzes = getQuizList()
         template_values = {'quizzes': quizzes}
         self.render_template('inQuizzes.html', template_values)

   def post(self):
     quiz_name = self.request.get('selected')
     user = self.user
     pq = Problem.query().filter(Problem.quiz == quiz_name)
     probs = pq.fetch()
     total=0
     good=0
     problems=[]
     answers=[]
     grades=[]
     for p in probs:
       total += 1
       my = self.request.get(str(total))
       answers.append(my)
       problems.append(p.content)
       eq1 = parse_expr(my)
       eq2 = parse_expr(p.answer)
       if eq1.equals(eq2):
          good += 1
          grades.append(1)
       else:
          grades.append(0)
     grade=100.0*good/total
     stringgrade=str(round(grade,1))+"%"
     pag = zip(problems, answers, grades)
     gradeRecord = Grades(parent=user_key(user.email_address))
     gradeRecord.author = Author(
                identity=user.name,
                email=user.email_address)
     gradeRecord.value=grade
     gradeRecord.stringgrade=stringgrade
     gradeRecord.quiz=quiz_name
     gradeRecord.pag= pag
     gradeRecord.put()

     gdate=gradeRecord.date.strftime("%B %d, %Y, %I:%M%P")

     qq = Quiz.query().filter(Quiz.name == quiz_name)
     quiz=qq.fetch()
     for q in quiz:
         q.jgrades.append([user.name,stringgrade, gradeRecord.key.urlsafe(), gdate])
         q.put()

     self.render_template('inQuizzes.html', {'selectdefault': quiz_name, 'grade': gradeRecord})


class inGradedQuizHandler(BaseHandler, webapp2.RequestHandler):
   @user_required
   def get(self):
      quiz_name = self.request.get('quiz_name')
      quizzes = getQuizList()
      problem_query = Problem.query().filter(Problem.quiz == quiz_name)
      problems = problem_query.fetch()
      template_values = { 'problems': problems,
              'quizzes': quizzes, 'selectdefault': quiz_name}
      self.render_template('inQuizzes.html', template_values)


class gradeQuiz(BaseHandler):
   @user_required
   def post(self):
       user = self.user
       quiz = self.request.get('quiz')
       problem_query = Problem.query().filter(Problem.quiz == quiz)
       problems = problem_query.fetch()
       right = None
       wrong = None
       counter = 1
       grade = Grades(parent=user_key(user.email_address))
       grade.author = Author(
                  identity=user.name,
                  email=user.email_address)
       grade.quiz = self.request.get('quizName')

       for problem in problems:
           total = self.request.get('counter')
           #answerList += answer
       self.display_message(total)
       #self.redirect("/inMyGrades")

class joinCourse(BaseHandler):
	@user_required
	def post(self):
		user = self.user
		course_key = ndb.Key(urlsafe=self.request.get('course_key'))
		course = course_key.get()

		course_query = Course.query()
		course_act = course_query.fetch()

		#for x in course_act:
		#	student_list = x.student
		#	for y in student_list:
		#		if(y.email == user.email_address):
		#			self.display_message("You have already added this course.")
		#			return
		#self.display_message(course)
		for x in course.student:
			if(x.email == user.email_address):
				self.display_message("You have already added this course.")
				return

		me = Author(identity=user.name, email=user.email_address)
		course.student.append(me)
		course.put()
		#tempCourse = course_key.get()
		#mycourse = coursesActive(parent=user_key(user.email_address))
		#cName = tempCourse.courseName
		#teach = tempCourse.teacher
		#tmpDate = tempCourse.dateCreated
		#mycourse_query = coursesActive.query(ancestor=user_key(user.email_address))
		#mycourseQResult = mycourse_query.fetch()
		#for e in mycourseQResult:
		#	if(cName == e.course.courseName):
		#		self.display_message("You have already added this course.")
		#		return

		#course.put()	

		#mycourse.course = Course(courseName=cName, teacher=teach, dateCreated=tmpDate)
		#mycourse.student = Author(identity=user.name, email=user.email_address)
		#mycourse.put()

		self.redirect("/inMyCourses")

###########################################################
# Deletion/Edit/Extra Functions
###########################################################

class deleteHandler(BaseHandler):
  @user_required
  def post(self):
      prob_key = ndb.Key(urlsafe=self.request.get('problem_key_delete'))
      #problem = prob_key.get()
      prob_key.delete()
      time.sleep(0.1)

      self.redirect("/inMyProblems")

class deleteQuizHandler(BaseHandler):
  @user_required
  def post(self):
      quiz_key = ndb.Key(urlsafe=self.request.get('quiz_key_delete'))
      quiz = quiz_key.get()
      problem_query = Problem.query().filter(Problem.quiz == quiz.name)
      problems = problem_query.fetch()
      for problem in problems:
          problem.key.delete()
      quiz_key.delete()
      time.sleep(0.1)
      self.redirect("inMyQuizzes")

class editProblemHanlder(BaseHandler):
  @user_required
  def post(self):
      user = self.user
      quizzes = getQuizList()
      prob_key = ndb.Key(urlsafe=self.request.get('problem_key_edit'))
      problem = prob_key.get()
      template_values = {'problem_content': problem.content,
                         'problem_answer': problem.answer,
                         'problem_tags': problem.tags,
                         'problem_key': prob_key,
                         'problem_difficulty': problem.difficulty,
                         'quizzes': quizzes, 'selectdefault': problem.quiz}
      #self.display_message(problem.content)
      self.render_template('inProblem.html', template_values)

class deleteCourse(BaseHandler):
	@user_required
	def post(self):
		user = self.user
		course_key = ndb.Key(urlsafe=self.request.get('course_key_delete'))
		course_key.delete()
		time.sleep(0.1)
		self.redirect("/inMyCourses")

def getQuizList():
   quiz_query = Quiz.query().order(-Quiz.date)
   quizzes = quiz_query.fetch()
   return quizzes


def getMyQuizList(self):
   qq = Quiz.query(ancestor=user_key(self.user.email_address)).order(-Quiz.date)
   quizzes = qq.fetch()
   return quizzes

def getGradeList():
   grade_query = Grades.query().order(-Grades.date)
   grades = grade_query.fetch()
   return grades

def getMyGradeList(self):
   g = Grades.query(ancestor=user_key(self.user.email_address)).order(-Grades.date)
   grades = g.fetch()
   return grades




################################################################################
# This is the python

# for json
# python:  loads vs dumps
# js:  stringify vs parces

all_quizzes = Quiz.query().order(-Quiz.date)

class TestHandler(BaseHandler):
   @user_required
   def get(self):
     if self.request.get('fmt') == 'json':
         data = defaultdict(list)
         for q in all_quizzes:
            probs = Problem.query().filter(Problem.quiz == q.name)
            for p in probs:
                data[q.name].append(p.content)
         self.response.out.headers['Content-Type'] = 'text/json'
         self.response.out.write(json.dumps(data))
     else:
         self.render_template('test.html')




config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name']
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}
# [START app]
app = webapp2.WSGIApplication([
    webapp2.Route('/', MainHandler, name='home'),
    webapp2.Route('/signup', SignupHandler),
    webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
      handler=VerificationHandler, name='verification'),
    webapp2.Route('/password', SetPasswordHandler),
    webapp2.Route('/login', LoginHandler, name='login'),
    webapp2.Route('/logout', LogoutHandler, name='logout'),
    webapp2.Route('/forgot', ForgotPasswordHandler, name='forgot'),
    webapp2.Route('/authenticated', AuthenticatedHandler, name='authenticated'),
    webapp2.Route('/inProblem', inProblemHandler, name='inProblem'),
    webapp2.Route('/inMyProblems', inMyProblemsHandler, name='inMyProblems'),
    webapp2.Route('/inQuizzes', inQuizzesHandler, name='inQuizzes'),
    webapp2.Route('/inGradedQuiz', inGradedQuizHandler, name='inGradedQuiz'),
    webapp2.Route('/inCreateCourse', inCreateCourseHandler, name='inCreateCourse'),
    webapp2.Route('/deleteProblem', deleteHandler, name='deleteProblem'),
    webapp2.Route('/deleteCourse', deleteCourse, name='deleteCourse'),
    webapp2.Route('/deleteQuiz', deleteQuizHandler, name='deleteQuiz'),
    webapp2.Route('/joinCourse', joinCourse, name='joinCourse'),
    webapp2.Route('/editProblem', editProblemHanlder, name='editProblem'),
    webapp2.Route('/inMyQuizzes', inMyQuizzesHandler, name='inMyQuizzes'),
    webapp2.Route('/inMyCourses', inMyCoursesHandler, name='inMyCourses'),
    webapp2.Route('/gradeQuiz', gradeQuiz, name='gradeQuiz'),
    webapp2.Route('/inHelp', helpHandler, name='inHelp'),
    webapp2.Route('/test', TestHandler, name='test')
# webapp2.Route('/inMain', inMainHandler, name='inMain'),
# webapp2.Route('/inAssignment', inAssignmentHandler, name='inAssignment'),
], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)



# [END app]
