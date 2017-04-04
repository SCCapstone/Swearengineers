#!/usr/bin/env python
################################################################################
# MAIN MATHQUIZZES APP
# --------------------
#  Requires:
#    - basehandler.py
#    - signup.py
#    - grade_quiz.py
#    - create_problem.py
#
#  Authors:
#    - Matthew Moskowitz
#    - Austin Napoli
#    - Jory Pettit
#    - James Sager
#    - Nate Polly
#
#  Modifed:
#    Sun Mar 19 13:31:24 EDT 2017
################################################################################




import logging, webapp2, urllib, time, datetime, json, os.path, inspect
from collections import defaultdict
from basehandler import *
from signup import *
from create_problem import *
from grade_quiz import *




################################################################################
# Four NDB Classes
#   - DB objects used by the MathQuizzes App
################################################################################
class Author(ndb.Model):
  identity = ndb.StringProperty(indexed=False)
  email = ndb.StringProperty(indexed=False)


class Problem(ndb.Model):
  author = ndb.StructuredProperty(Author)
  quiz = ndb.StringProperty(indexed=True)
  content = ndb.StringProperty(indexed=False)
  answer = ndb.StringProperty(indexed=False)
  tags = ndb.StringProperty(indexed=False)
  difficulty = ndb.StringProperty(indexed=False)
  date = ndb.DateTimeProperty(auto_now_add=True)


class Quiz(ndb.Model):
  author = ndb.StructuredProperty(Author)
  name = ndb.StringProperty(indexed=True)
  content = ndb.StringProperty(indexed=False)
  date = ndb.DateTimeProperty(auto_now_add=True)
  isReleased = ndb.BooleanProperty(default=False)
  releaseDate = ndb.DateTimeProperty()
  easy = ndb.StructuredProperty(Problem, repeated=True)
  medium = ndb.StructuredProperty(Problem, repeated=True)
  hard = ndb.StructuredProperty(Problem, repeated=True)
  jgrades = ndb.JsonProperty(default=[])



class Course(ndb.Model):
  name = ndb.StringProperty()
  date = ndb.DateTimeProperty(auto_now_add=True)
  numberOfStudents = ndb.IntegerProperty()
  numberOfQuizzes = ndb.IntegerProperty()
  studentUrls = ndb.JsonProperty()
  quizUrls = ndb.JsonProperty()
  selectedQuiz = ndb.StructuredProperty(Quiz)


class Grades(ndb.Model):
  author = ndb.StructuredProperty(Author)
  value = ndb.FloatProperty(indexed=False)
  stringgrade = ndb.StringProperty(indexed=False)
  quiz = ndb.StringProperty(indexed=False)
  date = ndb.DateTimeProperty(auto_now_add=True)
  pag = ndb.JsonProperty()


class User(ndb.Model):
  isTeacher = ndb.BooleanProperty()
  selectedCourseKey = ndb.StringProperty()






################################################################################
# Function: user_key
#   - Constructs a Datastore key for a User entity.
################################################################################
DEFAULT_USER = "test@email.sc.edu"
def user_key(user=DEFAULT_USER):
  return ndb.Key('User', user)




################################################################################
# Decorator Function:  user_required
#   - Must be used on all pages that require (at least) student access
#   - Directs to logout, if not an authenticated user
#   - For use on student pages
################################################################################
def user_required(handler):
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)
  return check_login




################################################################################
# Decorator Function:  instructor_required
#   - Must be used on all instructor pages
#   - Directs to logout, if not an authenticated user
#   - Directs to logout, if not an authenticated instructor
################################################################################
def instructor_required(handler):
  def check_login(self, *args, **kwargs):
    auth = self.auth
    if not auth.get_user_by_session():
      self.redirect(self.uri_for('login'), abort=True)
    if not self.user.isTeacher:
      self.redirect(self.uri_for('login'), abort=True)
    else:
      return handler(self, *args, **kwargs)
  return check_login




################################################################################
# Class:  Verification
#   - Manages Email Verification
################################################################################
class VerificationHandler(BaseHandler):
  def get(self, *args, **kwargs):
    user = None
    user_id = kwargs['user_id']
    signup_token = kwargs['signup_token']
    verification_type = kwargs['type']

    user, ts = self.user_model.get_by_auth_token(int(user_id), signup_token, 'signup')

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
      params = { 'user': user, 'token': signup_token }
      self.render_template('public/resetpassword.html', params)
    else:
      logging.info('verification type not supported')
      self.abort(404)




################################################################################
# Class:  Login
#   - Authenticates login
################################################################################
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
    params = { 'username': username, 'failed': failed }
    self.render_template('public/login.html', params)




################################################################################
# Class:  Logout
#   - Redirects to login
################################################################################
class LogoutHandler(BaseHandler):
  def get(self):
    self.auth.unset_session()
    self.redirect(self.uri_for('login'))




################################################################################
# Class:  Authenticated
#   - Should redirects to the requested page
#   - Currently redirects to home
################################################################################
class AuthenticatedHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('home.html')





################################################################################
# Class:  Main
#   - The home page
################################################################################
class MainHandler(BaseHandler, webapp2.RequestHandler):
  @user_required
  def get(self):
    g = Grades.query(ancestor=user_key(self.user.email_address))
    g = g.order(-Grades.date).fetch()
    if self.user.isTeacher:
      if not hasattr(self.user,'selectedCourseKey'):
        self.render_template('instructor/inMyCourses.html', {'newuser': True})
        return
      self.render_template('instructor/inHome.html', {'grades':g})
    else:
      self.render_template('home.html', {'grades': g})




################################################################################
# Class:  Quiz
#   - Take / Grade Quiz
#   - also see grade_quiz.py
################################################################################
class QuizHandler(BaseHandler, webapp2.RequestHandler):
  @user_required
  def get(self):
    if self.request.get('grade') is not '':
      grade = ndb.Key(urlsafe=self.request.get('grade'))
      grade = grade.get()
      sd=grade.quiz
      self.render_template(
        'quiz.html', { 'grade': grade, 'selectdefault': sd }
      )
    elif self.request.get('k') is not '':
      quiz = ndb.Key(urlsafe=self.request.get('k')).get()
      quizzes = getQuizList()
      problem_query = Problem.query().filter(Problem.quiz == quiz.name)
      problems = problem_query.fetch()
      template_values = {
        'problems': problems,
        'quizzes': quizzes,
        'selectdefault': quiz.name,
        'quiz': quiz
      }
      self.render_template('quiz.html', template_values)
    elif self.request.get('quiz_name') is not None:
      quiz_name = self.request.get('quiz_name')
      quizzes = getQuizList()
      problem_query = Problem.query().filter(Problem.quiz == quiz_name)
      problems = problem_query.fetch()
      template_values = {
        'problems': problems,
        'quizzes': quizzes,
        'selectdefault': quiz_name
      }
      self.render_template('quiz.html', template_values)
    elif self.request.get('quiz_name') is None:
      quizzes = getQuizList()
      template_values = {'quizzes': quizzes }
      self.render_template('quiz.html', template_values)
  def post(self):
    grade_quiz(self, user_key, Author, Problem, Quiz, Grades)




################################################################################
# Class:  inProblem
#   - Creates a Problem
#   - Can create a new Quiz
#   - Also see create_problem.py
################################################################################
class inProblemHandler(BaseHandler, webapp2.RequestHandler):
  @instructor_required
  def get(self):
    quizzes = getMyQuizList(self)
    self.render_template('instructor/inProblem.html',
      {'quizzes': quizzes, 'newquiz': self.request.get('n')})
  def post(self):
    create_problem(self, Problem, user_key, Author, Quiz)





################################################################################
# Class inMyProblems
#   - Displays all Problems
#   - Options:  Search, Edit, and Delete
################################################################################
class inMyProblemsHandler(BaseHandler):
  @instructor_required
  def get(self):
    user = self.user
    problem_query = Problem.query(ancestor=user_key(user.email_address)).order(-Problem.date)
    problems = problem_query.fetch()
    quizzes = getMyQuizList(self)
    template_values = {'problems': problems, 'quizzes': quizzes }
    self.render_template('instructor/inMyProblems.html', template_values)
  def post(self):
    quiz = self.request.get('quiz')
    quizzes = getQuizList()
    problem_query = Problem.query().filter(Problem.quiz == quiz)
    problems = problem_query.fetch()
    template_values = {
       'problems': problems,
       'selectdefault': quiz,
       'quizzes': quizzes,
    }
    self.render_template('instructor/inMyProblems.html', template_values)




################################################################################
# Class: inMyQuizzes
#   - Displays all Quizzes and Grades
#   - Options:  Delete Quiz and Open Graded Quiz
################################################################################
class inMyQuizzesHandler(BaseHandler):
  @instructor_required
  def get(self):
    user = self.user
    quizzes = getMyQuizList(self)
    template_values = {'quizzes': quizzes }
    self.render_template('instructor/inMyQuizzes.html', {'quizzes': quizzes })




################################################################################
# Class:  Release Quiz
#   - Assigns the quiz to students
#   - Locks the quiz from edit
################################################################################
class ReleaseQuizHandler(BaseHandler):
  @instructor_required
  def post(self):
    q = ndb.Key(urlsafe=self.request.get('k')).get()
    q.isReleased = True
    q.releaseDate=datetime.datetime.now()
    q.put()
    self.redirect('instructor/inMyQuizzes')



################################################################################
# Class:  Delete Quiz
################################################################################
class deleteQuizHandler(BaseHandler):
  @instructor_required
  def post(self):
    ndb.Key(urlsafe=self.request.get('k')).delete()
    self.redirect("instructor/inMyQuizzes")








################################################################################
# Class: inAddStudents
#   - Displays Student Users
#   - Options:  Add and Remove Students from Email List
################################################################################
class inAddStudentsHandler(BaseHandler):
  @instructor_required
  def get(self):

    allS = []
    users=User.query().fetch()
    for u in users:
      if not u.isTeacher:
        allS.append(u)

    myS = []
    course=ndb.Key(urlsafe=self.user.selectedCourseKey).get()
    if hasattr(course,'studentUrls') and course.studentUrls:
      for k in course.studentUrls:
        u=ndb.Key(urlsafe=k).get()
        allS.remove(u)
        myS.append(u)

    self.render_template('instructor/inAddStudents.html',{
      'allStudents': allS,
      'myStudents': myS,
      'added': self.request.get('added'),
      'removed': self.request.get('removed')
    })




################################################################################
# Class: Add One Student
#   - Works with inAddStudents to add Students
#   - Queued by clicking on a student in the All Students column
################################################################################
class AddOneStudentHandler(BaseHandler):
  @instructor_required
  def get(self):
    url=self.request.get('s')
    course=ndb.Key(urlsafe=self.user.selectedCourseKey).get()
    if not course.studentUrls:
      course.studentUrls = []
    course.studentUrls.append(url)
    course.numberOfStudents += 1
    course.put()
    added = ndb.Key(urlsafe=url).get()
    added = added.name + " " + added.last_name
    self.redirect("instructor/inAddStudents?added=" + added)




################################################################################
# Class: Remove One Student
#   - Works with inAddStudents to add Students
#   - Queued by clicking on a student in the MY Students column
################################################################################
class RemoveOneStudentHandler(BaseHandler):
  @instructor_required
  def get(self):
    url=self.request.get('s')
    course=ndb.Key(urlsafe=self.user.selectedCourseKey).get()
    course.studentUrls.remove(url)
    course.numberOfStudents -= 1
    course.put()
    removed = ndb.Key(urlsafe=url).get()
    removed = removed.name + " " + removed.last_name
    self.redirect("instructor/inAddStudents?removed=" + removed)




################################################################################
# Three Classes for Editing and Deleting; Used by:
#   - MyProblems:  delete and edit problem classes
#   - MyQuizzes:   delete quiz class
################################################################################

class deleteHandler(BaseHandler):
  @instructor_required
  def post(self):
    prob_key = ndb.Key(urlsafe=self.request.get('problem_key_delete'))
    #problem = prob_key.get()
    prob_key.delete()
    time.sleep(0.1)
    self.redirect("instructor/inMyProblems")


class editProblemHanlder(BaseHandler):
  @instructor_required
  def post(self):
    user = self.user
    quizzes = getQuizList()
    prob_key = ndb.Key(urlsafe=self.request.get('problem_key_edit'))
    problem = prob_key.get()
    template_values = {
      'problem_content': problem.content,
      'problem_answer': problem.answer,
      'problem_tags': problem.tags,
      'problem_key': prob_key,
      'problem_difficulty': problem.difficulty,
      'quizzes': quizzes,
      'selectdefault': problem.quiz,
    }
    self.render_template('instructor/inProblem.html', template_values)





################################################################################
# inMyCourses Handler
################################################################################
class inMyCoursesHandler(BaseHandler):
  @instructor_required
  def get(self):
    self.render_template('instructor/inMyCourses.html', {'noCourseSelect':True})

class CreateCourseHandler(BaseHandler):
  @instructor_required
  def post(self):
    name=self.request.get('course_name')
    c=Course()
    c.name=name
    c.numberOfQuizzes = 0
    c.numberOfStudents = 0
    c.put()
    k=c.key.urlsafe()
    if not hasattr(self.user, 'myCourseKeys'):
      self.user.myCourseKeys = []
    if not hasattr(self.user, 'selectedCourseKey'):
      self.user.myCourseKeys = []
    self.user.selectedCourseKey=k
    self.user.myCourseKeys.append(k)
    self.user.put()
    self.redirect('instructor/inAddStudents')

class DeleteCourseHandler(BaseHandler):
  @instructor_required
  def post(self):
    k=self.request.get('key')
    self.user.myCourseKeys.remove(k)
    self.user.put()
    ndb.Key(urlsafe=k).delete()
    self.redirect('instructor/inMyCourses')


class EditCourseHandler(BaseHandler):
  @instructor_required
  def post(self):
    name=self.request.get('course_name')
    course=ndb.Key(urlsafe=self.request.get('k')).get()
    course.name=name
    course.put()
    self.redirect('instructor/inMyCourses')



class SelectCourseHandler(BaseHandler):
  @user_required
  def get(self):
    self.user.selectedCourseKey = self.request.get('key')
    self.user.put()
    # remove dangleing vars from url on return
    url, sep, var = self.request.referer.partition('?')
    self.redirect(url)

################################################################################
# Displays Help HTML
################################################################################
class helpHandler(BaseHandler):
  @user_required
  def get(self):
    self.render_template('instructor/inHelp.html', {'noCourseSelect':True})




################################################################################
# Querey Functions
################################################################################

def getQuizList():
  return Quiz.query().order(-Quiz.date).fetch()

def getMyQuizList(self):
  course=ndb.Key(urlsafe=self.user.selectedCourseKey).get()
  q=[]
  if hasattr(course,'quizUrls') and course.quizUrls:
    for k in course.quizUrls:
      q.append(ndb.Key(urlsafe=k).get())
  return q




################################################################################
# Config / Start
################################################################################
config = {
  'webapp2_extras.auth': {
    'user_model': 'models.User',
    'user_attributes': ['name'],
    # one week below
    'token_max_age':   86400 * 7 * 1,
  },
  'webapp2_extras.sessions': {
    'secret_key': 'YOUR_SECRET_KEY'
  }
}




# [START app]
app = webapp2.WSGIApplication([

#    webapp2.Route('/public/forgot', ForgotPasswordHandler, name='forgot'),
#    webapp2.Route('/authenticated', AuthenticatedHandler, name='authenticated'),

  # public:  login, signup, etc
  webapp2.Route('/', MainHandler, name='index'),
  webapp2.Route('/public/login', LoginHandler, name='login'),
  webapp2.Route('/public/signup', SignupHandler),
  webapp2.Route('/logout', LogoutHandler, name='logout'),
  webapp2.Route('/<type:v|p>/<user_id:\d+>-<signup_token:.+>',
    handler=VerificationHandler, name='verification'),

  # instructor pages
  webapp2.Route('/instructor/inProblem', inProblemHandler, name='inProblem'),
  webapp2.Route('/instructor/inMyProblems', inMyProblemsHandler, name='inMyProblems'),
  webapp2.Route('/instructor/inMyQuizzes', inMyQuizzesHandler, name='inMyQuizzes'),
  webapp2.Route('/instructor/inAddStudents', inAddStudentsHandler, name='inAddStudents'),
  webapp2.Route('/instructor/inMyCourses', inMyCoursesHandler, name='inMyCourses'),
  webapp2.Route('/instructor/inHelp', helpHandler, name='inHelp'),

  # edit classes
  webapp2.Route('/deleteProblem', deleteHandler, name='deleteProblem'),
  webapp2.Route('/editProblem', editProblemHanlder, name='editProblem'),
  webapp2.Route('/addOneStudent', AddOneStudentHandler, name='addOneStudent'),
  webapp2.Route('/removeOneStudent', RemoveOneStudentHandler, name='removeOneStudent'),
  webapp2.Route('/releaseQuiz', ReleaseQuizHandler, name='releaseQuiz'),
  webapp2.Route('/deleteQuiz', deleteQuizHandler, name='deleteQuiz'),
  webapp2.Route('/createCourse', CreateCourseHandler, name='createCourse'),
  webapp2.Route('/deleteCourse', DeleteCourseHandler, name='deleteCourse'),
  webapp2.Route('/editCourse', EditCourseHandler, name='editCourse'),

  #shared class
  webapp2.Route('/selectCourse', SelectCourseHandler, name='selectCourse'),

  # student pages
  webapp2.Route('/home', MainHandler, name='home'),
  webapp2.Route('/quiz', QuizHandler, name='quiz'),

], debug=True, config=config)

logging.getLogger().setLevel(logging.DEBUG)



# [END app]
