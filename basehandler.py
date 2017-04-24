#!/usr/bin/env python
from main import *
from google.appengine.ext.webapp import template
from google.appengine.ext import ndb
from google.appengine.api import app_identity
from google.appengine.api import mail
from google.appengine.api import users

from webapp2_extras import auth
from webapp2_extras import sessions
from webapp2_extras.auth import InvalidAuthIdError
from webapp2_extras.auth import InvalidPasswordError

################################################################################
# Class:  BaseHandler
#   - Functions for access to webapp2 attributes
#   - Needed as a parameter for most pages
################################################################################
class BaseHandler(webapp2.RequestHandler):
  @webapp2.cached_property
  def auth(self):
     # Access the auth instance as a property
     return auth.get_auth()

  @webapp2.cached_property
  def user_info(self):
    # User-session-attributes: config['webapp2_extras.auth']['user_attributes']
    # returns:   A dictionary with most user information
    return self.auth.get_user_by_session()

  @webapp2.cached_property
  def user(self):
    # Current-user-attributes: returns: an instance of the underlying model
    u = self.user_info
    return self.user_model.get_by_id(u['user_id']) if u else None

  @webapp2.cached_property
  def user_model(self):
    # User-implementation model
    # If set, is consistent with config['webapp2_extras.auth']['user_model']
    return self.auth.store.user_model

  @webapp2.cached_property
  def session(self):
      # return the current session
      return self.session_store.get_session(backend="datastore")

  def render_template(self, view_filename, params=None):

    vals = {}
    course = ''
    quiz = ''
    selectedReleased = ''
    courses=[]
    quizzes=[]
    unassigned=[]
    assigned=[]
    problems=[]

    if hasattr(self.user, 'myCourseKeys'):
      for k in self.user.myCourseKeys:
        courses.insert(0, ndb.Key(urlsafe=k).get())

    if hasattr(self.user, 'selectedCourseKey'):
      course = ndb.Key(urlsafe=self.user.selectedCourseKey).get()
      if course and course.quizUrls:
        for url in course.quizUrls:
          q=ndb.Key(urlsafe=url[2]).get()
          quizzes.insert(0, q)
          print '\n'
          if q.isReleased:
            assigned.insert(0,q)
          else:
            unassigned.insert(0,q)

      if course and course.selectedQuizKey:
        quiz=ndb.Key(urlsafe=course.selectedQuizKey).get()
        for p in reversed(quiz.hard):
          problems.append(p)
        for p in reversed(quiz.medium):
          problems.append(p)
        for p in reversed(quiz.easy):
          problems.append(p)

      if course and course.selectedReleasedKey:
        selectedReleased=ndb.Key(urlsafe=course.selectedReleasedKey).get()

    vals = {
      'user': self.user,
      'mycourses': courses,
      'selectedcourse': course,
      'selectedquiz': quiz,
      'selectedreleased': selectedReleased,
      'problems': problems,
      'quizzes': quizzes,
      'unassigned': unassigned,
      'assigned': assigned,
    }

    if params:
      vals.update(params)

    params = vals

    path = os.path.join(os.path.dirname(__file__), 'views', view_filename)
    return self.response.out.write(template.render(path, params))

  def display_message(self, message):
    # Displays message.html with a unique message
    params = { 'message': message }
    self.render_template('public/message.html', params)

  def dispatch(self):
    # Required by webapp2
    # Get a session store for this request.
    self.session_store = sessions.get_store(request=self.request)
    try:
       # Dispatch the request.
       webapp2.RequestHandler.dispatch(self)
    finally:
       # Save all sessions.
       self.session_store.save_sessions(self.response)
