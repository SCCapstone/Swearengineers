#!/usr/bin/env python
from main import *

################################################################################
# Function:  Create Quiz
#   - Called from Create Problem (below)
################################################################################
def createQuiz(self, name):
  quiz = Quiz(parent=user_key(self.user.email_address))
  quiz.author = Author(
    identity=user.name,
    email=user.email_address)
  quiz.name = name
  quiz.put()
  course=ndb.Key(urlsafe=self.user.selectedCourseKey).get()
  if not hasattr(course,'quizUrls'):
    course.quizUrls=[]
  course.quizUrls.append(quiz.key.urlsafe())




################################################################################
# Function:  Create Problem
#   - Called from the class inProblemHandler in main.py
#   - Adds the new problem to the datastore
#   - Creates a new quiz if necessary
#   - Returns variable to JS that shows successful submission
################################################################################
def create_problem(self, Problem, user_key, Author, Quiz):
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
   if self.request.get('newquiz') is True:
     problem.quiz = self.request.get('quiz_name')
     if not problem.quiz:
       self.display_message('Make sure to select a quiz from the dropdown first!')
       return
     createQuiz(self, problem.quiz)

   problem.content = self.request.get('problem')
   problem.tags = self.request.get('tags')
   problem.answer = self.request.get('answer')
   problem.difficulty = self.request.get('difficulty')
   if not problem.content or not problem.tags or not problem.answer or not problem.quiz:
     self.display_message('Please fill out all parts of the form')
     return
   problem.put()
   self.render_template('instructor/inProblem.html',{
     'selectdefault': problem.quiz,
     'success': '1',
    })
