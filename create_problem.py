#!/usr/bin/env python
from main import *

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
  course = ndb.Key(urlsafe=self.user.selectedCourseKey).get()
  quiz = ndb.Key(urlsafe=course.selectedQuizKey).get()


  # a test for editing a problem
  if not problem_key:
    problem = Problem(parent=user_key(user.email_address))
    problem.author = Author( identity=user.name, email=user.email_address)
#    problem.quizKey = quizKey
#    problem.quizName = quiz.name
  else:
     prob_key = ndb.Key(urlsafe=self.request.get('problem_key'))
     problem = prob_key.get()

#  if not problem.quizKey:
#    error='Make sure to select a quiz from the dropdown first!'
#    self.display_message(error)
#    return


  problem.content = self.request.get('problem')
  problem.tags = self.request.get('tags')
  problem.answer = self.request.get('answer')
  problem.difficulty = self.request.get('difficulty')

#  if (not problem.content or not problem.tags
#      or not problem.answer or not problem.quizName):
#    self.display_message('Please fill out all parts of the form')
#    return


  if problem.difficulty == 'Easy':
    quiz.easy.append(problem)
  if problem.difficulty == 'Medium':
    quiz.medium.append(problem)
  if problem.difficulty == 'Hard':
    quiz.hard.append(problem)

  quiz.put()

  self.render_template('instructor/inProblem.html',{'success': '1'})
