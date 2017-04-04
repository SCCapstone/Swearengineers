#!/usr/bin/env python
from main import *

################################################################################
# Function:  Create Quiz
#   - Called from Create Problem (below)
################################################################################
def createQuiz(self, name, Quiz, user_key, Author):
  quiz = Quiz(parent=user_key(self.user.email_address))
  quiz.author = Author(
    identity=self.user.name,
    email=self.user.email_address)
  quiz.name = name
  quiz.put()
  course=ndb.Key(urlsafe=self.user.selectedCourseKey).get()
  if not course.quizUrls:
    course.quizUrls=[]
  course.quizUrls.append(quiz.key.urlsafe())
  return quiz.key.urlsafe()




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
   quiz_key = self.request.get('quiz_key')

   # a test for editing a problem
   if not problem_key:
      problem = Problem(parent=user_key(user.email_address))
      problem.author = Author(
               identity=user.name,
               email=user.email_address)
   else:
      prob_key = ndb.Key(urlsafe=self.request.get('problem_key'))
      problem = prob_key.get()

   problem.quiz = self.request.get('quiz_name')
   # a test for adding a new quiz
   if not quiz_key:
     if not problem.quiz:
       self.display_message('Make sure to select a quiz from the dropdown first!')
       return
     quiz_key=createQuiz(self, problem.quiz, Quiz, user_key, Author)

   quiz=ndb.Key(urlsafe=quiz_key).get()

   problem.content = self.request.get('problem')
   problem.tags = self.request.get('tags')
   problem.answer = self.request.get('answer')
   problem.difficulty = self.request.get('difficulty')
   if not problem.content or not problem.tags or not problem.answer or not problem.quiz:
     self.display_message('Please fill out all parts of the form')
     return
   problem.put()

   if problem.difficulty == 'Easy':
     if not quiz.easy:  quiz.easy = []
     quiz.easy.append(problem.key.urlsafe())
   if problem.difficulty == 'Medium':
     if not quiz.medium:  quiz.medium = []
     quiz.medium.append(problem.key.urlsafe())
   if problem.difficulty == 'Hard':
     if not quiz.hard:  quiz.hard = []
     quiz.hard.append(problem.key.urlsafe())
   quiz.put()

   self.render_template('instructor/inProblem.html',{
     'selectdefault': problem.quiz,
     'success': '1',
    })
