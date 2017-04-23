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
  newProb = False

  # a test for editing a problem
  if not problem_key:
    problem = Problem(parent=user_key(user.email_address))
    problem.author = Author( identity=user.last_name, email=user.email_address)
  else:
     problem = ndb.Key(urlsafe=problem_key).get()
     if problem.difficulty == 'Easy':
       for p in quiz.easy:
         if p.url == problem.url:
           quiz.easy.remove(p)
     if problem.difficulty == 'Medium':
       for p in quiz.medium:
         if p.url == problem.url:
           quiz.medium.remove(p)
     if problem.difficulty == 'Hard':
       for p in quiz.hard:
         if p.url == problem.url:
           quiz.hard.remove(p)


  problem.content = self.request.get('problem')
  problem.tags = self.request.get('tags')
  problem.answer = self.request.get('answer')
  problem.difficulty = self.request.get('difficulty')
  problem.quizName = quiz.name

  if not problem.content or not problem.tags or not problem.answer:
    self.display_message('Please fill out all parts of the form')
    return
  problem.put()
  problem.url=problem.key.urlsafe()
  problem.put()

  if problem.difficulty == 'Easy':
    quiz.easy.append(problem)
  if problem.difficulty == 'Medium':
    quiz.medium.append(problem)
  if problem.difficulty == 'Hard':
    quiz.hard.append(problem)

  quiz.put()
  template_values = {
    'success':1,
    'problem_tags': problem.tags,
    'problem_difficulty': problem.difficulty,
   }
  self.render_template('instructor/inProblem.html', template_values)

